"""Reviewed Azure-key export into one new plaintext or SOPS dotenv document."""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from io import StringIO
from pathlib import Path

from azurator.fingerprints import EphemeralFingerprinter, erase_fingerprint
from azurator.inputs import (
    MAX_DOTENV_FILE_BYTES,
    SecretInputError,
    consume_dotenv,
    render_dotenv_assignment,
    validate_dotenv_selector,
)
from azurator.models import DiscoveredResource, Inventory, KeyAuthentication, KeyMap, KeySlotSelection
from azurator.providers.base import KeyReadingProvider
from azurator.providers.resource_ids import ResourceIdError, resource_coordinates
from azurator.sops import MAX_SOPS_DOTENV_FILE_BYTES, SopsExportCommand

_SELECTOR_PART_PATTERN = re.compile(r"[^A-Za-z0-9]+")


class ExportError(RuntimeError):
    """A secret-free export contract or rendering failure."""


@dataclass(frozen=True, slots=True)
class DotenvExportAssignment:
    """One secret-free mapping from an Azure key slot to a dotenv selector."""

    resource: DiscoveredResource
    resource_group: str
    key_slot: str
    selector: str


def build_dotenv_export_assignments(
    inventory: Inventory,
    selections: Sequence[KeySlotSelection],
) -> tuple[DotenvExportAssignment, ...]:
    """Validate exact inventory selections and assign deterministic dotenv names."""

    resources: dict[str, DiscoveredResource] = {}
    for resource in inventory.resources:
        if resource.resource_id in resources:
            raise ExportError("Azure discovery returned one resource identity more than once")
        resources[resource.resource_id] = resource

    assignments: list[DotenvExportAssignment] = []
    selected: set[tuple[str, str]] = set()
    used_selectors: set[str] = set()
    for selection in selections:
        identity = (selection.resource_id, selection.key_slot)
        if identity in selected:
            raise ExportError("an Azure key slot was selected more than once")
        selected.add(identity)

        resource = resources.get(selection.resource_id)
        if resource is None:
            raise ExportError("an export selection references a resource outside the discovered inventory")
        slots = {slot.name: slot for slot in resource.key_slots}
        slot = slots.get(selection.key_slot)
        if (
            resource.key_authentication is not KeyAuthentication.enabled
            or len(slots) != 2
            or len(slots) != len(resource.key_slots)
            or any(not candidate.values_retrievable for candidate in resource.key_slots)
            or slot is None
            or not slot.values_retrievable
        ):
            raise ExportError("an export selection does not satisfy a supported retrievable key-pair contract")

        base_selector = _default_selector(resource, selection.key_slot)
        selector = base_selector
        suffix = 2
        while selector in used_selectors:
            selector = f"{base_selector}_{suffix}"
            suffix += 1
        used_selectors.add(selector)
        assignments.append(
            DotenvExportAssignment(
                resource=resource,
                resource_group=_validated_resource_group(inventory.subscription_id, resource),
                key_slot=selection.key_slot,
                selector=selector,
            )
        )

    if not assignments:
        raise ExportError("select at least one Azure key slot to export")
    return tuple(assignments)


def build_key_map_export_assignments(
    inventory: Inventory,
    key_map: KeyMap,
) -> tuple[DotenvExportAssignment, ...]:
    """Resolve one key map against the current exportable inventory."""

    if inventory.subscription_id.casefold() != key_map.subscription_id.casefold():
        raise ExportError("the key map belongs to a different Azure subscription")

    resources: dict[str, DiscoveredResource] = {}
    for resource in inventory.resources:
        identity = resource.resource_id.casefold()
        if identity in resources:
            raise ExportError("Azure discovery returned one resource identity more than once")
        resources[identity] = resource

    assignments: list[DotenvExportAssignment] = []
    for mapping in key_map.mappings:
        resource = resources.get(mapping.key_resource_id.casefold())
        if resource is None:
            raise ExportError("a key-map entry references a resource outside the discovered inventory")
        slots = {slot.name: slot for slot in resource.key_slots}
        slot = slots.get(mapping.key_slot)
        if (
            resource.key_authentication is not KeyAuthentication.enabled
            or len(slots) != 2
            or len(slots) != len(resource.key_slots)
            or any(not candidate.values_retrievable for candidate in resource.key_slots)
            or slot is None
            or not slot.values_retrievable
        ):
            raise ExportError("a key-map entry does not satisfy a supported retrievable key-pair contract")
        try:
            validate_dotenv_selector(mapping.selector)
        except SecretInputError:
            raise ExportError("a key-map selector violates the supported dotenv output contract") from None
        assignments.append(
            DotenvExportAssignment(
                resource=resource,
                resource_group=_validated_resource_group(inventory.subscription_id, resource),
                key_slot=mapping.key_slot,
                selector=mapping.selector,
            )
        )
    return tuple(assignments)


def _validated_resource_group(subscription_id: str, resource: DiscoveredResource) -> str:
    """Resolve one exact display identity while assignments are still being validated."""

    try:
        coordinates = resource_coordinates(
            resource.resource_id,
            subscription_id=subscription_id,
            expected_resource_type=resource.resource_type,
            expected_name=resource.name,
        )
    except ResourceIdError:
        raise ExportError(
            "a selected key resource does not satisfy the supported Azure resource identity contract"
        ) from None
    return coordinates.resource_group


class DotenvExportService:
    """Read exact supported key pairs and render selected slots only."""

    def __init__(self, providers: Sequence[KeyReadingProvider]) -> None:
        self._providers: dict[str, KeyReadingProvider] = {}
        for provider in providers:
            name = provider.info.name
            if name in self._providers:
                raise ExportError("a key-reading provider was registered more than once")
            self._providers[name] = provider

    def render(
        self,
        subscription_id: str,
        assignments: Sequence[DotenvExportAssignment],
    ) -> str:
        """Return one canonical dotenv document while keeping values out of result metadata."""

        if not assignments:
            raise ExportError("select at least one Azure key slot to export")

        grouped: dict[tuple[str, str], list[DotenvExportAssignment]] = defaultdict(list)
        seen_selectors: set[str] = set()
        for assignment in assignments:
            if assignment.selector in seen_selectors:
                raise ExportError("dotenv export assignments must have unique selectors")
            seen_selectors.add(assignment.selector)
            if assignment.resource.provider not in self._providers:
                raise ExportError("an export selection has no installed supported key-reading provider")
            try:
                validate_dotenv_selector(assignment.selector)
            except SecretInputError:
                raise ExportError("a dotenv export selector violates the supported output contract") from None
            grouped[(assignment.resource.provider, assignment.resource.resource_id)].append(assignment)

        validated_groups: list[
            tuple[KeyReadingProvider, DiscoveredResource, dict[str, list[DotenvExportAssignment]], tuple[str, ...]]
        ] = []
        for (provider_name, _), resource_assignments in grouped.items():
            provider = self._providers[provider_name]
            resource = resource_assignments[0].resource
            if any(assignment.resource != resource for assignment in resource_assignments):
                raise ExportError("one Azure resource identity resolved to conflicting metadata")

            declared_slots = tuple(slot.name for slot in resource.key_slots)
            if (
                resource.key_authentication is not KeyAuthentication.enabled
                or len(declared_slots) != 2
                or len(set(declared_slots)) != len(declared_slots)
                or any(not slot.values_retrievable for slot in resource.key_slots)
            ):
                raise ExportError("an export resource violates the supported retrievable key-pair contract")
            selected_by_slot: dict[str, list[DotenvExportAssignment]] = defaultdict(list)
            for assignment in resource_assignments:
                selected_by_slot[assignment.key_slot].append(assignment)
            if not set(selected_by_slot).issubset(declared_slots):
                raise ExportError("an export assignment references an undeclared key slot")
            validated_groups.append((provider, resource, selected_by_slot, declared_slots))

        rendered: dict[str, str] = {}
        try:
            for provider, resource, selected_by_slot, declared_slots in validated_groups:
                consumed_slots: set[str] = set()

                def consume(slot: str, value: str) -> None:
                    if slot not in declared_slots or slot in consumed_slots:
                        raise ExportError("a provider violated its supported key-state callback contract")
                    consumed_slots.add(slot)
                    for assignment in selected_by_slot.get(slot, ()):
                        try:
                            rendered[assignment.selector] = render_dotenv_assignment(assignment.selector, value) + "\n"
                        except SecretInputError:
                            raise ExportError(
                                "an Azure key cannot be represented by the supported dotenv output contract"
                            ) from None

                provider.use_key_state(subscription_id, resource, consume)
                if consumed_slots != set(declared_slots):
                    raise ExportError("a provider returned an incomplete supported key state")

            if len(rendered) != len(assignments):
                raise ExportError("not every selected Azure key slot produced one dotenv assignment")
            payload = "".join(rendered[assignment.selector] for assignment in assignments)
            try:
                payload_size = len(payload.encode("utf-8"))
            except UnicodeError:
                raise ExportError("the generated dotenv document violates the supported UTF-8 contract") from None
            if payload_size > MAX_DOTENV_FILE_BYTES:
                raise ExportError("the generated dotenv document exceeds the supported 1 MiB limit")
            return payload
        finally:
            rendered.clear()


class SopsDotenvExportService:
    """Encrypt and verify one generated dotenv document without plaintext disk I/O."""

    def __init__(self, command: SopsExportCommand) -> None:
        self._command = command

    def validate_environment(self) -> None:
        """Require the pinned SOPS executable before Azure key retrieval begins."""

        self._command.validate()

    def encrypt(self, plaintext: str, destination: Path) -> bytearray:
        """Return verified SOPS ciphertext while erasing owned mutable secret buffers."""

        plaintext_bytes = bytearray()
        ciphertext = bytearray()
        decrypted = ""
        succeeded = False
        try:
            plaintext_bytes.extend(plaintext.encode("utf-8"))
            if not plaintext_bytes or len(plaintext_bytes) > MAX_DOTENV_FILE_BYTES:
                raise ExportError("the generated dotenv document exceeds the supported 1 MiB limit")
            ciphertext = self._command.encrypt_dotenv(destination, plaintext_bytes)
            if not ciphertext or len(ciphertext) > MAX_SOPS_DOTENV_FILE_BYTES:
                raise ExportError("SOPS returned ciphertext outside the supported 8 MiB limit")
            decrypted = self._command.decrypt_dotenv_ciphertext(destination, ciphertext)
            _verify_dotenv_round_trip(plaintext, decrypted)
            succeeded = True
            return ciphertext
        except UnicodeError:
            raise ExportError("the generated dotenv document violates the supported UTF-8 contract") from None
        finally:
            plaintext_bytes[:] = b"\x00" * len(plaintext_bytes)
            decrypted = ""
            if not succeeded:
                ciphertext[:] = b"\x00" * len(ciphertext)


def _verify_dotenv_round_trip(expected: str, observed: str) -> None:
    """Compare exact dotenv assignments through unlinkable in-process fingerprints."""

    expected_fingerprints: dict[str, bytearray] = {}
    observed_fingerprints: dict[str, bytearray] = {}
    try:
        with EphemeralFingerprinter() as fingerprinter:
            expected_fingerprints = _dotenv_fingerprints(expected, fingerprinter)
            observed_fingerprints = _dotenv_fingerprints(observed, fingerprinter)
            matches = expected_fingerprints.keys() == observed_fingerprints.keys() and all(
                fingerprinter.equal(digest, observed_fingerprints[selector])
                for selector, digest in expected_fingerprints.items()
            )
            if not matches:
                raise ExportError("SOPS verification did not reproduce the selected dotenv assignments")
    except SecretInputError:
        raise ExportError("SOPS verification returned content outside the supported dotenv format") from None
    finally:
        for digest in (*expected_fingerprints.values(), *observed_fingerprints.values()):
            erase_fingerprint(digest)
        expected_fingerprints.clear()
        observed_fingerprints.clear()


def _dotenv_fingerprints(content: str, fingerprinter: EphemeralFingerprinter) -> dict[str, bytearray]:
    fingerprints: dict[str, bytearray] = {}

    def consume(selector: str, value: str) -> None:
        fingerprints[selector] = fingerprinter.derive(value)

    try:
        result = consume_dotenv(StringIO(content, newline=""), consume)
    except BaseException:
        for digest in fingerprints.values():
            erase_fingerprint(digest)
        fingerprints.clear()
        raise
    if result.skipped_empty_selectors:
        for digest in fingerprints.values():
            erase_fingerprint(digest)
        fingerprints.clear()
        raise SecretInputError("dotenv verification contains empty assignments")
    return fingerprints


def _default_selector(resource: DiscoveredResource, key_slot: str) -> str:
    provider = _selector_part(resource.provider)
    name = _selector_part(resource.name)
    slot = _selector_part(key_slot)
    return f"AZURATOR_{provider}_{name}_{slot}"


def _selector_part(value: str) -> str:
    normalized = _SELECTOR_PART_PATTERN.sub("_", value).strip("_").upper()
    if not normalized:
        raise ExportError("Azure metadata cannot form a valid dotenv selector")
    return normalized

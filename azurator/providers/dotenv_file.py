"""Managed updates for one explicitly selected plaintext dotenv file."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from pathlib import Path

from azurator.files import (
    UnsafeInputPathError,
    UnsafeOutputPathError,
    open_managed_plaintext,
    read_managed_plaintext,
    replace_managed_plaintext,
    resolve_parent_path,
)
from azurator.inputs import (
    MAX_DOTENV_FILE_BYTES,
    SecretInputError,
    dotenv_stream_values_equal,
    dotenv_values_equal,
    replace_dotenv_values,
    validate_dotenv_assignments,
)
from azurator.models import (
    BindingInspection,
    BindingInspectionStatus,
    BindingLocation,
    BindingManagement,
    CredentialBinding,
    DiscoveredResource,
    DiscoveryWarning,
    KeyAuthentication,
    MatchReport,
    ProviderBindingResult,
    ProviderInfo,
    WarningCategory,
    WarningImpact,
)
from azurator.providers.base import (
    BINDING_VERIFICATION_MISMATCH_CODE,
    CandidateIdentifier,
    ProviderOperationError,
)
from azurator.providers.resource_ids import ResourceIdError, resource_coordinates

_PROVIDER_NAME = "local-dotenv-file"
_PROVIDER_CONTRACT_VERSION = "1"
_BINDING_TYPE = "local/dotenv-file"
_STORAGE_RESOURCE_TYPE = "Microsoft.Storage/storageAccounts"
_COGNITIVE_RESOURCE_TYPE = "Microsoft.CognitiveServices/accounts"
_KEY_RESOURCE_TYPES = (_STORAGE_RESOURCE_TYPE, _COGNITIVE_RESOURCE_TYPE)

DOTENV_FILE_PROVIDER_INFO = ProviderInfo(
    name=_PROVIDER_NAME,
    contract_version=_PROVIDER_CONTRACT_VERSION,
    resource_types=(_BINDING_TYPE,),
)


class DotenvFileContractError(RuntimeError):
    """A plaintext dotenv source cannot be represented by the supported managed-file contract."""


def normalize_dotenv_file_path(path: Path) -> Path:
    """Bind an absolute path to its resolved parent without following the final component."""

    return resolve_parent_path(path)


def attach_dotenv_file_bindings(report: MatchReport, path: Path) -> MatchReport:
    """Treat matched assignments in one exact dotenv file as managed bindings."""

    source = normalize_dotenv_file_path(path)
    if any(provider.name == _PROVIDER_NAME for provider in report.providers):
        raise DotenvFileContractError("the dotenv-file provider was registered more than once")

    identities_by_selector: dict[str, set[tuple[str, str]]] = {}
    selectors_by_identity: dict[tuple[str, str], list[str]] = {}
    for match in report.matches:
        identity = (match.resource_id, match.key_slot)
        identities_by_selector.setdefault(match.input_selector, set()).add(identity)
        selectors_by_identity.setdefault(identity, []).append(match.input_selector)
    if any(len(identities) != 1 for identities in identities_by_selector.values()):
        raise DotenvFileContractError(
            "a dotenv assignment matched more than one Azure key slot and cannot be updated safely"
        )

    input_order = {selector: index for index, selector in enumerate(report.input_selectors)}
    resources_by_id = {resource.resource_id: resource for resource in report.resources}
    bindings: list[CredentialBinding] = list(report.bindings)
    inspections: list[BindingInspection] = list(report.binding_inspections)
    inspected_resources: set[str] = set()
    for (resource_id, key_slot), matched_selectors in sorted(
        selectors_by_identity.items(),
        key=lambda item: (
            item[0][0].casefold(),
            item[0][1].casefold(),
        ),
    ):
        if resource_id not in resources_by_id:
            raise DotenvFileContractError("a dotenv match has no supported Azure resource metadata")
        selectors = tuple(sorted(set(matched_selectors), key=input_order.__getitem__))
        bindings.append(_binding(source, resource_id, key_slot, selectors))
        if resource_id not in inspected_resources:
            inspections.append(
                BindingInspection(
                    resource_id=resource_id,
                    provider=_PROVIDER_NAME,
                    location=BindingLocation.local,
                    status=BindingInspectionStatus.inspected,
                    scopes_inspected=1,
                )
            )
            inspected_resources.add(resource_id)

    providers = tuple(sorted((*report.providers, DOTENV_FILE_PROVIDER_INFO), key=lambda item: item.name))
    warnings = (
        *report.warnings,
        DiscoveryWarning(
            code="dotenv-file-plaintext-at-rest",
            message=(
                "A file-sourced rotation atomically persists and verifies temporary bridge and final values. "
                "If interrupted, the file may intentionally remain on a valid bridge until resume. "
                "It remains plaintext at rest, and running workloads are not reloaded or health-checked."
            ),
            impact=WarningImpact.confirmation,
            category=WarningCategory.persistence,
            provider=_PROVIDER_NAME,
        ),
    )
    return report.model_copy(
        update={
            "providers": providers,
            "binding_inspections": tuple(
                sorted(inspections, key=lambda item: (item.provider, item.resource_id.casefold()))
            ),
            "bindings": tuple(sorted(bindings, key=lambda item: (item.scope_name.casefold(), item.name.casefold()))),
            "warnings": warnings,
        }
    )


class DotenvFileProvider:
    """Update and verify exact assignments in one user-managed local dotenv file."""

    @property
    def info(self) -> ProviderInfo:
        return DOTENV_FILE_PROVIDER_INFO

    @property
    def location(self) -> BindingLocation:
        return BindingLocation.local

    @property
    def key_resource_types(self) -> tuple[str, ...]:
        return _KEY_RESOURCE_TYPES

    def inspect_bindings(
        self,
        subscription_id: str,
        resources: Sequence[DiscoveredResource],
        selected_resource_ids: frozenset[str],
        identify: CandidateIdentifier,
    ) -> ProviderBindingResult:
        """Reject generic inspection because the source file must be explicit."""

        del subscription_id, resources, identify
        if selected_resource_ids:
            raise DotenvFileContractError("dotenv-file inspection requires one explicit source file")
        return ProviderBindingResult()

    def update_binding(
        self,
        subscription_id: str,
        binding: CredentialBinding,
        resource: DiscoveredResource,
        expected_key: str,
        replacement_key: str,
    ) -> None:
        """Atomically move exact expected assignments to one replacement key."""

        path = self._operation_path(subscription_id, binding, resource)
        if not expected_key or not replacement_key:
            raise ProviderOperationError(
                "dotenv-file-update-contract-invalid",
                "A dotenv binding did not match the expected update shape.",
            )
        content = ""
        replacement = ""
        try:
            content = read_managed_plaintext(path, max_bytes=MAX_DOTENV_FILE_BYTES)
            validate_dotenv_assignments(content, binding.selectors)
            if dotenv_values_equal(content, binding.selectors, replacement_key):
                return
            if not dotenv_values_equal(content, binding.selectors, expected_key):
                raise ProviderOperationError(
                    "dotenv-file-binding-drift-detected",
                    "The managed dotenv assignments changed after planning; they were not updated.",
                )
            replacement = replace_dotenv_values(content, binding.selectors, replacement_key)
            if len(replacement.encode("utf-8")) > MAX_DOTENV_FILE_BYTES:
                raise SecretInputError("the updated dotenv file would exceed the supported size limit")
            replace_managed_plaintext(
                path,
                content,
                replacement,
                max_bytes=MAX_DOTENV_FILE_BYTES,
            )
        except SecretInputError:
            raise ProviderOperationError(
                "dotenv-file-update-contract-invalid",
                "The managed dotenv file no longer satisfies its supported format.",
            ) from None
        except (OSError, UnicodeError, UnsafeInputPathError, UnsafeOutputPathError):
            raise ProviderOperationError(
                "dotenv-file-update-failed",
                "The managed dotenv file could not be updated safely.",
            ) from None
        finally:
            content = ""
            replacement = ""
            expected_key = ""
            replacement_key = ""

    def verify_binding(
        self,
        subscription_id: str,
        binding: CredentialBinding,
        resource: DiscoveredResource,
        expected_key: str,
    ) -> None:
        """Re-read every managed selector and compare it with the expected Azure key."""

        path = self._operation_path(subscription_id, binding, resource)
        if not expected_key:
            raise ProviderOperationError(
                "dotenv-file-verification-contract-invalid",
                "A dotenv binding did not match the expected verification shape.",
            )
        try:
            with open_managed_plaintext(path, max_bytes=MAX_DOTENV_FILE_BYTES) as stream:
                matches = dotenv_stream_values_equal(stream, binding.selectors, expected_key)
        except SecretInputError:
            raise ProviderOperationError(
                "dotenv-file-verification-contract-invalid",
                "The managed dotenv file no longer satisfies its supported format.",
            ) from None
        except (OSError, UnicodeError, UnsafeInputPathError):
            raise ProviderOperationError(
                "dotenv-file-verification-failed",
                "The managed dotenv file could not be re-read safely.",
            ) from None
        finally:
            expected_key = ""
        if not matches:
            raise ProviderOperationError(
                BINDING_VERIFICATION_MISMATCH_CODE,
                "The managed dotenv assignments did not retain the expected Azure key.",
            )

    @staticmethod
    def _operation_path(
        subscription_id: str,
        binding: CredentialBinding,
        resource: DiscoveredResource,
    ) -> Path:
        path = Path(binding.scope_id)
        valid_resource = (
            resource.key_authentication is KeyAuthentication.enabled
            and resource.resource_type in _KEY_RESOURCE_TYPES
            and binding.key_resource_id.casefold() == resource.resource_id.casefold()
            and binding.key_slot in {slot.name for slot in resource.key_slots}
        )
        valid_binding = (
            binding.provider == _PROVIDER_NAME
            and binding.binding_type == _BINDING_TYPE
            and binding.location is BindingLocation.local
            and binding.management is BindingManagement.update_and_verify
            and path.is_absolute()
            and normalize_dotenv_file_path(path) == path
            and binding.target == binding.scope_id
            and binding.scope_name == path.name
            and binding.name == ", ".join(binding.selectors)
            and binding.binding_id == _binding_id(path, resource.resource_id, binding.key_slot or "", binding.selectors)
        )
        if not valid_resource or not valid_binding:
            raise ProviderOperationError(
                "dotenv-file-operation-contract-invalid",
                "A dotenv operation did not match the expected binding shape.",
            )
        try:
            resource_coordinates(
                resource.resource_id,
                subscription_id=subscription_id,
                expected_resource_type=resource.resource_type,
                expected_name=resource.name,
            )
        except ResourceIdError:
            raise ProviderOperationError(
                "dotenv-file-operation-contract-invalid",
                "A dotenv operation did not match the expected binding shape.",
            ) from None
        return path


def _binding(
    path: Path,
    resource_id: str,
    key_slot: str,
    selectors: tuple[str, ...],
) -> CredentialBinding:
    return CredentialBinding(
        binding_id=_binding_id(path, resource_id, key_slot, selectors),
        name=", ".join(selectors),
        binding_type=_BINDING_TYPE,
        provider=_PROVIDER_NAME,
        location=BindingLocation.local,
        scope_id=str(path),
        scope_name=path.name,
        key_resource_id=resource_id,
        key_slot=key_slot,
        target=str(path),
        selectors=selectors,
        management=BindingManagement.update_and_verify,
    )


def _binding_id(path: Path, resource_id: str, key_slot: str, selectors: tuple[str, ...]) -> str:
    payload = json.dumps(
        ("azurator-dotenv-file-binding-v1", str(path), resource_id, key_slot, selectors),
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"dotenv-file:{hashlib.sha256(payload).hexdigest()}"

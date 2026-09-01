"""Managed updates for one explicitly selected SOPS-encrypted dotenv file."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from io import StringIO
from pathlib import Path

from azurator.files import (
    MAX_OPERATION_ARTIFACT_BYTES,
    UnsafeInputPathError,
    UnsafeOutputPathError,
    commit_regular_copy,
    resolve_parent_path,
    temporary_regular_copy,
)
from azurator.fingerprints import EphemeralFingerprinter, erase_fingerprint
from azurator.inputs import (
    SecretInputError,
    consume_dotenv,
    dotenv_values_equal,
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
from azurator.sops import SopsCli, SopsCommand, SopsError

_PROVIDER_NAME = "local-sops-dotenv-file"
_PROVIDER_CONTRACT_VERSION = "1"
_BINDING_TYPE = "local/sops-dotenv-file"
_STORAGE_RESOURCE_TYPE = "Microsoft.Storage/storageAccounts"
_COGNITIVE_RESOURCE_TYPE = "Microsoft.CognitiveServices/accounts"
_KEY_RESOURCE_TYPES = (_STORAGE_RESOURCE_TYPE, _COGNITIVE_RESOURCE_TYPE)
_MAX_SOPS_FILE_BYTES = MAX_OPERATION_ARTIFACT_BYTES

SOPS_DOTENV_FILE_PROVIDER_INFO = ProviderInfo(
    name=_PROVIDER_NAME,
    contract_version=_PROVIDER_CONTRACT_VERSION,
    resource_types=(_BINDING_TYPE,),
)


class SopsDotenvFileContractError(RuntimeError):
    """A SOPS dotenv source cannot be represented by the supported managed-file contract."""


def normalize_sops_dotenv_file_path(path: Path) -> Path:
    """Bind an absolute path to its resolved parent without following the final component."""

    return resolve_parent_path(path)


def attach_sops_dotenv_file_bindings(report: MatchReport, path: Path) -> MatchReport:
    """Treat matched assignments in one exact encrypted dotenv file as managed bindings."""

    source = normalize_sops_dotenv_file_path(path)
    if any(provider.name == _PROVIDER_NAME for provider in report.providers):
        raise SopsDotenvFileContractError("the SOPS dotenv-file provider was registered more than once")

    identities_by_selector: dict[str, set[tuple[str, str]]] = {}
    selectors_by_identity: dict[tuple[str, str], list[str]] = {}
    for match in report.matches:
        identity = (match.resource_id, match.key_slot)
        identities_by_selector.setdefault(match.input_selector, set()).add(identity)
        selectors_by_identity.setdefault(identity, []).append(match.input_selector)
    if any(len(identities) != 1 for identities in identities_by_selector.values()):
        raise SopsDotenvFileContractError(
            "a SOPS dotenv assignment matched more than one Azure key slot and cannot be updated safely"
        )

    input_order = {selector: index for index, selector in enumerate(report.input_selectors)}
    resources_by_id = {resource.resource_id: resource for resource in report.resources}
    bindings: list[CredentialBinding] = list(report.bindings)
    inspections: list[BindingInspection] = list(report.binding_inspections)
    inspected_resources: set[str] = set()
    for (resource_id, key_slot), matched_selectors in sorted(
        selectors_by_identity.items(),
        key=lambda item: (item[0][0].casefold(), item[0][1].casefold()),
    ):
        if resource_id not in resources_by_id:
            raise SopsDotenvFileContractError("a SOPS dotenv match has no supported Azure resource metadata")
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

    providers = tuple(sorted((*report.providers, SOPS_DOTENV_FILE_PROVIDER_INFO), key=lambda item: item.name))
    warnings = (
        *report.warnings,
        DiscoveryWarning(
            code="sops-file-managed-update",
            message=(
                "A file-sourced rotation atomically persists and verifies encrypted temporary bridge and final "
                "values through SOPS. If interrupted, the file may intentionally remain on a valid bridge until "
                "resume. Running workloads are not reloaded or health-checked."
            ),
            impact=WarningImpact.advisory,
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


class SopsDotenvFileProvider:
    """Update and verify exact assignments without writing decrypted SOPS content to disk."""

    def __init__(self, command: SopsCommand | None = None) -> None:
        self._command = command or SopsCli()

    @property
    def info(self) -> ProviderInfo:
        return SOPS_DOTENV_FILE_PROVIDER_INFO

    @property
    def location(self) -> BindingLocation:
        return BindingLocation.local

    @property
    def key_resource_types(self) -> tuple[str, ...]:
        return _KEY_RESOURCE_TYPES

    def read_source(self, path: Path) -> str:
        """Safely decrypt one encrypted dotenv snapshot into process memory."""

        source = normalize_sops_dotenv_file_path(path)
        try:
            with temporary_regular_copy(source, max_bytes=_MAX_SOPS_FILE_BYTES) as (temporary, _snapshot):
                return self._command.decrypt_dotenv(temporary)
        except SopsError:
            raise
        except (OSError, UnsafeInputPathError, UnsafeOutputPathError):
            raise SopsDotenvFileContractError(
                "the SOPS dotenv file is missing, unsafe, too large, or not owned by the current user"
            ) from None

    def inspect_bindings(
        self,
        subscription_id: str,
        resources: Sequence[DiscoveredResource],
        selected_resource_ids: frozenset[str],
        identify: CandidateIdentifier,
    ) -> ProviderBindingResult:
        """Reject generic inspection because the encrypted source file must be explicit."""

        del subscription_id, resources, identify
        if selected_resource_ids:
            raise SopsDotenvFileContractError("SOPS dotenv-file inspection requires one explicit source file")
        return ProviderBindingResult()

    def update_binding(
        self,
        subscription_id: str,
        binding: CredentialBinding,
        resource: DiscoveredResource,
        expected_key: str,
        replacement_key: str,
    ) -> None:
        """Atomically move exact encrypted assignments to one replacement key."""

        path = self._operation_path(subscription_id, binding, resource)
        if not expected_key or not replacement_key:
            raise ProviderOperationError(
                "sops-file-update-contract-invalid",
                "A SOPS dotenv binding did not match the expected update shape.",
            )

        before = ""
        after = ""
        before_fingerprints: dict[str, bytearray | None] = {}
        after_fingerprints: dict[str, bytearray | None] = {}
        try:
            with temporary_regular_copy(path, max_bytes=_MAX_SOPS_FILE_BYTES) as (temporary, snapshot):
                before = self._command.decrypt_dotenv(temporary)
                validate_dotenv_assignments(before, binding.selectors)
                if dotenv_values_equal(before, binding.selectors, replacement_key):
                    return
                if not dotenv_values_equal(before, binding.selectors, expected_key):
                    raise ProviderOperationError(
                        "sops-file-binding-drift-detected",
                        "The managed SOPS dotenv assignments changed after planning; they were not updated.",
                    )

                with EphemeralFingerprinter() as fingerprinter:
                    before_fingerprints = _dotenv_fingerprints(before, fingerprinter)
                    before = ""
                    for selector in binding.selectors:
                        self._command.set_dotenv_value(temporary, selector, replacement_key)
                    after = self._command.decrypt_dotenv(temporary)
                    validate_dotenv_assignments(after, binding.selectors)
                    if not dotenv_values_equal(after, binding.selectors, replacement_key):
                        raise ProviderOperationError(
                            "sops-file-update-verification-failed",
                            "The encrypted dotenv temporary did not retain the requested replacement.",
                        )
                    after_fingerprints = _dotenv_fingerprints(after, fingerprinter)
                    after = ""
                    if not _unselected_values_equal(
                        before_fingerprints,
                        after_fingerprints,
                        frozenset(binding.selectors),
                        fingerprinter,
                    ):
                        raise ProviderOperationError(
                            "sops-file-unselected-content-changed",
                            "SOPS changed an unselected dotenv assignment; the managed file was not replaced.",
                        )

                commit_regular_copy(snapshot, temporary, max_bytes=_MAX_SOPS_FILE_BYTES)
        except ProviderOperationError:
            raise
        except SecretInputError:
            raise ProviderOperationError(
                "sops-file-update-contract-invalid",
                "The managed SOPS dotenv file no longer satisfies its supported format.",
            ) from None
        except (SopsError, OSError, UnicodeError, UnsafeInputPathError, UnsafeOutputPathError):
            raise ProviderOperationError(
                "sops-file-update-failed",
                "The managed SOPS dotenv file could not be updated safely.",
            ) from None
        finally:
            before = ""
            after = ""
            _erase_dotenv_fingerprints(before_fingerprints)
            _erase_dotenv_fingerprints(after_fingerprints)
            expected_key = ""
            replacement_key = ""

    def verify_binding(
        self,
        subscription_id: str,
        binding: CredentialBinding,
        resource: DiscoveredResource,
        expected_key: str,
    ) -> None:
        """Decrypt a fresh encrypted snapshot and compare every managed selector."""

        path = self._operation_path(subscription_id, binding, resource)
        if not expected_key:
            raise ProviderOperationError(
                "sops-file-verification-contract-invalid",
                "A SOPS dotenv binding did not match the expected verification shape.",
            )
        content = ""
        try:
            content = self.read_source(path)
            matches = dotenv_values_equal(content, binding.selectors, expected_key)
        except SecretInputError:
            raise ProviderOperationError(
                "sops-file-verification-contract-invalid",
                "The managed SOPS dotenv file no longer satisfies its supported format.",
            ) from None
        except (SopsError, SopsDotenvFileContractError, OSError, UnicodeError):
            raise ProviderOperationError(
                "sops-file-verification-failed",
                "The managed SOPS dotenv file could not be re-read safely.",
            ) from None
        finally:
            content = ""
            expected_key = ""
        if not matches:
            raise ProviderOperationError(
                BINDING_VERIFICATION_MISMATCH_CODE,
                "The managed SOPS dotenv assignments did not retain the expected Azure key.",
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
            and normalize_sops_dotenv_file_path(path) == path
            and binding.target == binding.scope_id
            and binding.scope_name == path.name
            and binding.name == ", ".join(binding.selectors)
            and binding.binding_id == _binding_id(path, resource.resource_id, binding.key_slot or "", binding.selectors)
        )
        if not valid_resource or not valid_binding:
            raise ProviderOperationError(
                "sops-file-operation-contract-invalid",
                "A SOPS dotenv operation did not match the expected binding shape.",
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
                "sops-file-operation-contract-invalid",
                "A SOPS dotenv operation did not match the expected binding shape.",
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
        ("azurator-sops-dotenv-file-binding-v1", str(path), resource_id, key_slot, selectors),
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"sops-dotenv-file:{hashlib.sha256(payload).hexdigest()}"


def _dotenv_fingerprints(
    content: str,
    fingerprinter: EphemeralFingerprinter,
) -> dict[str, bytearray | None]:
    fingerprints: dict[str, bytearray | None] = {}
    try:
        result = consume_dotenv(
            StringIO(content, newline=""),
            lambda selector, value: fingerprints.__setitem__(selector, fingerprinter.derive(value)),
        )
        for selector in result.skipped_empty_selectors:
            fingerprints[selector] = None
        return fingerprints
    except BaseException:
        _erase_dotenv_fingerprints(fingerprints)
        raise


def _unselected_values_equal(
    before: dict[str, bytearray | None],
    after: dict[str, bytearray | None],
    selected: frozenset[str],
    fingerprinter: EphemeralFingerprinter,
) -> bool:
    before_selectors = set(before) - selected
    after_selectors = set(after) - selected
    if before_selectors != after_selectors:
        return False
    for selector in before_selectors:
        first = before[selector]
        second = after[selector]
        if first is None or second is None:
            if first is not second:
                return False
        elif not fingerprinter.equal(first, second):
            return False
    return True


def _erase_dotenv_fingerprints(fingerprints: dict[str, bytearray | None]) -> None:
    for fingerprint in fingerprints.values():
        if fingerprint is not None:
            erase_fingerprint(fingerprint)
    fingerprints.clear()

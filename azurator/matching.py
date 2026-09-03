"""Read-only orchestration for ephemeral matching of input values to Azure slots."""

from __future__ import annotations

import secrets
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import TextIO

from azurator.credential_values import STORAGE_RESOURCE_TYPE, parse_storage_shared_key_connection_string
from azurator.discovery import utc_now
from azurator.fingerprints import EphemeralFingerprinter, erase_fingerprint
from azurator.inputs import SecretInputError, consume_dotenv
from azurator.models import (
    AzureBindingInspection,
    BindingInspection,
    BindingInspectionStatus,
    BindingLocation,
    CandidateInspection,
    CandidateInspectionStatus,
    CredentialBinding,
    DiscoveredResource,
    DiscoveryWarning,
    Inventory,
    KeyAuthentication,
    KeyMatch,
    KeySlotSelection,
    MatchReport,
    MatchResource,
    ProviderInfo,
    SelectionReport,
    WarningCategory,
    WarningImpact,
)
from azurator.providers.base import BindingProvider, MatchingProvider

_MATCH_COVERAGE_WARNING = DiscoveryWarning(
    code="provider-coverage-limited",
    message=(
        "Matching covers only the key-resource and credential-binding types supported by this Azurator build; "
        "it is not a complete search across every Azure secret."
    ),
    impact=WarningImpact.advisory,
    category=WarningCategory.coverage,
)

_AZURE_BINDING_INSPECTION_SKIPPED_WARNING = DiscoveryWarning(
    code="azure-binding-inspection-skipped",
    message=(
        "Automatic Azure credential-binding inspection was explicitly skipped. "
        "Azure-side configurations containing the selected keys were not included."
    ),
    impact=WarningImpact.confirmation,
    category=WarningCategory.credential_binding,
)


class MatchingError(RuntimeError):
    """Matching could not complete without violating a provider contract."""


KeyFactory = Callable[[], bytes]


def _new_session_key() -> bytes:
    return secrets.token_bytes(32)


@dataclass
class _InputFingerprint:
    selector: str
    digest: bytearray = field(repr=False)
    resource_type: str | None = None
    resource_name: str | None = None

    def erase(self) -> None:
        erase_fingerprint(self.digest)


class _MatchAccumulator:
    def __init__(
        self,
        fingerprinter: EphemeralFingerprinter,
        inputs: Sequence[_InputFingerprint],
        allowed_slots: dict[str, frozenset[str]],
        resources: dict[str, DiscoveredResource],
    ) -> None:
        self._fingerprinter = fingerprinter
        self._inputs = tuple(inputs)
        self._allowed_slots = allowed_slots
        self._resources = resources
        self._consumed_slots: set[tuple[str, str]] = set()
        self._candidate_fingerprints: dict[tuple[str, str], bytearray] = {}
        self.matches: list[KeyMatch] = []

    @property
    def consumed_slots(self) -> frozenset[tuple[str, str]]:
        return frozenset(self._consumed_slots)

    def consume(self, resource_id: str, key_slot: str, value: str) -> None:
        allowed = self._allowed_slots.get(resource_id)
        identity = (resource_id, key_slot)
        if allowed is None or key_slot not in allowed or identity in self._consumed_slots or not value:
            raise MatchingError("a provider violated the supported candidate-consumption contract")
        resource = self._resources.get(resource_id)
        if resource is None:
            raise MatchingError("a provider consumed a candidate without supported resource metadata")

        candidate = self._fingerprinter.derive(value)
        try:
            for input_fingerprint in self._inputs:
                if input_fingerprint.resource_type is not None and (
                    resource.resource_type.casefold() != input_fingerprint.resource_type.casefold()
                    or resource.name.casefold() != (input_fingerprint.resource_name or "").casefold()
                ):
                    continue
                if self._fingerprinter.equal(input_fingerprint.digest, candidate):
                    self.matches.append(
                        KeyMatch(
                            input_selector=input_fingerprint.selector,
                            resource_id=resource_id,
                            key_slot=key_slot,
                        )
                    )
        except BaseException:
            erase_fingerprint(candidate)
            raise
        self._candidate_fingerprints[identity] = candidate
        self._consumed_slots.add(identity)

    def identify(self, resource_id: str, value: str) -> str | None:
        allowed = self._allowed_slots.get(resource_id)
        if allowed is None or not value:
            raise MatchingError("a binding provider violated the supported credential-identification contract")

        fingerprint = self._fingerprinter.derive(value)
        try:
            matches = [
                slot
                for (candidate_resource_id, slot), candidate in self._candidate_fingerprints.items()
                if candidate_resource_id == resource_id and self._fingerprinter.equal(fingerprint, candidate)
            ]
        finally:
            erase_fingerprint(fingerprint)
        if len(matches) > 1:
            raise MatchingError("a binding credential ambiguously matched more than one candidate slot")
        return matches[0] if matches else None

    def close(self) -> None:
        for fingerprint in self._candidate_fingerprints.values():
            erase_fingerprint(fingerprint)
        self._candidate_fingerprints.clear()


class MatchingService:
    """Discover supported resources, retrieve their slots, and compare in memory."""

    def __init__(
        self,
        providers: Sequence[MatchingProvider],
        *,
        binding_providers: Sequence[BindingProvider] = (),
        azure_binding_inspection: AzureBindingInspection = AzureBindingInspection.enabled,
        clock: Callable[[], datetime] = utc_now,
        key_factory: KeyFactory = _new_session_key,
    ) -> None:
        self._providers = tuple(providers)
        self._binding_providers = tuple(binding_providers)
        self._azure_binding_inspection = azure_binding_inspection
        self._clock = clock
        self._key_factory = key_factory
        if any(provider.location is not BindingLocation.azure for provider in self._binding_providers):
            raise ValueError("automatic binding providers must manage Azure bindings")
        if self._azure_binding_inspection is AzureBindingInspection.skipped and self._binding_providers:
            raise ValueError("skipped Azure binding inspection cannot register Azure binding providers")

    def match_dotenv(self, subscription_id: str, stream: TextIO) -> MatchReport:
        """Consume dotenv values and compare them against one selected subscription."""

        inputs: list[_InputFingerprint] = []
        with EphemeralFingerprinter(self._key_factory()) as fingerprinter:
            try:

                def consume_input(selector: str, value: str) -> None:
                    parsed = parse_storage_shared_key_connection_string(value)
                    candidate = value
                    resource_type: str | None = None
                    resource_name: str | None = None
                    try:
                        if parsed is not None:
                            candidate = parsed.account_key
                            resource_type = STORAGE_RESOURCE_TYPE
                            resource_name = parsed.account_name
                        inputs.append(
                            _InputFingerprint(
                                selector=selector,
                                digest=fingerprinter.derive(candidate),
                                resource_type=resource_type,
                                resource_name=resource_name,
                            )
                        )
                    finally:
                        candidate = ""
                        value = ""

                input_summary = consume_dotenv(
                    stream,
                    consume_input,
                )
                if not inputs:
                    raise SecretInputError("dotenv input contains no non-empty values")

                return self._match_fingerprints(
                    subscription_id,
                    inputs,
                    input_summary.skipped_empty_selectors,
                    fingerprinter,
                )
            finally:
                for input_fingerprint in inputs:
                    input_fingerprint.erase()

    def inspect_selection(
        self,
        subscription_id: str,
        inventory: Inventory,
        selections: Sequence[KeySlotSelection],
    ) -> SelectionReport:
        """Inspect explicitly selected slots and their supported bindings in memory."""

        if inventory.subscription_id != subscription_id:
            raise MatchingError("the selection inventory does not match the selected subscription")
        if not selections:
            raise MatchingError("direct planning requires at least one selected key slot")

        provider_names = [provider.info.name.casefold() for provider in (*self._providers, *self._binding_providers)]
        if len(provider_names) != len(set(provider_names)):
            raise MatchingError("installed providers returned conflicting provider metadata")

        providers_by_name = {provider.info.name: provider for provider in self._providers}
        inventory_providers = {provider.name: provider for provider in inventory.providers}
        if len(inventory_providers) != len(inventory.providers) or any(
            inventory_providers.get(name) != provider.info for name, provider in providers_by_name.items()
        ):
            raise MatchingError("the selection inventory does not match the installed provider contracts")

        resources_by_normalized_id: dict[str, DiscoveredResource] = {}
        for resource in inventory.resources:
            normalized_id = resource.resource_id.casefold()
            if resource.provider not in providers_by_name or normalized_id in resources_by_normalized_id:
                raise MatchingError("the selection inventory contains conflicting resource metadata")
            resources_by_normalized_id[normalized_id] = resource

        selected_identities: set[tuple[str, str]] = set()
        canonical_selections: list[KeySlotSelection] = []
        selected_resources: dict[str, DiscoveredResource] = {}
        for selection in selections:
            resource = resources_by_normalized_id.get(selection.resource_id.casefold())
            if resource is None:
                raise MatchingError("a selected Azure resource is no longer available")
            declared = {slot.name: slot for slot in resource.key_slots}
            slot = declared.get(selection.key_slot)
            if (
                resource.key_authentication is not KeyAuthentication.enabled
                or len(declared) != 2
                or len(declared) != len(resource.key_slots)
                or any(not candidate.values_retrievable for candidate in resource.key_slots)
                or slot is None
                or not slot.rotatable
            ):
                raise MatchingError("a selected key slot does not satisfy the supported rotation contract")
            identity = (resource.resource_id.casefold(), slot.name)
            if identity in selected_identities:
                raise MatchingError("a key slot was selected more than once")
            selected_identities.add(identity)
            selected_resources[resource.resource_id] = resource
            canonical_selections.append(KeySlotSelection(resource_id=resource.resource_id, key_slot=slot.name))

        resource_order = {resource.resource_id: index for index, resource in enumerate(inventory.resources)}
        slot_order = {
            (resource.resource_id, slot.name): index
            for resource in selected_resources.values()
            for index, slot in enumerate(resource.key_slots)
        }
        ordered_selections = tuple(
            sorted(
                canonical_selections,
                key=lambda item: (resource_order[item.resource_id], slot_order[(item.resource_id, item.key_slot)]),
            )
        )
        selected_resource_ids = frozenset(selected_resources)
        allowed_slots = {
            resource.resource_id: frozenset(slot.name for slot in resource.key_slots)
            for resource in selected_resources.values()
        }
        report_resources = {
            resource.resource_id: MatchResource(
                resource_id=resource.resource_id,
                name=resource.name,
                resource_type=resource.resource_type,
                location=resource.location,
                kind=resource.kind,
                endpoint=resource.endpoint,
                provider=resource.provider,
                key_slots=resource.key_slots,
            )
            for resource in selected_resources.values()
        }
        warnings = [warning for warning in inventory.warnings if not _is_untested_permission_warning(warning)]

        with EphemeralFingerprinter(self._key_factory()) as fingerprinter:
            accumulator = _MatchAccumulator(fingerprinter, (), allowed_slots, selected_resources)
            try:
                inspections: list[CandidateInspection] = []
                declared_consumed_slots: set[tuple[str, str]] = set()
                for provider in self._providers:
                    targets = tuple(
                        resource
                        for resource in inventory.resources
                        if resource.resource_id in selected_resource_ids and resource.provider == provider.info.name
                    )
                    if not targets:
                        continue
                    result = provider.inspect_candidates(subscription_id, targets, accumulator.consume)
                    warnings.extend(result.warnings)
                    self._validate_candidate_result(
                        targets,
                        result.inspections,
                        allowed_slots,
                        declared_consumed_slots,
                    )
                    inspections.extend(result.inspections)

                if accumulator.consumed_slots != frozenset(declared_consumed_slots):
                    raise MatchingError("provider candidate values and inspection metadata did not agree")

                binding_inspections, bindings, warnings = self._inspect_bindings(
                    subscription_id,
                    inventory.resources,
                    selected_resources,
                    selected_resource_ids,
                    declared_consumed_slots,
                    accumulator.identify,
                    warnings,
                )
                provider_info = tuple(
                    sorted(
                        (provider.info for provider in (*self._providers, *self._binding_providers)),
                        key=lambda item: item.name,
                    )
                )
                return SelectionReport(
                    subscription_id=subscription_id,
                    subscription_name=inventory.subscription_name,
                    generated_at=self._clock(),
                    azure_binding_inspection=self._azure_binding_inspection,
                    providers=provider_info,
                    resources=tuple(
                        report_resources[resource_id]
                        for resource_id in sorted(report_resources, key=lambda item: resource_order[item])
                    ),
                    inspections=tuple(sorted(inspections, key=lambda item: item.resource_id.casefold())),
                    selected_slots=ordered_selections,
                    binding_inspections=binding_inspections,
                    bindings=bindings,
                    warnings=tuple(warnings),
                )
            finally:
                accumulator.close()

    def _match_fingerprints(
        self,
        subscription_id: str,
        inputs: Sequence[_InputFingerprint],
        skipped_empty_selectors: tuple[str, ...],
        fingerprinter: EphemeralFingerprinter,
    ) -> MatchReport:
        provider_targets: list[tuple[MatchingProvider, tuple[DiscoveredResource, ...]]] = []
        provider_info: list[ProviderInfo] = [provider.info for provider in self._binding_providers]
        resources_by_id: dict[str, MatchResource] = {}
        discovered_by_id: dict[str, DiscoveredResource] = {}
        all_discovered_resources: list[DiscoveredResource] = []
        all_discovered_ids: set[str] = set()
        allowed_slots: dict[str, frozenset[str]] = {}
        warnings: list[DiscoveryWarning] = [_MATCH_COVERAGE_WARNING]

        provider_names = [provider.info.name.casefold() for provider in (*self._providers, *self._binding_providers)]
        if len(provider_names) != len(set(provider_names)):
            raise MatchingError("installed providers returned conflicting provider metadata")

        for provider in self._providers:
            provider_info.append(provider.info)
            discovery = provider.discover(subscription_id)
            warnings.extend(warning for warning in discovery.warnings if not _is_untested_permission_warning(warning))
            for resource in discovery.resources:
                normalized_id = resource.resource_id.casefold()
                if resource.provider != provider.info.name or normalized_id in all_discovered_ids:
                    raise MatchingError("a provider returned conflicting resource metadata")
                all_discovered_ids.add(normalized_id)
                all_discovered_resources.append(resource)
            targets = tuple(
                resource
                for resource in discovery.resources
                if resource.key_authentication is KeyAuthentication.enabled
                and any(slot.values_retrievable for slot in resource.key_slots)
            )
            provider_targets.append((provider, targets))
            for resource in targets:
                slots = frozenset(slot.name for slot in resource.key_slots if slot.values_retrievable)
                if not slots:
                    raise MatchingError("a provider returned a candidate resource without retrievable slots")
                discovered_by_id[resource.resource_id] = resource
                allowed_slots[resource.resource_id] = slots
                resources_by_id[resource.resource_id] = MatchResource(
                    resource_id=resource.resource_id,
                    name=resource.name,
                    resource_type=resource.resource_type,
                    location=resource.location,
                    kind=resource.kind,
                    endpoint=resource.endpoint,
                    provider=resource.provider,
                    key_slots=resource.key_slots,
                )

        accumulator = _MatchAccumulator(fingerprinter, inputs, allowed_slots, discovered_by_id)
        try:
            inspections: list[CandidateInspection] = []
            declared_consumed_slots: set[tuple[str, str]] = set()

            for provider, targets in provider_targets:
                result = provider.inspect_candidates(subscription_id, targets, accumulator.consume)
                warnings.extend(result.warnings)
                target_ids = {resource.resource_id for resource in targets}
                inspection_ids = [inspection.resource_id for inspection in result.inspections]
                if len(inspection_ids) != len(set(inspection_ids)) or set(inspection_ids) != target_ids:
                    raise MatchingError("a provider returned incomplete candidate-inspection metadata")
                for inspection in result.inspections:
                    allowed = allowed_slots[inspection.resource_id]
                    if not set(inspection.key_slots).issubset(allowed):
                        raise MatchingError("a provider reported an undeclared candidate slot")
                    if inspection.status is CandidateInspectionStatus.unavailable and inspection.key_slots:
                        raise MatchingError("an unavailable candidate inspection reported compared slots")
                    for key_slot in inspection.key_slots:
                        identity = (inspection.resource_id, key_slot)
                        if identity in declared_consumed_slots:
                            raise MatchingError("a provider reported a candidate slot more than once")
                        declared_consumed_slots.add(identity)
                inspections.extend(result.inspections)

            if accumulator.consumed_slots != frozenset(declared_consumed_slots):
                raise MatchingError("provider candidate values and inspection metadata did not agree")

            input_order = {item.selector: index for index, item in enumerate(inputs)}
            resource_order = {
                resource_id: index for index, resource_id in enumerate(sorted(resources_by_id, key=str.casefold))
            }
            matches = tuple(
                sorted(
                    accumulator.matches,
                    key=lambda item: (
                        input_order[item.input_selector],
                        resource_order[item.resource_id],
                        item.key_slot.casefold(),
                    ),
                )
            )
            selected_resource_ids = frozenset(match.resource_id for match in matches)
            binding_inspections, bindings, warnings = self._inspect_bindings(
                subscription_id,
                tuple(all_discovered_resources),
                discovered_by_id,
                selected_resource_ids,
                declared_consumed_slots,
                accumulator.identify,
                warnings,
            )

            return MatchReport(
                subscription_id=subscription_id,
                generated_at=self._clock(),
                azure_binding_inspection=self._azure_binding_inspection,
                providers=tuple(sorted(provider_info, key=lambda item: item.name)),
                input_selectors=tuple(item.selector for item in inputs),
                skipped_empty_selectors=skipped_empty_selectors,
                resources=tuple(resources_by_id[key] for key in sorted(resources_by_id, key=str.casefold)),
                inspections=tuple(sorted(inspections, key=lambda item: item.resource_id.casefold())),
                candidate_slots_compared=len(declared_consumed_slots),
                matches=matches,
                binding_inspections=binding_inspections,
                bindings=bindings,
                warnings=tuple(warnings),
            )
        finally:
            accumulator.close()

    @staticmethod
    def _validate_candidate_result(
        targets: Sequence[DiscoveredResource],
        inspections: Sequence[CandidateInspection],
        allowed_slots: dict[str, frozenset[str]],
        declared_consumed_slots: set[tuple[str, str]],
    ) -> None:
        target_ids = {resource.resource_id for resource in targets}
        inspection_ids = [inspection.resource_id for inspection in inspections]
        if len(inspection_ids) != len(set(inspection_ids)) or set(inspection_ids) != target_ids:
            raise MatchingError("a provider returned incomplete candidate-inspection metadata")
        for inspection in inspections:
            allowed = allowed_slots[inspection.resource_id]
            if not set(inspection.key_slots).issubset(allowed):
                raise MatchingError("a provider reported an undeclared candidate slot")
            if inspection.status is CandidateInspectionStatus.unavailable and inspection.key_slots:
                raise MatchingError("an unavailable candidate inspection reported compared slots")
            for key_slot in inspection.key_slots:
                identity = (inspection.resource_id, key_slot)
                if identity in declared_consumed_slots:
                    raise MatchingError("a provider reported a candidate slot more than once")
                declared_consumed_slots.add(identity)

    def _inspect_bindings(
        self,
        subscription_id: str,
        all_discovered_resources: Sequence[DiscoveredResource],
        discovered_by_id: dict[str, DiscoveredResource],
        selected_resource_ids: frozenset[str],
        declared_consumed_slots: set[tuple[str, str]],
        identify_candidate: Callable[[str, str], str | None],
        warnings: list[DiscoveryWarning],
    ) -> tuple[tuple[BindingInspection, ...], tuple[CredentialBinding, ...], list[DiscoveryWarning]]:
        selected_resource_providers = {discovered_by_id[resource_id].provider for resource_id in selected_resource_ids}
        if self._azure_binding_inspection is AzureBindingInspection.skipped:
            filtered_warnings = [
                warning for warning in warnings if warning.category is not WarningCategory.credential_binding
            ]
            if selected_resource_ids:
                filtered_warnings.append(_AZURE_BINDING_INSPECTION_SKIPPED_WARNING)
            return (), (), filtered_warnings

        binding_inspections: list[BindingInspection] = []
        bindings: list[CredentialBinding] = []
        seen_bindings: set[tuple[str, str]] = set()
        replaced_binding_coverage_providers: set[str] = set()
        binding_warnings: list[DiscoveryWarning] = []

        for provider in self._binding_providers:
            supported_types = {resource_type.casefold() for resource_type in provider.key_resource_types}
            expected_ids = frozenset(
                resource_id
                for resource_id in selected_resource_ids
                if discovered_by_id[resource_id].resource_type.casefold() in supported_types
            )
            if not expected_ids:
                continue
            replaced_binding_coverage_providers.update(
                discovered_by_id[resource_id].provider for resource_id in expected_ids
            )

            def identify(resource_id: str, value: str) -> str | None:
                if resource_id not in expected_ids:
                    raise MatchingError("a binding provider inspected an unselected key resource")
                return identify_candidate(resource_id, value)

            result = provider.inspect_bindings(
                subscription_id,
                all_discovered_resources,
                expected_ids,
                identify,
            )
            if any(warning.provider != provider.info.name for warning in result.warnings):
                raise MatchingError("a binding provider returned conflicting warning metadata")
            binding_warnings.extend(result.warnings)
            inspection_ids = [inspection.resource_id for inspection in result.inspections]
            if len(inspection_ids) != len(set(inspection_ids)) or set(inspection_ids) != set(expected_ids):
                raise MatchingError("a binding provider returned incomplete inspection metadata")
            for inspection in result.inspections:
                if inspection.provider != provider.info.name:
                    raise MatchingError("a binding provider returned conflicting inspection metadata")
                if inspection.location is not provider.location:
                    raise MatchingError("a binding provider returned inspection metadata outside its location")
                if inspection.status is BindingInspectionStatus.unavailable and inspection.scopes_inspected:
                    raise MatchingError("an unavailable binding inspection reported inspected scopes")
            binding_inspections.extend(result.inspections)

            for binding in result.bindings:
                identity = (provider.info.name.casefold(), binding.binding_id.casefold())
                if (
                    binding.provider != provider.info.name
                    or binding.key_resource_id not in expected_ids
                    or identity in seen_bindings
                ):
                    raise MatchingError("a binding provider returned conflicting binding metadata")
                if binding.location is not provider.location:
                    raise MatchingError("a binding provider returned binding metadata outside its location")
                if binding.key_slot is not None:
                    candidate_identity = (binding.key_resource_id, binding.key_slot)
                    if candidate_identity not in declared_consumed_slots:
                        raise MatchingError("a binding provider attributed an undeclared candidate slot")
                seen_bindings.add(identity)
                bindings.append(binding)

        filtered_warnings = [
            warning
            for warning in warnings
            if not (
                warning.category is WarningCategory.credential_binding
                and warning.provider is not None
                and (
                    warning.provider not in selected_resource_providers
                    or warning.provider in replaced_binding_coverage_providers
                )
            )
        ]
        filtered_warnings.extend(binding_warnings)
        return (
            tuple(sorted(binding_inspections, key=lambda item: (item.provider, item.resource_id.casefold()))),
            tuple(sorted(bindings, key=lambda item: (item.scope_name.casefold(), item.name.casefold()))),
            filtered_warnings,
        )


def _is_untested_permission_warning(warning: DiscoveryWarning) -> bool:
    return warning.category is WarningCategory.permission and warning.impact is WarningImpact.advisory

"""Tests for secret-free matching orchestration with fake providers."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timezone
from io import StringIO

import pytest

import azurator.matching as matching_module
from azurator.inputs import SecretInputError
from azurator.matching import MatchingError, MatchingService
from azurator.models import (
    AzureBindingInspection,
    BindingInspection,
    BindingInspectionStatus,
    BindingLocation,
    BindingManagement,
    CandidateInspection,
    CandidateInspectionStatus,
    CredentialBinding,
    DiscoveredResource,
    DiscoveryWarning,
    Inventory,
    KeyAuthentication,
    KeySlot,
    KeySlotSelection,
    ProviderBindingResult,
    ProviderCandidateResult,
    ProviderDiscovery,
    ProviderInfo,
    WarningCategory,
    WarningImpact,
)
from azurator.providers.base import CandidateIdentifier, CandidateSink

SUBSCRIPTION_ID = "11111111-1111-1111-1111-111111111111"
NOW = datetime(2000, 1, 1, 12, 0, tzinfo=timezone.utc)


def _resource(name: str) -> DiscoveredResource:
    return DiscoveredResource(
        resource_id=(f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/Example.Accounts/accounts/{name}"),
        name=name,
        resource_type="Example.Accounts/accounts",
        location="westeurope",
        kind="Example",
        endpoint=f"https://{name}.example.test/",
        provider="fake-provider",
        key_authentication=KeyAuthentication.enabled,
        key_slots=(
            KeySlot(name="key1", values_retrievable=True, rotatable=True),
            KeySlot(name="key2", values_retrievable=True, rotatable=True),
        ),
    )


class FakeMatchingProvider:
    def __init__(self) -> None:
        self.first = _resource("first")
        self.second = _resource("second")
        self.discovery_calls: list[str] = []
        self.inspection_calls: list[str] = []
        self.inspection_targets: list[tuple[str, ...]] = []
        self.candidates = {
            self.first.resource_id: (("key1", "alpha-secret"), ("key2", "unmatched-secret")),
            self.second.resource_id: (("key1", "beta-secret"),),
        }

    @property
    def info(self) -> ProviderInfo:
        return ProviderInfo(
            name="fake-provider",
            contract_version="1",
            resource_types=("Example.Accounts/accounts",),
        )

    def discover(self, subscription_id: str) -> ProviderDiscovery:
        self.discovery_calls.append(subscription_id)
        return ProviderDiscovery(
            resources=(self.first, self.second),
            warnings=(
                DiscoveryWarning(
                    code="fake-key-permissions-not-tested",
                    message="not filtered",
                    impact=WarningImpact.advisory,
                    category=WarningCategory.contract,
                ),
                DiscoveryWarning(
                    code="storage-key-permissions-not-tested",
                    message="filtered",
                    impact=WarningImpact.advisory,
                    category=WarningCategory.permission,
                ),
            ),
        )

    def inspect_candidates(
        self,
        subscription_id: str,
        resources: Sequence[DiscoveredResource],
        consume: CandidateSink,
    ) -> ProviderCandidateResult:
        self.inspection_calls.append(subscription_id)
        self.inspection_targets.append(tuple(resource.resource_id for resource in resources))
        inspections: list[CandidateInspection] = []
        for resource in resources:
            slots: list[str] = []
            for slot, value in self.candidates[resource.resource_id]:
                consume(resource.resource_id, slot, value)
                slots.append(slot)
            inspections.append(
                CandidateInspection(
                    resource_id=resource.resource_id,
                    status=CandidateInspectionStatus.compared,
                    key_slots=tuple(slots),
                )
            )
        return ProviderCandidateResult(inspections=tuple(inspections))


def test_matching_reports_selectors_resources_and_slots_without_values() -> None:
    provider = FakeMatchingProvider()
    service = MatchingService((provider,), clock=lambda: NOW, key_factory=lambda: b"k" * 32)

    report = service.match_dotenv(
        SUBSCRIPTION_ID,
        StringIO("FIRST=alpha-secret\nSECOND=beta-secret\nALIAS=alpha-secret\nEMPTY=\n"),
    )

    assert provider.discovery_calls == [SUBSCRIPTION_ID]
    assert provider.inspection_calls == [SUBSCRIPTION_ID]
    assert report.generated_at == NOW
    assert report.input_selectors == ("FIRST", "SECOND", "ALIAS")
    assert report.skipped_empty_selectors == ("EMPTY",)
    assert report.candidate_slots_compared == 3
    assert {resource.name: resource.endpoint for resource in report.resources} == {
        "first": "https://first.example.test/",
        "second": "https://second.example.test/",
    }
    assert [(match.input_selector, match.resource_id, match.key_slot) for match in report.matches] == [
        ("FIRST", provider.first.resource_id, "key1"),
        ("SECOND", provider.second.resource_id, "key1"),
        ("ALIAS", provider.first.resource_id, "key1"),
    ]
    assert "storage-key-permissions-not-tested" not in {warning.code for warning in report.warnings}
    assert "fake-key-permissions-not-tested" in {warning.code for warning in report.warnings}

    serialized = report.model_dump_json()
    for raw_value in ("alpha-secret", "beta-secret", "unmatched-secret"):
        assert raw_value not in serialized
    assert "session-match" not in serialized


def test_matching_rejects_empty_input_before_calling_a_provider() -> None:
    provider = FakeMatchingProvider()
    service = MatchingService((provider,), key_factory=lambda: b"k" * 32)

    with pytest.raises(SecretInputError, match="no non-empty values"):
        service.match_dotenv(SUBSCRIPTION_ID, StringIO("EMPTY=\n# comment\n"))

    assert provider.discovery_calls == []
    assert provider.inspection_calls == []


class InvalidSlotProvider(FakeMatchingProvider):
    def inspect_candidates(
        self,
        subscription_id: str,
        resources: Sequence[DiscoveredResource],
        consume: CandidateSink,
    ) -> ProviderCandidateResult:
        del subscription_id
        consume(resources[0].resource_id, "undeclared", "must-never-appear")
        raise AssertionError("the binding must reject the slot")


def test_matching_rejects_provider_contract_violations_without_values() -> None:
    service = MatchingService((InvalidSlotProvider(),), key_factory=lambda: b"k" * 32)

    with pytest.raises(MatchingError) as raised:
        service.match_dotenv(SUBSCRIPTION_ID, StringIO("TOKEN=input-secret\n"))

    message = str(raised.value)
    assert "must-never-appear" not in message
    assert "input-secret" not in message


class InvalidInspectionProvider(FakeMatchingProvider):
    def __init__(self, violation: str) -> None:
        super().__init__()
        self.violation = violation

    def inspect_candidates(
        self,
        subscription_id: str,
        resources: Sequence[DiscoveredResource],
        consume: CandidateSink,
    ) -> ProviderCandidateResult:
        del subscription_id, consume
        if self.violation == "incomplete":
            return ProviderCandidateResult(
                inspections=(
                    CandidateInspection(
                        resource_id=resources[0].resource_id,
                        status=CandidateInspectionStatus.unavailable,
                    ),
                )
            )

        first_status = CandidateInspectionStatus.compared
        first_slots = ("key1",)
        if self.violation == "undeclared-slot":
            first_slots = ("undeclared",)
        elif self.violation == "unavailable-with-slot":
            first_status = CandidateInspectionStatus.unavailable
        elif self.violation == "duplicate-slot":
            first_slots = ("key1", "key1")

        return ProviderCandidateResult(
            inspections=(
                CandidateInspection(
                    resource_id=resources[0].resource_id,
                    status=first_status,
                    key_slots=first_slots,
                ),
                CandidateInspection(
                    resource_id=resources[1].resource_id,
                    status=CandidateInspectionStatus.unavailable,
                ),
            )
        )


@pytest.mark.parametrize(
    "violation",
    ("incomplete", "undeclared-slot", "unavailable-with-slot", "duplicate-slot", "metadata-mismatch"),
)
def test_matching_rejects_inconsistent_provider_inspection_metadata(violation: str) -> None:
    service = MatchingService((InvalidInspectionProvider(violation),), key_factory=lambda: b"k" * 32)

    with pytest.raises(MatchingError):
        service.match_dotenv(SUBSCRIPTION_ID, StringIO("TOKEN=input-secret\n"))


class FakeBindingProvider:
    def __init__(self, key_resource_id: str) -> None:
        self.key_resource_id = key_resource_id
        self.calls: list[tuple[str, frozenset[str]]] = []

    @property
    def info(self) -> ProviderInfo:
        return ProviderInfo(
            name="fake-binding-provider",
            contract_version="1",
            resource_types=("Example.Accounts/accounts/bindings",),
        )

    @property
    def location(self) -> BindingLocation:
        return BindingLocation.azure

    @property
    def key_resource_types(self) -> tuple[str, ...]:
        return ("Example.Accounts/accounts",)

    def inspect_bindings(
        self,
        subscription_id: str,
        resources: Sequence[DiscoveredResource],
        selected_resource_ids: frozenset[str],
        identify: CandidateIdentifier,
    ) -> ProviderBindingResult:
        del resources
        self.calls.append((subscription_id, selected_resource_ids))
        slot = identify(self.key_resource_id, "alpha-secret")
        return ProviderBindingResult(
            inspections=(
                BindingInspection(
                    resource_id=self.key_resource_id,
                    provider=self.info.name,
                    location=BindingLocation.azure,
                    status=BindingInspectionStatus.inspected,
                    scopes_inspected=1,
                ),
            ),
            bindings=(
                CredentialBinding(
                    binding_id="/example/bindings/one",
                    name="binding-one",
                    binding_type="Example.Accounts/accounts/bindings",
                    provider=self.info.name,
                    location=BindingLocation.azure,
                    scope_id="/example/scopes/one",
                    scope_name="scope-one",
                    key_resource_id=self.key_resource_id,
                    key_slot=slot,
                    selectors=(),
                    management=BindingManagement.observed_only,
                ),
            ),
        )


def test_matching_attributes_binding_credentials_with_ephemeral_candidate_fingerprints() -> None:
    matching_provider = FakeMatchingProvider()
    binding_provider = FakeBindingProvider(matching_provider.first.resource_id)
    service = MatchingService(
        (matching_provider,),
        binding_providers=(binding_provider,),
        clock=lambda: NOW,
        key_factory=lambda: b"k" * 32,
    )

    report = service.match_dotenv(SUBSCRIPTION_ID, StringIO("FIRST=alpha-secret\n"))

    assert binding_provider.calls == [(SUBSCRIPTION_ID, frozenset({matching_provider.first.resource_id}))]
    assert report.schema_version == "1"
    assert [provider.name for provider in report.providers] == ["fake-binding-provider", "fake-provider"]
    assert report.binding_inspections[0].status is BindingInspectionStatus.inspected
    assert report.bindings[0].key_resource_id == matching_provider.first.resource_id
    assert report.bindings[0].key_slot == "key1"
    serialized = report.model_dump_json()
    assert "alpha-secret" not in serialized
    assert "unmatched-secret" not in serialized


def test_matching_can_explicitly_skip_all_azure_binding_inspection() -> None:
    matching_provider = FakeMatchingProvider()
    service = MatchingService(
        (matching_provider,),
        azure_binding_inspection=AzureBindingInspection.skipped,
        clock=lambda: NOW,
        key_factory=lambda: b"k" * 32,
    )

    report = service.match_dotenv(SUBSCRIPTION_ID, StringIO("FIRST=alpha-secret\n"))

    assert report.azure_binding_inspection is AzureBindingInspection.skipped
    assert report.binding_inspections == ()
    assert report.bindings == ()
    warning = next(warning for warning in report.warnings if warning.code == "azure-binding-inspection-skipped")
    assert warning.impact is WarningImpact.confirmation
    assert warning.category is WarningCategory.credential_binding


def test_skipped_azure_binding_inspection_rejects_registered_binding_providers() -> None:
    matching_provider = FakeMatchingProvider()
    binding_provider = FakeBindingProvider(matching_provider.first.resource_id)

    with pytest.raises(ValueError, match="cannot register"):
        MatchingService(
            (matching_provider,),
            binding_providers=(binding_provider,),
            azure_binding_inspection=AzureBindingInspection.skipped,
        )


def _inventory(provider: FakeMatchingProvider) -> Inventory:
    return Inventory(
        subscription_id=SUBSCRIPTION_ID,
        subscription_name="Example Production",
        generated_at=NOW,
        providers=(provider.info,),
        resources=(provider.first, provider.second),
        warnings=(
            DiscoveryWarning(
                code="provider-coverage-limited",
                message="Coverage is limited.",
                impact=WarningImpact.advisory,
                category=WarningCategory.coverage,
            ),
            DiscoveryWarning(
                code="fake-key-permissions-not-tested",
                message="not filtered",
                impact=WarningImpact.advisory,
                category=WarningCategory.contract,
            ),
            DiscoveryWarning(
                code="arbitrary-generic-binding-gap",
                message="Generic binding coverage.",
                impact=WarningImpact.confirmation,
                category=WarningCategory.credential_binding,
                provider="fake-provider",
            ),
            DiscoveryWarning(
                code="looks-like-bindings-not-inspected",
                message="A code suffix alone must not control filtering.",
                impact=WarningImpact.advisory,
                category=WarningCategory.contract,
                provider="unselected-provider",
            ),
        ),
    )


def test_direct_selection_inspects_only_selected_resources_and_attributes_bindings() -> None:
    matching_provider = FakeMatchingProvider()
    binding_provider = FakeBindingProvider(matching_provider.first.resource_id)
    service = MatchingService(
        (matching_provider,),
        binding_providers=(binding_provider,),
        clock=lambda: NOW,
        key_factory=lambda: b"k" * 32,
    )

    report = service.inspect_selection(
        SUBSCRIPTION_ID,
        _inventory(matching_provider),
        (KeySlotSelection(resource_id=matching_provider.first.resource_id, key_slot="key1"),),
    )

    assert matching_provider.discovery_calls == []
    assert matching_provider.inspection_targets == [(matching_provider.first.resource_id,)]
    assert report.subscription_name == "Example Production"
    assert report.selected_slots == (
        KeySlotSelection(resource_id=matching_provider.first.resource_id, key_slot="key1"),
    )
    assert [resource.resource_id for resource in report.resources] == [matching_provider.first.resource_id]
    assert report.inspections[0].key_slots == ("key1", "key2")
    assert binding_provider.calls == [(SUBSCRIPTION_ID, frozenset({matching_provider.first.resource_id}))]
    assert report.bindings[0].key_slot == "key1"
    warning_codes = {warning.code for warning in report.warnings}
    assert "arbitrary-generic-binding-gap" not in warning_codes
    assert "looks-like-bindings-not-inspected" in warning_codes
    serialized = report.model_dump_json()
    for raw_value in ("alpha-secret", "unmatched-secret"):
        assert raw_value not in serialized


def test_direct_selection_rejects_duplicate_or_unknown_identities_before_key_retrieval() -> None:
    provider = FakeMatchingProvider()
    service = MatchingService((provider,), key_factory=lambda: b"k" * 32)
    selection = KeySlotSelection(resource_id=provider.first.resource_id, key_slot="key1")

    with pytest.raises(MatchingError, match="more than once"):
        service.inspect_selection(SUBSCRIPTION_ID, _inventory(provider), (selection, selection))
    with pytest.raises(MatchingError, match="no longer available"):
        service.inspect_selection(
            SUBSCRIPTION_ID,
            _inventory(provider),
            (KeySlotSelection(resource_id="/unknown", key_slot="key1"),),
        )

    assert provider.inspection_calls == []


class PartialSelectionProvider(FakeMatchingProvider):
    def inspect_candidates(
        self,
        subscription_id: str,
        resources: Sequence[DiscoveredResource],
        consume: CandidateSink,
    ) -> ProviderCandidateResult:
        del subscription_id
        consume(resources[0].resource_id, "key1", "must-never-appear")
        return ProviderCandidateResult(
            inspections=(
                CandidateInspection(
                    resource_id=resources[0].resource_id,
                    status=CandidateInspectionStatus.compared,
                    key_slots=("key1",),
                ),
            )
        )


def test_direct_selection_reports_partial_key_state_without_exposing_values() -> None:
    provider = PartialSelectionProvider()
    service = MatchingService((provider,), key_factory=lambda: b"k" * 32)

    report = service.inspect_selection(
        SUBSCRIPTION_ID,
        _inventory(provider),
        (KeySlotSelection(resource_id=provider.first.resource_id, key_slot="key1"),),
    )

    assert report.inspections[0].key_slots == ("key1",)
    assert "must-never-appear" not in report.model_dump_json()


class InvalidBindingProvider(FakeBindingProvider):
    def __init__(self, key_resource_id: str, unselected_resource_id: str) -> None:
        super().__init__(key_resource_id)
        self.unselected_resource_id = unselected_resource_id

    def inspect_bindings(
        self,
        subscription_id: str,
        resources: Sequence[DiscoveredResource],
        selected_resource_ids: frozenset[str],
        identify: CandidateIdentifier,
    ) -> ProviderBindingResult:
        del subscription_id, resources, selected_resource_ids
        identify(self.unselected_resource_id, "beta-secret")
        raise AssertionError("the identifier must reject an unselected resource")


def test_matching_rejects_binding_provider_access_to_unselected_resource_without_values() -> None:
    matching_provider = FakeMatchingProvider()
    binding_provider = InvalidBindingProvider(
        matching_provider.first.resource_id,
        matching_provider.second.resource_id,
    )
    service = MatchingService(
        (matching_provider,),
        binding_providers=(binding_provider,),
        key_factory=lambda: b"k" * 32,
    )

    with pytest.raises(MatchingError) as raised:
        service.match_dotenv(SUBSCRIPTION_ID, StringIO("FIRST=alpha-secret\n"))

    assert "alpha-secret" not in str(raised.value)
    assert "beta-secret" not in str(raised.value)


class WrongLocationBindingProvider(FakeBindingProvider):
    def inspect_bindings(
        self,
        subscription_id: str,
        resources: Sequence[DiscoveredResource],
        selected_resource_ids: frozenset[str],
        identify: CandidateIdentifier,
    ) -> ProviderBindingResult:
        result = super().inspect_bindings(
            subscription_id,
            resources,
            selected_resource_ids,
            identify,
        )
        return result.model_copy(
            update={
                "inspections": tuple(
                    inspection.model_copy(update={"location": BindingLocation.local})
                    for inspection in result.inspections
                ),
                "bindings": tuple(
                    binding.model_copy(update={"location": BindingLocation.local}) for binding in result.bindings
                ),
            }
        )


def test_matching_rejects_binding_metadata_outside_the_provider_location() -> None:
    matching_provider = FakeMatchingProvider()
    binding_provider = WrongLocationBindingProvider(matching_provider.first.resource_id)
    service = MatchingService(
        (matching_provider,),
        binding_providers=(binding_provider,),
        key_factory=lambda: b"k" * 32,
    )

    with pytest.raises(MatchingError, match="location"):
        service.match_dotenv(SUBSCRIPTION_ID, StringIO("FIRST=alpha-secret\n"))


class FailingBindingProvider(FakeBindingProvider):
    def inspect_bindings(
        self,
        subscription_id: str,
        resources: Sequence[DiscoveredResource],
        selected_resource_ids: frozenset[str],
        identify: CandidateIdentifier,
    ) -> ProviderBindingResult:
        del subscription_id, resources, selected_resource_ids, identify
        raise RuntimeError("binding inspection stopped")


def test_matching_erases_owned_fingerprints_when_binding_inspection_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    matching_provider = FakeMatchingProvider()
    binding_provider = FailingBindingProvider(matching_provider.first.resource_id)
    erased: list[bytearray] = []
    original_erase = matching_module.erase_fingerprint

    def track_erase(value: bytearray) -> None:
        erased.append(value)
        original_erase(value)

    monkeypatch.setattr(matching_module, "erase_fingerprint", track_erase)
    service = MatchingService(
        (matching_provider,),
        binding_providers=(binding_provider,),
        key_factory=lambda: b"k" * 32,
    )

    with pytest.raises(RuntimeError, match="binding inspection stopped"):
        service.match_dotenv(SUBSCRIPTION_ID, StringIO("FIRST=alpha-secret\n"))

    assert len(erased) >= 4
    assert all(not any(value) for value in erased)

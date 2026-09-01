"""Shared fake providers and plan builders for execution tests."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID

from azurator.execution import ExecutionService
from azurator.fingerprints import derive_key_state_fingerprint
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
    KeyMatch,
    KeySlot,
    MatchReport,
    MatchResource,
    PlanStepAction,
    ProviderBindingResult,
    ProviderInfo,
    RotationPlan,
)
from azurator.operation import OperationSlotFingerprint
from azurator.planning import PlanningService
from azurator.providers.base import (
    BINDING_VERIFICATION_MISMATCH_CODE,
    CandidateIdentifier,
    KeyStateSink,
    ProviderOperationError,
    SecretSink,
)
from azurator.providers.dotenv_file import attach_dotenv_file_bindings
from azurator.providers.sops_dotenv_file import attach_sops_dotenv_file_bindings
from tests.sops_test_support import write_fake_sops_file

SUBSCRIPTION_ID = "11111111-1111-1111-1111-111111111111"
TENANT_ID = "22222222-2222-2222-2222-222222222222"
RESOURCE_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/accountone"
)
COGNITIVE_RESOURCE_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/openai-one"
)
PROJECT_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
    "Microsoft.CognitiveServices/accounts/foundryone/projects/projectone"
)
BINDING_ID = f"{PROJECT_ID}/connections/storage-connection"
SECOND_BINDING_ID = f"{PROJECT_ID}/connections/storage-connection-secondary"
NOW = datetime(2000, 1, 1, 12, 0, tzinfo=timezone.utc)
KEY_STATE_SALT = "00" * 32
OPERATION_ID = UUID("55555555-5555-4555-8555-555555555555")
COGNITIVE_OPERATION_ID = UUID("88888888-8888-4888-8888-888888888888")
_TWO_SLOT_DOTENV = (
    "PRIMARY_KEY=old-storage-secret\n"
    "PRIMARY_ALIAS=old-storage-secret\n"
    "SECONDARY_KEY=bridge-storage-secret\n"
    "SECONDARY_ALIAS=bridge-storage-secret\n"
    "UNRELATED=leave-me\n"
)


class FakeRotationProvider:
    def __init__(self) -> None:
        self.info = ProviderInfo(
            name="azure-storage",
            contract_version="1",
            resource_types=("Microsoft.Storage/storageAccounts",),
        )
        self.values = {"key1": "old-storage-secret", "key2": "bridge-storage-secret"}
        self.calls: list[tuple[str, str]] = []
        self.regeneration_count = 0
        self.fail_next_state_read_after_regeneration = False
        self.regeneration_errors: list[ProviderOperationError] = []
        self.error_after_regeneration: ProviderOperationError | None = None
        self.change_sibling_on_regeneration = False
        self.before_regeneration: Callable[[], None] | None = None

    def use_key_slot(
        self,
        subscription_id: str,
        resource: DiscoveredResource,
        key_slot: str,
        consume: SecretSink,
    ) -> None:
        assert subscription_id == SUBSCRIPTION_ID
        assert resource.resource_id == RESOURCE_ID
        self.calls.append(("use", key_slot))
        consume(self.values[key_slot])

    def use_key_state(
        self,
        subscription_id: str,
        resource: DiscoveredResource,
        consume: KeyStateSink,
    ) -> None:
        assert subscription_id == SUBSCRIPTION_ID
        assert resource.resource_id == RESOURCE_ID
        self.calls.append(("state", resource.name))
        if self.regeneration_count and self.fail_next_state_read_after_regeneration:
            self.fail_next_state_read_after_regeneration = False
            raise ProviderOperationError("fake-key-state-read-failed", "The fake key-state read failed safely.")
        for slot, value in self.values.items():
            consume(slot, value)

    def regenerate_key(
        self,
        subscription_id: str,
        resource: DiscoveredResource,
        key_slot: str,
    ) -> None:
        assert subscription_id == SUBSCRIPTION_ID
        assert resource.resource_id == RESOURCE_ID
        self.calls.append(("regenerate", key_slot))
        if self.before_regeneration is not None:
            self.before_regeneration()
        if self.regeneration_errors:
            raise self.regeneration_errors.pop(0)
        self.regeneration_count += 1
        self.values[key_slot] = f"new-storage-secret-{self.regeneration_count}"
        if self.change_sibling_on_regeneration:
            sibling = next(slot for slot in self.values if slot != key_slot)
            self.values[sibling] = "unexpected-sibling-secret"
        if self.error_after_regeneration is not None:
            raise self.error_after_regeneration


class FakeBindingProvider:
    def __init__(self) -> None:
        self.info = ProviderInfo(
            name="azure-foundry-connections",
            contract_version="1",
            resource_types=("Microsoft.CognitiveServices/accounts/projects/connections",),
        )
        self.stored = {
            BINDING_ID: "old-storage-secret",
            SECOND_BINDING_ID: "bridge-storage-secret",
        }
        self.calls: list[tuple[str, str]] = []
        self.fail_verification_once = False
        self.fail_update_before_apply_once = False
        self.fail_update_after_apply_once = False
        self.fail_update_before_apply_on_call: int | None = None
        self.fail_update_after_apply_on_call: int | None = None
        self.update_attempts = 0

    @property
    def location(self) -> BindingLocation:
        return BindingLocation.azure

    @property
    def key_resource_types(self) -> tuple[str, ...]:
        return ("Microsoft.Storage/storageAccounts",)

    def inspect_bindings(
        self,
        subscription_id: str,
        resources: Sequence[DiscoveredResource],
        selected_resource_ids: frozenset[str],
        identify: CandidateIdentifier,
    ) -> ProviderBindingResult:
        del subscription_id, resources, selected_resource_ids, identify
        return ProviderBindingResult()

    def update_binding(
        self,
        subscription_id: str,
        binding: CredentialBinding,
        resource: DiscoveredResource,
        expected_key: str,
        replacement_key: str,
    ) -> None:
        assert subscription_id == SUBSCRIPTION_ID
        assert resource.resource_id == RESOURCE_ID
        self.calls.append(("update", binding.binding_id))
        self.update_attempts += 1
        if self.fail_update_before_apply_once or self.update_attempts == self.fail_update_before_apply_on_call:
            self.fail_update_before_apply_once = False
            raise ProviderOperationError(
                "fake-binding-update-failed",
                "The fake binding update failed safely before applying.",
            )
        current = self.stored[binding.binding_id]
        if current == replacement_key:
            return
        if current != expected_key:
            raise ProviderOperationError(
                "fake-binding-drift-detected",
                "The fake binding changed after planning.",
            )
        self.stored[binding.binding_id] = replacement_key
        if self.fail_update_after_apply_once or self.update_attempts == self.fail_update_after_apply_on_call:
            self.fail_update_after_apply_once = False
            raise ProviderOperationError(
                "fake-binding-update-failed",
                "The fake binding update response was lost safely.",
            )

    def verify_binding(
        self,
        subscription_id: str,
        binding: CredentialBinding,
        resource: DiscoveredResource,
        expected_key: str,
    ) -> None:
        assert subscription_id == SUBSCRIPTION_ID
        assert resource.resource_id == RESOURCE_ID
        self.calls.append(("verify", binding.binding_id))
        if self.fail_verification_once:
            self.fail_verification_once = False
            raise ProviderOperationError(
                "foundry-connection-verification-failed",
                "The fake verification failed safely.",
            )
        if self.stored[binding.binding_id] != expected_key:
            raise ProviderOperationError(
                BINDING_VERIFICATION_MISMATCH_CODE,
                "The fake connection did not retain the expected key.",
            )


class FakeCognitiveProvider:
    def __init__(self) -> None:
        self.info = ProviderInfo(
            name="azure-cognitive-services",
            contract_version="1",
            resource_types=("Microsoft.CognitiveServices/accounts",),
        )
        self.values = {"Key1": "old-ai-secret", "Key2": "bridge-ai-secret"}
        self.regeneration_count = 0

    def use_key_slot(
        self,
        subscription_id: str,
        resource: DiscoveredResource,
        key_slot: str,
        consume: SecretSink,
    ) -> None:
        assert subscription_id == SUBSCRIPTION_ID
        assert resource.endpoint == "https://openai-one.openai.azure.com/"
        consume(self.values[key_slot])

    def use_key_state(
        self,
        subscription_id: str,
        resource: DiscoveredResource,
        consume: KeyStateSink,
    ) -> None:
        assert subscription_id == SUBSCRIPTION_ID
        assert resource.endpoint == "https://openai-one.openai.azure.com/"
        for slot, value in self.values.items():
            consume(slot, value)

    def regenerate_key(
        self,
        subscription_id: str,
        resource: DiscoveredResource,
        key_slot: str,
    ) -> None:
        assert subscription_id == SUBSCRIPTION_ID
        assert resource.endpoint == "https://openai-one.openai.azure.com/"
        self.regeneration_count += 1
        self.values[key_slot] = "new-ai-secret"


def _report() -> MatchReport:
    resource = MatchResource(
        resource_id=RESOURCE_ID,
        name="accountone",
        resource_type="Microsoft.Storage/storageAccounts",
        location="westeurope",
        kind="StorageV2",
        provider="azure-storage",
        key_slots=(
            KeySlot(name="key1", values_retrievable=True, rotatable=True),
            KeySlot(name="key2", values_retrievable=True, rotatable=True),
        ),
    )
    binding = CredentialBinding(
        binding_id=BINDING_ID,
        name="storage-connection",
        binding_type="Microsoft.CognitiveServices/accounts/projects/connections",
        provider="azure-foundry-connections",
        location=BindingLocation.azure,
        scope_id=PROJECT_ID,
        scope_name="projectone",
        key_resource_id=RESOURCE_ID,
        key_slot="key1",
        target="https://accountone.blob.core.windows.net/",
        selectors=(),
        management=BindingManagement.update_and_verify,
    )
    return MatchReport(
        subscription_id=SUBSCRIPTION_ID,
        subscription_name="Example Production",
        generated_at=NOW,
        azure_binding_inspection=AzureBindingInspection.enabled,
        providers=(
            ProviderInfo(
                name="azure-foundry-connections",
                contract_version="1",
                resource_types=("Microsoft.CognitiveServices/accounts/projects/connections",),
            ),
            ProviderInfo(
                name="azure-storage",
                contract_version="1",
                resource_types=("Microsoft.Storage/storageAccounts",),
            ),
        ),
        input_selectors=("STORAGE_KEY",),
        resources=(resource,),
        inspections=(
            CandidateInspection(
                resource_id=RESOURCE_ID,
                status=CandidateInspectionStatus.compared,
                key_slots=("key1", "key2"),
            ),
        ),
        candidate_slots_compared=2,
        matches=(KeyMatch(input_selector="STORAGE_KEY", resource_id=RESOURCE_ID, key_slot="key1"),),
        binding_inspections=(
            BindingInspection(
                resource_id=RESOURCE_ID,
                provider="azure-foundry-connections",
                location=BindingLocation.azure,
                status=BindingInspectionStatus.inspected,
                scopes_inspected=1,
            ),
        ),
        bindings=(binding,),
        warnings=(),
    )


def make_plans():
    first = PlanningService(clock=lambda: NOW).create(_report(), TENANT_ID)
    fresh = PlanningService(clock=lambda: NOW + timedelta(minutes=1)).create(_report(), TENANT_ID)
    return first, fresh


def _two_slot_report() -> MatchReport:
    base = _report()
    primary_binding = base.bindings[0]
    secondary_binding = primary_binding.model_copy(
        update={
            "binding_id": SECOND_BINDING_ID,
            "name": "storage-connection-secondary",
            "key_slot": "key2",
        }
    )
    return base.model_copy(
        update={
            "input_selectors": ("PRIMARY_KEY", "SECONDARY_KEY"),
            "matches": (
                KeyMatch(input_selector="PRIMARY_KEY", resource_id=RESOURCE_ID, key_slot="key1"),
                KeyMatch(input_selector="SECONDARY_KEY", resource_id=RESOURCE_ID, key_slot="key2"),
            ),
            "bindings": (primary_binding, secondary_binding),
        }
    )


def make_two_slot_binding_plans() -> tuple[RotationPlan, RotationPlan]:
    report = _two_slot_report()
    first = PlanningService(clock=lambda: NOW).create(report, TENANT_ID)
    fresh = PlanningService(clock=lambda: NOW + timedelta(minutes=1)).create(report, TENANT_ID)
    return first, fresh


def _two_slot_local_report() -> MatchReport:
    return _two_slot_report().model_copy(
        update={
            "providers": (_report().providers[1],),
            "input_selectors": (
                "PRIMARY_KEY",
                "PRIMARY_ALIAS",
                "SECONDARY_KEY",
                "SECONDARY_ALIAS",
                "UNRELATED",
            ),
            "matches": (
                KeyMatch(input_selector="PRIMARY_KEY", resource_id=RESOURCE_ID, key_slot="key1"),
                KeyMatch(input_selector="PRIMARY_ALIAS", resource_id=RESOURCE_ID, key_slot="key1"),
                KeyMatch(input_selector="SECONDARY_KEY", resource_id=RESOURCE_ID, key_slot="key2"),
                KeyMatch(input_selector="SECONDARY_ALIAS", resource_id=RESOURCE_ID, key_slot="key2"),
            ),
            "binding_inspections": (),
            "bindings": (),
            "warnings": (),
        }
    )


def make_service(rotation: FakeRotationProvider, binding: FakeBindingProvider) -> ExecutionService:
    return ExecutionService(
        (rotation,),
        (binding,),
        clock=lambda: NOW,
        key_state_salt_factory=lambda: KEY_STATE_SALT,
    )


def make_dotenv_file_plans(tmp_path: Path) -> tuple[Path, RotationPlan, RotationPlan]:
    source = tmp_path / "secrets.env"
    source.write_text("STORAGE_KEY=old-storage-secret\nUNRELATED=leave-me\n", encoding="utf-8")
    source.chmod(0o600)
    base = _report().model_copy(
        update={
            "providers": (_report().providers[1],),
            "binding_inspections": (),
            "bindings": (),
            "warnings": (),
        }
    )
    report = attach_dotenv_file_bindings(base, source)
    plan = PlanningService(clock=lambda: NOW).create_dotenv_file(report, TENANT_ID, str(source))
    fresh = PlanningService(clock=lambda: NOW + timedelta(minutes=1)).create_dotenv_file(
        report,
        TENANT_ID,
        str(source),
    )
    return source, plan, fresh


def make_two_slot_dotenv_file_plans(tmp_path: Path) -> tuple[Path, RotationPlan, RotationPlan]:
    source = tmp_path / "two-slots.env"
    source.write_text(_TWO_SLOT_DOTENV, encoding="utf-8")
    source.chmod(0o600)
    report = attach_dotenv_file_bindings(_two_slot_local_report(), source)
    plan = PlanningService(clock=lambda: NOW).create_dotenv_file(report, TENANT_ID, str(source))
    fresh = PlanningService(clock=lambda: NOW + timedelta(minutes=1)).create_dotenv_file(
        report,
        TENANT_ID,
        str(source),
    )
    return source, plan, fresh


def make_sops_dotenv_file_plans(tmp_path: Path) -> tuple[Path, RotationPlan, RotationPlan]:
    source = tmp_path / "secrets.enc.env"
    write_fake_sops_file(source, "STORAGE_KEY=old-storage-secret\nUNRELATED=leave-me\n")
    base = _report().model_copy(
        update={
            "providers": (_report().providers[1],),
            "binding_inspections": (),
            "bindings": (),
            "warnings": (),
        }
    )
    report = attach_sops_dotenv_file_bindings(base, source)
    plan = PlanningService(clock=lambda: NOW).create_sops_dotenv_file(report, TENANT_ID, str(source))
    fresh = PlanningService(clock=lambda: NOW + timedelta(minutes=1)).create_sops_dotenv_file(
        report,
        TENANT_ID,
        str(source),
    )
    return source, plan, fresh


def make_two_slot_sops_dotenv_file_plans(tmp_path: Path) -> tuple[Path, RotationPlan, RotationPlan]:
    source = tmp_path / "two-slots.enc.env"
    write_fake_sops_file(source, _TWO_SLOT_DOTENV)
    report = attach_sops_dotenv_file_bindings(_two_slot_local_report(), source)
    plan = PlanningService(clock=lambda: NOW).create_sops_dotenv_file(report, TENANT_ID, str(source))
    fresh = PlanningService(clock=lambda: NOW + timedelta(minutes=1)).create_sops_dotenv_file(
        report,
        TENANT_ID,
        str(source),
    )
    return source, plan, fresh


def make_cognitive_plans():
    resource = MatchResource(
        resource_id=COGNITIVE_RESOURCE_ID,
        name="openai-one",
        resource_type="Microsoft.CognitiveServices/accounts",
        location="westeurope",
        kind="OpenAI",
        endpoint="https://openai-one.openai.azure.com/",
        provider="azure-cognitive-services",
        key_slots=(
            KeySlot(name="Key1", values_retrievable=True, rotatable=True),
            KeySlot(name="Key2", values_retrievable=True, rotatable=True),
        ),
    )
    report = MatchReport(
        subscription_id=SUBSCRIPTION_ID,
        subscription_name="Example Production",
        generated_at=NOW,
        azure_binding_inspection=AzureBindingInspection.enabled,
        providers=(
            ProviderInfo(
                name="azure-cognitive-services",
                contract_version="1",
                resource_types=("Microsoft.CognitiveServices/accounts",),
            ),
        ),
        input_selectors=("AI_KEY",),
        resources=(resource,),
        inspections=(
            CandidateInspection(
                resource_id=COGNITIVE_RESOURCE_ID,
                status=CandidateInspectionStatus.compared,
                key_slots=("Key1", "Key2"),
            ),
        ),
        candidate_slots_compared=2,
        matches=(KeyMatch(input_selector="AI_KEY", resource_id=COGNITIVE_RESOURCE_ID, key_slot="Key1"),),
        warnings=(),
    )
    first = PlanningService(clock=lambda: NOW).create(report, TENANT_ID)
    fresh = PlanningService(clock=lambda: NOW + timedelta(minutes=1)).create(report, TENANT_ID)
    return first, fresh


def make_cognitive_service(provider: FakeCognitiveProvider) -> ExecutionService:
    return ExecutionService(
        (provider,),
        (),
        clock=lambda: NOW,
        key_state_salt_factory=lambda: KEY_STATE_SALT,
    )


def make_slot_fingerprints(
    plan: RotationPlan,
    values: dict[str, str],
) -> tuple[OperationSlotFingerprint, ...]:
    resource_ids = {step.resource_id for step in plan.steps if step.action is PlanStepAction.regenerate_key}
    return tuple(
        OperationSlotFingerprint(
            resource_id=resource.resource_id,
            key_slot=slot.name,
            fingerprint=derive_key_state_fingerprint(
                values[slot.name],
                salt=KEY_STATE_SALT,
                resource_id=resource.resource_id,
                key_slot=slot.name,
            ),
        )
        for resource in plan.resources
        if resource.resource_id in resource_ids
        for slot in resource.key_slots
    )


def replace_step(plan: RotationPlan, index: int, **updates: object) -> RotationPlan:
    steps = list(plan.steps)
    steps[index] = steps[index].model_copy(update=updates)
    return plan.model_copy(update={"steps": tuple(steps)})

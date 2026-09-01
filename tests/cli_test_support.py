"""Shared fakes and builders for command-boundary tests."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

import pytest
from typer.testing import CliRunner

import azurator.cli as cli_module
from azurator.auth import SubscriptionSelection
from azurator.cli import app
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
    KeyMatch,
    KeySlot,
    KeySlotSelection,
    MatchReport,
    MatchResource,
    PlanSource,
    PlanStep,
    PlanStepAction,
    ProviderInfo,
    RotationPlan,
    SelectionReport,
    WarningCategory,
    WarningImpact,
)
from azurator.operation import (
    OperationSlotFingerprint,
    OperationState,
    OperationStatus,
    OperationStore,
    PendingOperationStep,
    operation_intent_digest,
)

SUBSCRIPTION_ID = "11111111-1111-1111-1111-111111111111"
SUBSCRIPTION_NAME = "Example Production"
CLI_OPERATION_ID = UUID("55555555-5555-4555-8555-555555555555")


def _azure_bindings_skipped_warning() -> DiscoveryWarning:
    return DiscoveryWarning(
        code="azure-binding-inspection-skipped",
        message="Automatic Azure credential-binding inspection was explicitly skipped.",
        impact=WarningImpact.confirmation,
        category=WarningCategory.credential_binding,
    )


def make_inventory(subscription_id: str = SUBSCRIPTION_ID) -> Inventory:
    return Inventory(
        subscription_id=subscription_id,
        generated_at=datetime(2000, 1, 1, 12, 0, tzinfo=timezone.utc),
        providers=(
            ProviderInfo(
                name="azure-storage",
                contract_version="1",
                resource_types=("Microsoft.Storage/storageAccounts",),
            ),
        ),
        resources=(
            DiscoveredResource(
                resource_id=f"/subscriptions/{subscription_id}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/a",
                name="account-a",
                resource_type="Microsoft.Storage/storageAccounts",
                location="westeurope",
                kind="StorageV2",
                provider="azure-storage",
                key_authentication=KeyAuthentication.enabled,
                key_slots=(
                    KeySlot(name="key1", values_retrievable=True, rotatable=True),
                    KeySlot(name="key2", values_retrievable=True, rotatable=True),
                ),
            ),
        ),
        warnings=(
            DiscoveryWarning(
                code="provider-coverage-limited",
                message="Coverage is limited.",
                impact=WarningImpact.advisory,
                category=WarningCategory.coverage,
            ),
        ),
    )


def make_ai_inventory(subscription_id: str = SUBSCRIPTION_ID) -> Inventory:
    resource_id = (
        f"/subscriptions/{subscription_id}/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/openai-a"
    )
    return Inventory(
        subscription_id=subscription_id,
        generated_at=datetime(2000, 1, 1, 12, 0, tzinfo=timezone.utc),
        providers=(
            ProviderInfo(
                name="azure-cognitive-services",
                contract_version="1",
                resource_types=("Microsoft.CognitiveServices/accounts",),
            ),
            ProviderInfo(
                name="azure-foundry-connections",
                contract_version="1",
                resource_types=("Microsoft.CognitiveServices/accounts/projects/connections",),
            ),
        ),
        resources=(
            DiscoveredResource(
                resource_id=resource_id,
                name="openai-a",
                resource_type="Microsoft.CognitiveServices/accounts",
                location="westeurope",
                kind="OpenAI",
                endpoint="https://openai-a.openai.azure.com/",
                provider="azure-cognitive-services",
                key_authentication=KeyAuthentication.enabled,
                key_slots=(
                    KeySlot(name="Key1", values_retrievable=True, rotatable=True),
                    KeySlot(name="Key2", values_retrievable=True, rotatable=True),
                ),
            ),
        ),
        warnings=(
            DiscoveryWarning(
                code="provider-coverage-limited",
                message="Coverage is limited.",
                impact=WarningImpact.advisory,
                category=WarningCategory.coverage,
            ),
            DiscoveryWarning(
                code="foundry-binding-coverage-limited",
                message="Coverage must be rendered from the selected resource types.",
                impact=WarningImpact.confirmation,
                category=WarningCategory.credential_binding,
                provider="azure-foundry-connections",
            ),
        ),
    )


def make_match_report(subscription_id: str = SUBSCRIPTION_ID) -> MatchReport:
    storage_id = (
        f"/subscriptions/{subscription_id}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/account-a"
    )
    openai_id = (
        f"/subscriptions/{subscription_id}/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/openai-a"
    )
    return MatchReport(
        subscription_id=subscription_id,
        generated_at=datetime(2000, 1, 1, 12, 0, tzinfo=timezone.utc),
        azure_binding_inspection=AzureBindingInspection.enabled,
        providers=(
            ProviderInfo(
                name="azure-storage",
                contract_version="1",
                resource_types=("Microsoft.Storage/storageAccounts",),
            ),
            ProviderInfo(
                name="azure-cognitive-services",
                contract_version="1",
                resource_types=("Microsoft.CognitiveServices/accounts",),
            ),
            ProviderInfo(
                name="azure-foundry-connections",
                contract_version="1",
                resource_types=("Microsoft.CognitiveServices/accounts/projects/connections",),
            ),
        ),
        input_selectors=("STORAGE_KEY", "SECOND_STORAGE_KEY", "UNMATCHED"),
        skipped_empty_selectors=("EMPTY",),
        resources=(
            MatchResource(
                resource_id=storage_id,
                name="account-a",
                resource_type="Microsoft.Storage/storageAccounts",
                location="westeurope",
                kind="StorageV2",
                provider="azure-storage",
                key_slots=(
                    KeySlot(name="key1", values_retrievable=True, rotatable=True),
                    KeySlot(name="key2", values_retrievable=True, rotatable=True),
                ),
            ),
            MatchResource(
                resource_id=openai_id,
                name="openai-a",
                resource_type="Microsoft.CognitiveServices/accounts",
                location="westeurope",
                kind="OpenAI",
                provider="azure-cognitive-services",
                key_slots=(
                    KeySlot(name="Key1", values_retrievable=True, rotatable=False),
                    KeySlot(name="Key2", values_retrievable=True, rotatable=False),
                ),
            ),
        ),
        inspections=(
            CandidateInspection(
                resource_id=storage_id,
                status=CandidateInspectionStatus.compared,
                key_slots=("key1", "key2"),
            ),
            CandidateInspection(
                resource_id=openai_id,
                status=CandidateInspectionStatus.unavailable,
            ),
        ),
        candidate_slots_compared=2,
        matches=(
            KeyMatch(input_selector="STORAGE_KEY", resource_id=storage_id, key_slot="key1"),
            KeyMatch(input_selector="SECOND_STORAGE_KEY", resource_id=storage_id, key_slot="key2"),
        ),
        binding_inspections=(
            BindingInspection(
                resource_id=storage_id,
                provider="azure-foundry-connections",
                location=BindingLocation.azure,
                status=BindingInspectionStatus.inspected,
                scopes_inspected=1,
            ),
        ),
        bindings=(
            CredentialBinding(
                binding_id=(
                    f"/subscriptions/{subscription_id}/resourceGroups/rg/providers/"
                    "Microsoft.CognitiveServices/accounts/foundry-a/projects/project-a/connections/storage-a"
                ),
                name="storage-a",
                binding_type="Microsoft.CognitiveServices/accounts/projects/connections",
                provider="azure-foundry-connections",
                location=BindingLocation.azure,
                scope_id=(
                    f"/subscriptions/{subscription_id}/resourceGroups/rg/providers/"
                    "Microsoft.CognitiveServices/accounts/foundry-a/projects/project-a"
                ),
                scope_name="project-a",
                key_resource_id=storage_id,
                key_slot="key1",
                target="https://account-a.blob.core.windows.net/",
                selectors=(),
                management=BindingManagement.update_and_verify,
            ),
        ),
        warnings=(
            DiscoveryWarning(
                code="provider-coverage-limited",
                message="Coverage is limited.",
                impact=WarningImpact.advisory,
                category=WarningCategory.coverage,
            ),
            DiscoveryWarning(
                code="foundry-binding-coverage-limited",
                message="Other Storage bindings are outside coverage.",
                impact=WarningImpact.confirmation,
                category=WarningCategory.credential_binding,
                provider="azure-foundry-connections",
            ),
            DiscoveryWarning(
                code="cognitive-services-key-retrieval-forbidden",
                message="AI key inspection failed with HTTP 403.",
                impact=WarningImpact.blocking,
                category=WarningCategory.contract,
                provider="azure-cognitive-services",
                resource_id=openai_id,
            ),
        ),
    )


def patch_match_boundary(monkeypatch: pytest.MonkeyPatch) -> None:
    def resolve_subscription(value: str | None) -> SubscriptionSelection:
        assert value in {None, SUBSCRIPTION_ID}
        return SubscriptionSelection(SUBSCRIPTION_ID, SUBSCRIPTION_NAME)

    def match_fake(
        subscription_id: str,
        stream: object,
        *,
        skip_azure_bindings: bool = False,
    ) -> MatchReport:
        assert subscription_id == SUBSCRIPTION_ID
        assert stream is not None
        report = make_match_report(subscription_id)
        if not skip_azure_bindings:
            return report
        return report.model_copy(
            update={
                "azure_binding_inspection": AzureBindingInspection.skipped,
                "binding_inspections": (),
                "bindings": (),
                "warnings": (
                    *(
                        warning
                        for warning in report.warnings
                        if warning.category is not WarningCategory.credential_binding
                    ),
                    _azure_bindings_skipped_warning(),
                ),
            }
        )

    monkeypatch.setattr(cli_module, "_resolve_subscription", resolve_subscription)
    monkeypatch.setattr(cli_module, "_match_dotenv", match_fake)


def patch_plan_boundary(monkeypatch: pytest.MonkeyPatch) -> None:
    def resolve_subscription(value: str | None) -> SubscriptionSelection:
        assert value in {None, SUBSCRIPTION_ID}
        return SubscriptionSelection(SUBSCRIPTION_ID, SUBSCRIPTION_NAME, "tenant-id")

    def match_fake(
        subscription_id: str,
        stream: object,
        *,
        skip_azure_bindings: bool = False,
    ) -> MatchReport:
        assert subscription_id == SUBSCRIPTION_ID
        assert stream is not None
        report = make_match_report(subscription_id)
        selected_resource_id = report.matches[0].resource_id
        return report.model_copy(
            update={
                "resources": tuple(
                    resource for resource in report.resources if resource.resource_id == selected_resource_id
                ),
                "inspections": tuple(
                    inspection for inspection in report.inspections if inspection.resource_id == selected_resource_id
                ),
                "warnings": (
                    *(
                        warning
                        for warning in report.warnings
                        if warning.code != "cognitive-services-key-retrieval-forbidden"
                        and (not skip_azure_bindings or warning.category is not WarningCategory.credential_binding)
                    ),
                    *((_azure_bindings_skipped_warning(),) if skip_azure_bindings else ()),
                ),
                "azure_binding_inspection": (
                    AzureBindingInspection.skipped if skip_azure_bindings else AzureBindingInspection.enabled
                ),
                "binding_inspections": () if skip_azure_bindings else report.binding_inspections,
                "bindings": () if skip_azure_bindings else report.bindings,
            }
        )

    monkeypatch.setattr(cli_module, "_resolve_plan_subscription", resolve_subscription)
    monkeypatch.setattr(cli_module, "_match_dotenv", match_fake)


def patch_direct_plan_boundary(
    monkeypatch: pytest.MonkeyPatch,
    inventory_result: Inventory | None = None,
) -> list[tuple[KeySlotSelection, ...]]:
    inspected: list[tuple[KeySlotSelection, ...]] = []

    def resolve_subscription(value: str | None) -> SubscriptionSelection:
        assert value in {None, SUBSCRIPTION_ID}
        return SubscriptionSelection(SUBSCRIPTION_ID, SUBSCRIPTION_NAME, "tenant-id")

    def discover_fake(subscription_id: str) -> Inventory:
        assert subscription_id == SUBSCRIPTION_ID
        return inventory_result or make_inventory(subscription_id)

    def inspect_fake(
        subscription_id: str,
        inventory: Inventory,
        selections: tuple[KeySlotSelection, ...],
        *,
        skip_azure_bindings: bool = False,
    ) -> SelectionReport:
        assert subscription_id == SUBSCRIPTION_ID
        inspected.append(selections)
        selected_ids = {selection.resource_id for selection in selections}
        resources = tuple(
            MatchResource(
                resource_id=resource.resource_id,
                name=resource.name,
                resource_type=resource.resource_type,
                location=resource.location,
                kind=resource.kind,
                endpoint=resource.endpoint,
                provider=resource.provider,
                key_slots=resource.key_slots,
            )
            for resource in inventory.resources
            if resource.resource_id in selected_ids
        )
        return SelectionReport(
            subscription_id=subscription_id,
            subscription_name=inventory.subscription_name,
            generated_at=inventory.generated_at,
            azure_binding_inspection=(
                AzureBindingInspection.skipped if skip_azure_bindings else AzureBindingInspection.enabled
            ),
            providers=inventory.providers,
            resources=resources,
            inspections=tuple(
                CandidateInspection(
                    resource_id=resource.resource_id,
                    status=CandidateInspectionStatus.compared,
                    key_slots=tuple(slot.name for slot in resource.key_slots),
                )
                for resource in resources
            ),
            selected_slots=selections,
            warnings=(
                *(
                    warning
                    for warning in inventory.warnings
                    if not skip_azure_bindings or warning.category is not WarningCategory.credential_binding
                ),
                *((_azure_bindings_skipped_warning(),) if skip_azure_bindings else ()),
            ),
        )

    monkeypatch.setattr(cli_module, "_resolve_plan_subscription", resolve_subscription)
    monkeypatch.setattr(cli_module, "_discover_inventory", discover_fake)
    monkeypatch.setattr(cli_module, "_inspect_selection", inspect_fake)
    monkeypatch.setattr(cli_module, "_interactive_terminal_available", lambda: True)
    return inspected


class FakeExecutionService:
    def __init__(self) -> None:
        self.validated = False
        self.started = False
        self.resumed = False

    def validate_start(self, plan: RotationPlan, fresh_plan: RotationPlan) -> None:
        assert plan.subscription_id == fresh_plan.subscription_id
        self.validated = True

    def validate_plan(self, plan: RotationPlan) -> None:
        assert plan.subscription_id == SUBSCRIPTION_ID

    def validate_operation(self, store: OperationStore) -> OperationState:
        operation = store.load()
        self.validated = True
        return operation

    def validate_resume(
        self,
        store: OperationStore,
        *,
        fresh_plan: RotationPlan | None = None,
    ) -> OperationState:
        operation = store.load()
        if fresh_plan is not None:
            assert fresh_plan.subscription_id == operation.plan.subscription_id
        self.validated = True
        return operation

    def start(
        self,
        plan: RotationPlan,
        fresh_plan: RotationPlan,
        store: OperationStore,
        operation_id: UUID,
        *,
        progress: Callable[[PlanStep], None],
    ) -> OperationState:
        del fresh_plan
        self.started = True
        for step in plan.steps:
            progress(step)
        operation = make_operation_state(
            plan,
            status=OperationStatus.completed,
            operation_id=operation_id,
        )
        store.create(operation)
        return operation

    def resume(
        self,
        store: OperationStore,
        *,
        fresh_plan: RotationPlan | None = None,
        progress: Callable[[PlanStep], None],
    ) -> OperationState:
        del fresh_plan
        self.resumed = True
        current = store.load()
        for step in current.plan.steps[len(current.completed_steps) :]:
            progress(step)
        completed = make_operation_state(
            current.plan,
            status=OperationStatus.completed,
            operation_id=current.operation_id,
        )
        store.save(completed)
        return completed


def make_operation_state(
    plan: RotationPlan,
    *,
    status: OperationStatus,
    completed_steps: tuple[int, ...] | None = None,
    operation_id: UUID = CLI_OPERATION_ID,
) -> OperationState:
    completed = completed_steps if completed_steps is not None else tuple(range(1, len(plan.steps) + 1))
    resource_ids = {step.resource_id for step in plan.steps if step.action is PlanStepAction.regenerate_key}
    slot_fingerprints = tuple(
        OperationSlotFingerprint(
            resource_id=resource.resource_id,
            key_slot=slot.name,
            fingerprint=f"sha256:v1:{'1' * 64}",
        )
        for resource in plan.resources
        if resource.resource_id in resource_ids
        for slot in resource.key_slots
    )
    pending_step = None
    error_code = None
    error_message = None
    if status is OperationStatus.failed:
        step = plan.steps[len(completed)]
        pending_step = PendingOperationStep(
            sequence=step.sequence,
            action=step.action,
            resource_id=step.resource_id,
            key_slot=step.key_slot,
            binding_id=step.binding_id,
        )
        error_code = "synthetic-operation-failure"
        error_message = "Synthetic secret-free operation failure."
    return OperationState(
        operation_id=operation_id,
        plan=plan,
        intent_digest=operation_intent_digest(plan),
        started_at=datetime(2000, 1, 1, 12, 0, tzinfo=timezone.utc),
        updated_at=datetime(2000, 1, 1, 12, 1, tzinfo=timezone.utc),
        status=status,
        key_state_salt="00" * 32,
        slot_fingerprints=slot_fingerprints,
        completed_steps=completed,
        pending_step=pending_step,
        error_code=error_code,
        error_message=error_message,
    )


def write_cli_plan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, RotationPlan]:
    patch_plan_boundary(monkeypatch)
    destination = tmp_path / "plan.json"
    result = CliRunner().invoke(
        app,
        ["plan", "--stdin", "--out", str(destination)],
        input="TOKEN=plan-input-secret\n",
    )
    assert result.exit_code == 0
    return destination, RotationPlan.model_validate_json(destination.read_text(encoding="utf-8"))


def write_direct_cli_plan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, RotationPlan]:
    patch_direct_plan_boundary(monkeypatch)
    destination = tmp_path / "direct-plan.json"
    result = CliRunner().invoke(
        app,
        ["plan", "--out", str(destination)],
        input="1\n",
    )
    assert result.exit_code == 0
    plan = RotationPlan.model_validate_json(destination.read_text(encoding="utf-8"))
    assert plan.source_format is PlanSource.direct_selection
    return destination, plan


def write_dotenv_file_cli_plan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Path, Path, RotationPlan]:
    patch_plan_boundary(monkeypatch)
    source = tmp_path / "secrets.env"
    source.write_text(
        "STORAGE_KEY=plan-input-secret\nSECOND_STORAGE_KEY=second-plan-secret\n",
        encoding="utf-8",
    )
    source.chmod(0o600)
    destination = tmp_path / "dotenv-file-plan.json"
    result = CliRunner().invoke(
        app,
        ["plan", "--env-file", str(source), "--out", str(destination)],
    )
    assert result.exit_code == 0
    plan = RotationPlan.model_validate_json(destination.read_text(encoding="utf-8"))
    assert plan.source_format is PlanSource.dotenv_file
    return destination, source, plan


def patch_automatic_operation_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    operation_path = tmp_path / str(CLI_OPERATION_ID) / "operation.json"

    def automatic_path(operation_id: UUID) -> Path:
        assert operation_id == CLI_OPERATION_ID
        return operation_path

    monkeypatch.setattr(cli_module, "uuid4", lambda: CLI_OPERATION_ID)
    monkeypatch.setattr(cli_module, "_automatic_operation_path", automatic_path)
    monkeypatch.setattr(cli_module, "_prepare_operation_root", lambda: None)
    return operation_path

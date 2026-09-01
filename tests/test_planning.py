"""Tests for generated, secret-free rotation plans."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from azurator.models import (
    AzureBindingInspection,
    BindingInspection,
    BindingInspectionStatus,
    BindingLocation,
    BindingManagement,
    CandidateInspection,
    CandidateInspectionStatus,
    CredentialBinding,
    DiscoveryWarning,
    KeyMatch,
    KeySlot,
    KeySlotSelection,
    MatchReport,
    MatchResource,
    PlanSource,
    PlanState,
    PlanStepAction,
    ProviderInfo,
    SelectionReport,
    WarningCategory,
    WarningImpact,
)
from azurator.planning import PlanningError, PlanningService

SUBSCRIPTION_ID = "11111111-1111-1111-1111-111111111111"
TENANT_ID = "22222222-2222-2222-2222-222222222222"
RESOURCE_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/account-a"
)
NOW = datetime(2000, 1, 1, 12, 0, tzinfo=timezone.utc)


def _resource(*, key1_rotatable: bool = True) -> MatchResource:
    return MatchResource(
        resource_id=RESOURCE_ID,
        name="account-a",
        resource_type="Microsoft.Storage/storageAccounts",
        location="westeurope",
        kind="StorageV2",
        provider="azure-storage",
        key_slots=(
            KeySlot(name="key1", values_retrievable=True, rotatable=key1_rotatable),
            KeySlot(name="key2", values_retrievable=True, rotatable=True),
        ),
    )


def _binding(name: str, slot: str | None, management: BindingManagement) -> CredentialBinding:
    return CredentialBinding(
        binding_id=f"/foundry/projects/project-a/connections/{name}",
        name=name,
        binding_type="Microsoft.CognitiveServices/accounts/projects/connections",
        provider="azure-foundry-connections",
        location=BindingLocation.azure,
        scope_id="/foundry/projects/project-a",
        scope_name="project-a",
        key_resource_id=RESOURCE_ID,
        key_slot=slot,
        target="https://account-a.blob.core.windows.net/",
        selectors=(),
        management=management,
    )


def _report(
    matches: tuple[KeyMatch, ...],
    *,
    resource: MatchResource | None = None,
    bindings: tuple[CredentialBinding, ...] = (),
    binding_status: BindingInspectionStatus = BindingInspectionStatus.inspected,
    warnings: tuple[DiscoveryWarning, ...] = (),
) -> MatchReport:
    selectors = tuple(dict.fromkeys(match.input_selector for match in matches)) or ("UNMATCHED",)
    binding_inspections = (
        (
            BindingInspection(
                resource_id=RESOURCE_ID,
                provider="azure-foundry-connections",
                location=BindingLocation.azure,
                status=binding_status,
                scopes_inspected=1 if binding_status is not BindingInspectionStatus.unavailable else 0,
            ),
        )
        if bindings or binding_status is not BindingInspectionStatus.inspected
        else ()
    )
    return MatchReport(
        subscription_id=SUBSCRIPTION_ID,
        subscription_name="Example Production",
        generated_at=NOW,
        azure_binding_inspection=AzureBindingInspection.enabled,
        providers=(
            ProviderInfo(
                name="azure-storage",
                contract_version="1",
                resource_types=("Microsoft.Storage/storageAccounts",),
            ),
            ProviderInfo(
                name="azure-foundry-connections",
                contract_version="1",
                resource_types=("Microsoft.CognitiveServices/accounts/projects/connections",),
            ),
        ),
        input_selectors=selectors,
        resources=(resource or _resource(),),
        inspections=(
            CandidateInspection(
                resource_id=RESOURCE_ID,
                status=CandidateInspectionStatus.compared,
                key_slots=("key1", "key2"),
            ),
        ),
        candidate_slots_compared=2,
        matches=matches,
        binding_inspections=binding_inspections,
        bindings=bindings,
        warnings=warnings,
    )


def _selection_report(
    selected_slots: tuple[KeySlotSelection, ...],
    *,
    bindings: tuple[CredentialBinding, ...] = (),
    inspection_status: CandidateInspectionStatus = CandidateInspectionStatus.compared,
) -> SelectionReport:
    binding_inspections = (
        (
            BindingInspection(
                resource_id=RESOURCE_ID,
                provider="azure-foundry-connections",
                location=BindingLocation.azure,
                status=BindingInspectionStatus.inspected,
                scopes_inspected=1,
            ),
        )
        if bindings
        else ()
    )
    return SelectionReport(
        subscription_id=SUBSCRIPTION_ID,
        subscription_name="Example Production",
        generated_at=NOW,
        azure_binding_inspection=AzureBindingInspection.enabled,
        providers=(
            ProviderInfo(
                name="azure-storage",
                contract_version="1",
                resource_types=("Microsoft.Storage/storageAccounts",),
            ),
            ProviderInfo(
                name="azure-foundry-connections",
                contract_version="1",
                resource_types=("Microsoft.CognitiveServices/accounts/projects/connections",),
            ),
        ),
        resources=(_resource(),),
        inspections=(
            CandidateInspection(
                resource_id=RESOURCE_ID,
                status=inspection_status,
                key_slots=("key1", "key2") if inspection_status is CandidateInspectionStatus.compared else (),
            ),
        ),
        selected_slots=selected_slots,
        binding_inspections=binding_inspections,
        bindings=bindings,
        warnings=(
            DiscoveryWarning(
                code="provider-coverage-limited",
                message="Coverage is limited.",
                impact=WarningImpact.advisory,
                category=WarningCategory.coverage,
            ),
        ),
    )


def _planner() -> PlanningService:
    return PlanningService(clock=lambda: NOW)


def test_no_match_produces_a_no_changes_plan_without_steps() -> None:
    plan = _planner().create(_report(()), TENANT_ID)

    assert plan.state is PlanState.no_changes
    assert plan.scheduled_slots == ()
    assert plan.resources == ()
    assert plan.steps == ()
    assert plan.preconditions[0].subject == "planning-snapshot"


def test_direct_selection_uses_the_same_rotation_semantics_without_input_selectors() -> None:
    binding = _binding("storage-a", "key1", BindingManagement.update_and_verify)
    report = _selection_report(
        (KeySlotSelection(resource_id=RESOURCE_ID, key_slot="key1"),),
        bindings=(binding,),
    )

    plan = _planner().create_selection(report, TENANT_ID)

    assert plan.source_format is PlanSource.direct_selection
    assert plan.source_selectors == ()
    assert plan.skipped_empty_selectors == ()
    assert plan.scheduled_slots[0].input_selectors == ()
    assert [(step.action, step.key_slot) for step in plan.steps] == [
        (PlanStepAction.update_binding, "key2"),
        (PlanStepAction.verify_binding, "key2"),
        (PlanStepAction.regenerate_key, "key1"),
        (PlanStepAction.update_binding, "key1"),
        (PlanStepAction.verify_binding, "key1"),
    ]
    assert plan.preconditions[0].subject == "planning-snapshot"


def test_unavailable_direct_selection_inspection_emits_a_blocked_plan_without_steps() -> None:
    report = _selection_report(
        (KeySlotSelection(resource_id=RESOURCE_ID, key_slot="key1"),),
        inspection_status=CandidateInspectionStatus.unavailable,
    )

    plan = _planner().create_selection(report, TENANT_ID)

    assert plan.state is PlanState.blocked
    assert plan.steps == ()
    assert "candidate-inspection-incomplete" in {warning.code for warning in plan.warnings}


def test_partial_direct_selection_inspection_emits_a_blocked_plan_without_steps() -> None:
    report = _selection_report(
        (KeySlotSelection(resource_id=RESOURCE_ID, key_slot="key1"),),
    ).model_copy(
        update={
            "inspections": (
                CandidateInspection(
                    resource_id=RESOURCE_ID,
                    status=CandidateInspectionStatus.compared,
                    key_slots=("key1",),
                ),
            )
        }
    )

    plan = _planner().create_selection(report, TENANT_ID)

    assert plan.state is PlanState.blocked
    assert plan.steps == ()
    assert "candidate-inspection-incomplete" in {warning.code for warning in plan.warnings}


def test_failed_resource_discovery_blocks_an_empty_plan() -> None:
    report = _report(()).model_copy(
        update={
            "resources": (),
            "inspections": (),
            "candidate_slots_compared": 0,
            "warnings": (
                DiscoveryWarning(
                    code="storage-discovery-failed",
                    message="Storage Account discovery failed with an Azure HTTP error.",
                    impact=WarningImpact.blocking,
                    category=WarningCategory.contract,
                    provider="azure-storage",
                ),
            ),
        }
    )

    plan = _planner().create(report, TENANT_ID)

    assert plan.state is PlanState.blocked
    assert plan.scheduled_slots == ()
    assert plan.steps == ()
    assert [warning.code for warning in plan.warnings] == ["storage-discovery-failed"]


def test_warning_impact_controls_plan_state_independently_of_code_name() -> None:
    match = KeyMatch(input_selector="STORAGE_KEY", resource_id=RESOURCE_ID, key_slot="key1")
    blocking = _planner().create(
        _report(
            (match,),
            warnings=(
                DiscoveryWarning(
                    code="ordinary-looking-warning",
                    message="The inspection contract is incomplete.",
                    impact=WarningImpact.blocking,
                    category=WarningCategory.contract,
                ),
            ),
        ),
        TENANT_ID,
    )
    advisory = _planner().create(
        _report(
            (match,),
            warnings=(
                DiscoveryWarning(
                    code="foundry-looking-warning",
                    message="This warning is advisory.",
                    impact=WarningImpact.advisory,
                    category=WarningCategory.credential_binding,
                ),
            ),
        ),
        TENANT_ID,
    )

    assert blocking.state is PlanState.blocked
    assert advisory.state is PlanState.ready


def test_unavailable_candidate_inspection_blocks_a_no_match_result() -> None:
    report = _report(()).model_copy(
        update={
            "inspections": (
                CandidateInspection(
                    resource_id=RESOURCE_ID,
                    status=CandidateInspectionStatus.unavailable,
                ),
            ),
            "candidate_slots_compared": 0,
        }
    )

    plan = _planner().create(report, TENANT_ID)

    assert plan.state is PlanState.blocked
    assert "candidate-inspection-incomplete" in {warning.code for warning in plan.warnings}


def test_one_selected_slot_without_a_known_affected_binding_rotates_directly() -> None:
    report = _report((KeyMatch(input_selector="STORAGE_KEY", resource_id=RESOURCE_ID, key_slot="key1"),))

    plan = _planner().create(report, TENANT_ID)

    assert plan.state is PlanState.ready
    assert [(step.action, step.key_slot) for step in plan.steps] == [
        (PlanStepAction.regenerate_key, "key1"),
    ]


def test_affected_observed_only_binding_blocks_without_generating_steps() -> None:
    connection = _binding("storage-a", "key1", BindingManagement.observed_only)
    report = _report(
        (KeyMatch(input_selector="STORAGE_KEY", resource_id=RESOURCE_ID, key_slot="key1"),),
        bindings=(connection,),
    )

    plan = _planner().create(report, TENANT_ID)

    assert plan.state is PlanState.blocked
    assert plan.steps == ()
    warning = next(warning for warning in plan.warnings if warning.code == "binding-automation-unavailable")
    assert warning.binding_id == connection.binding_id
    assert warning.impact is WarningImpact.blocking


def test_managed_foundry_connection_steps_are_fully_automatic() -> None:
    connection = _binding("storage-a", "key1", BindingManagement.update_and_verify)
    report = _report(
        (KeyMatch(input_selector="STORAGE_KEY", resource_id=RESOURCE_ID, key_slot="key1"),),
        bindings=(connection,),
    )

    plan = _planner().create(report, TENANT_ID)

    assert [(step.action, step.key_slot) for step in plan.steps] == [
        (PlanStepAction.update_binding, "key2"),
        (PlanStepAction.verify_binding, "key2"),
        (PlanStepAction.regenerate_key, "key1"),
        (PlanStepAction.update_binding, "key1"),
        (PlanStepAction.verify_binding, "key1"),
    ]
    assert "binding-automation-unavailable" not in {warning.code for warning in plan.warnings}


def test_managed_dotenv_file_uses_the_same_bridge_contract_and_requires_plaintext_review() -> None:
    source_path = str((Path.cwd() / "private" / "config" / "secrets.env").resolve())
    match = KeyMatch(input_selector="STORAGE_KEY", resource_id=RESOURCE_ID, key_slot="key1")
    binding = CredentialBinding(
        binding_id=f"dotenv-file:{'a' * 64}",
        name="STORAGE_KEY",
        binding_type="local/dotenv-file",
        provider="local-dotenv-file",
        location=BindingLocation.local,
        scope_id=source_path,
        scope_name="secrets.env",
        key_resource_id=RESOURCE_ID,
        key_slot="key1",
        target=source_path,
        selectors=("STORAGE_KEY",),
        management=BindingManagement.update_and_verify,
    )
    report = _report(
        (match,),
        bindings=(binding,),
        warnings=(
            DiscoveryWarning(
                code="dotenv-file-plaintext-at-rest",
                message="The selected file remains plaintext at rest.",
                impact=WarningImpact.confirmation,
                category=WarningCategory.persistence,
                provider="local-dotenv-file",
            ),
        ),
    ).model_copy(
        update={
            "providers": (
                *_report((match,)).providers,
                ProviderInfo(
                    name="local-dotenv-file",
                    contract_version="1",
                    resource_types=("local/dotenv-file",),
                ),
            ),
            "binding_inspections": (
                BindingInspection(
                    resource_id=RESOURCE_ID,
                    provider="local-dotenv-file",
                    location=BindingLocation.local,
                    status=BindingInspectionStatus.inspected,
                    scopes_inspected=1,
                ),
            ),
        }
    )

    plan = _planner().create_dotenv_file(report, TENANT_ID, source_path)

    assert plan.source_format is PlanSource.dotenv_file
    assert plan.source_path == source_path
    assert plan.source_selectors == ("STORAGE_KEY",)
    assert plan.state is PlanState.confirmation_required
    assert [(step.action, step.key_slot) for step in plan.steps] == [
        (PlanStepAction.update_binding, "key2"),
        (PlanStepAction.verify_binding, "key2"),
        (PlanStepAction.regenerate_key, "key1"),
        (PlanStepAction.update_binding, "key1"),
        (PlanStepAction.verify_binding, "key1"),
    ]
    serialized = plan.model_dump_json()
    assert "old-storage-secret" not in serialized
    assert "fingerprint" not in serialized


def test_managed_connection_without_a_target_blocks_the_plan() -> None:
    connection = _binding("storage-a", "key1", BindingManagement.update_and_verify).model_copy(update={"target": None})
    report = _report(
        (KeyMatch(input_selector="STORAGE_KEY", resource_id=RESOURCE_ID, key_slot="key1"),),
        bindings=(connection,),
    )

    plan = _planner().create(report, TENANT_ID)

    assert plan.state is PlanState.blocked
    assert plan.steps == ()
    assert "managed-binding-contract-incomplete" in {warning.code for warning in plan.warnings}


def test_binding_already_using_the_unscheduled_sibling_is_not_moved() -> None:
    connection = _binding("storage-a", "key2", BindingManagement.observed_only)
    report = _report(
        (KeyMatch(input_selector="STORAGE_KEY", resource_id=RESOURCE_ID, key_slot="key1"),),
        bindings=(connection,),
    )

    plan = _planner().create(report, TENANT_ID)

    assert plan.state is PlanState.ready
    assert [step.action for step in plan.steps] == [PlanStepAction.regenerate_key]
    assert "binding-automation-unavailable" not in {warning.code for warning in plan.warnings}


def test_two_selected_slots_with_an_observed_only_binding_are_blocked() -> None:
    connection = _binding("storage-a", "key2", BindingManagement.observed_only)
    report = _report(
        (
            KeyMatch(input_selector="FIRST", resource_id=RESOURCE_ID, key_slot="key1"),
            KeyMatch(input_selector="SECOND", resource_id=RESOURCE_ID, key_slot="key2"),
        ),
        bindings=(connection,),
    )

    plan = _planner().create(report, TENANT_ID)

    assert plan.state is PlanState.blocked
    assert plan.steps == ()
    assert "binding-automation-unavailable" in {warning.code for warning in plan.warnings}


def test_two_selected_slots_rotate_sequentially_through_one_bridge() -> None:
    key1_binding = _binding("using-key1", "key1", BindingManagement.update_and_verify)
    key2_binding = _binding("using-key2", "key2", BindingManagement.update_and_verify)
    report = _report(
        (
            KeyMatch(input_selector="FIRST", resource_id=RESOURCE_ID, key_slot="key1"),
            KeyMatch(input_selector="SECOND", resource_id=RESOURCE_ID, key_slot="key2"),
        ),
        bindings=(key1_binding, key2_binding),
    )

    plan = _planner().create(report, TENANT_ID)

    assert plan.state is PlanState.ready
    assert [(step.action, step.key_slot, step.binding_id) for step in plan.steps] == [
        (PlanStepAction.update_binding, "key2", key1_binding.binding_id),
        (PlanStepAction.verify_binding, "key2", key1_binding.binding_id),
        (PlanStepAction.regenerate_key, "key1", None),
        (PlanStepAction.update_binding, "key1", key1_binding.binding_id),
        (PlanStepAction.verify_binding, "key1", key1_binding.binding_id),
        (PlanStepAction.update_binding, "key1", key2_binding.binding_id),
        (PlanStepAction.verify_binding, "key1", key2_binding.binding_id),
        (PlanStepAction.regenerate_key, "key2", None),
        (PlanStepAction.update_binding, "key2", key2_binding.binding_id),
        (PlanStepAction.verify_binding, "key2", key2_binding.binding_id),
    ]
    assert [step.sequence for step in plan.steps] == list(range(1, 11))


def test_two_selected_slots_leave_unattributed_bindings_on_the_new_primary_slot() -> None:
    unattributed = _binding("slot-unknown", None, BindingManagement.update_and_verify)
    report = _report(
        (
            KeyMatch(input_selector="FIRST", resource_id=RESOURCE_ID, key_slot="key1"),
            KeyMatch(input_selector="SECOND", resource_id=RESOURCE_ID, key_slot="key2"),
        ),
        bindings=(unattributed,),
    )

    plan = _planner().create(report, TENANT_ID)

    assert plan.state is PlanState.confirmation_required
    binding_steps = [step for step in plan.steps if step.binding_id == unattributed.binding_id]
    assert [(step.action, step.key_slot) for step in binding_steps] == [
        (PlanStepAction.update_binding, "key2"),
        (PlanStepAction.verify_binding, "key2"),
        (PlanStepAction.update_binding, "key1"),
        (PlanStepAction.verify_binding, "key1"),
    ]
    assert "binding-key-slot-unknown" in {warning.code for warning in plan.warnings}


def test_duplicate_input_aliases_schedule_a_slot_only_once() -> None:
    report = _report(
        (
            KeyMatch(input_selector="STORAGE_KEY", resource_id=RESOURCE_ID, key_slot="key1"),
            KeyMatch(input_selector="STORAGE_KEY_ALIAS", resource_id=RESOURCE_ID, key_slot="key1"),
        )
    )

    plan = _planner().create(report, TENANT_ID)

    assert len(plan.scheduled_slots) == 1
    assert plan.scheduled_slots[0].input_selectors == ("STORAGE_KEY", "STORAGE_KEY_ALIAS")
    assert [step.action for step in plan.steps] == [PlanStepAction.regenerate_key]


def test_non_rotatable_selected_slot_blocks_the_plan() -> None:
    report = _report(
        (KeyMatch(input_selector="STORAGE_KEY", resource_id=RESOURCE_ID, key_slot="key1"),),
        resource=_resource(key1_rotatable=False),
    )

    plan = _planner().create(report, TENANT_ID)

    assert plan.state is PlanState.blocked
    assert plan.steps == ()
    assert "selected-slot-not-rotatable" in {warning.code for warning in plan.warnings}


def test_partial_binding_inspection_blocks_the_plan() -> None:
    report = _report(
        (KeyMatch(input_selector="STORAGE_KEY", resource_id=RESOURCE_ID, key_slot="key1"),),
        binding_status=BindingInspectionStatus.partial,
    )

    plan = _planner().create(report, TENANT_ID)

    assert plan.state is PlanState.blocked
    assert "binding-inspection-incomplete" in {warning.code for warning in plan.warnings}


def test_plan_is_secret_free_and_matching_precondition_is_stable() -> None:
    report = _report(
        (KeyMatch(input_selector="STORAGE_KEY", resource_id=RESOURCE_ID, key_slot="key1"),),
        warnings=(
            DiscoveryWarning(
                code="provider-coverage-limited",
                message="Coverage is limited.",
                impact=WarningImpact.advisory,
                category=WarningCategory.coverage,
            ),
        ),
    )

    first = _planner().create(report, TENANT_ID)
    second = PlanningService(clock=lambda: datetime(2000, 1, 2, 12, 0, tzinfo=timezone.utc)).create(
        report.model_copy(update={"generated_at": datetime.now(timezone.utc)}),
        TENANT_ID,
    )

    serialized = first.model_dump_json()
    assert "must-never-appear" not in serialized
    assert "fingerprint" not in serialized
    assert "hmac" not in serialized.casefold()
    assert first.preconditions == second.preconditions

    skipped = _planner().create(
        report.model_copy(update={"azure_binding_inspection": AzureBindingInspection.skipped}),
        TENANT_ID,
    )
    assert skipped.preconditions != first.preconditions


@pytest.mark.parametrize("missing", ("source_format", "source_path", "input_selectors"))
def test_pre_alpha_plan_selection_source_fields_are_required(missing: str) -> None:
    plan = _planner().create(
        _report((KeyMatch(input_selector="STORAGE_KEY", resource_id=RESOURCE_ID, key_slot="key1"),)),
        TENANT_ID,
    )
    payload = plan.model_dump(mode="json")
    if missing == "source_format":
        payload.pop("source_format")
    elif missing == "source_path":
        payload.pop("source_path")
    else:
        payload["scheduled_slots"][0].pop("input_selectors")

    with pytest.raises(ValidationError):
        type(plan).model_validate(payload)


@pytest.mark.parametrize("missing", ("impact", "category"))
def test_pre_alpha_plan_warning_semantics_are_required(missing: str) -> None:
    plan = _planner().create(
        _report(
            (KeyMatch(input_selector="STORAGE_KEY", resource_id=RESOURCE_ID, key_slot="key1"),),
            binding_status=BindingInspectionStatus.partial,
        ),
        TENANT_ID,
    )
    payload = plan.model_dump(mode="json")
    payload["warnings"][0].pop(missing)

    with pytest.raises(ValidationError):
        type(plan).model_validate(payload)


def test_pre_alpha_plan_rejects_the_obsolete_warning_confirmation_field() -> None:
    plan = _planner().create(
        _report(
            (KeyMatch(input_selector="STORAGE_KEY", resource_id=RESOURCE_ID, key_slot="key1"),),
            binding_status=BindingInspectionStatus.partial,
        ),
        TENANT_ID,
    )
    payload = plan.model_dump(mode="json")
    payload["warnings"][0]["requires_confirmation"] = True

    with pytest.raises(ValidationError):
        type(plan).model_validate(payload)


def test_pre_alpha_plan_binding_selectors_are_required() -> None:
    plan = _planner().create(
        _report(
            (KeyMatch(input_selector="STORAGE_KEY", resource_id=RESOURCE_ID, key_slot="key1"),),
            bindings=(
                _binding(
                    "storage-a",
                    "key1",
                    BindingManagement.update_and_verify,
                ),
            ),
        ),
        TENANT_ID,
    )
    payload = plan.model_dump(mode="json")
    payload["bindings"][0].pop("selectors")

    with pytest.raises(ValidationError):
        type(plan).model_validate(payload)


def test_pre_alpha_plan_requires_the_recorded_azure_binding_inspection_mode() -> None:
    plan = _planner().create(
        _report((KeyMatch(input_selector="STORAGE_KEY", resource_id=RESOURCE_ID, key_slot="key1"),)),
        TENANT_ID,
    )
    payload = plan.model_dump(mode="json")
    payload.pop("azure_binding_inspection")

    with pytest.raises(ValidationError):
        type(plan).model_validate(payload)


def test_pre_alpha_plan_requires_binding_location_and_rejects_obsolete_consumer_fields() -> None:
    plan = _planner().create(
        _report(
            (KeyMatch(input_selector="STORAGE_KEY", resource_id=RESOURCE_ID, key_slot="key1"),),
            bindings=(
                _binding(
                    "storage-a",
                    "key1",
                    BindingManagement.update_and_verify,
                ),
            ),
        ),
        TENANT_ID,
    )
    missing_location = plan.model_dump(mode="json")
    missing_location["bindings"][0].pop("location")
    obsolete_shape = plan.model_dump(mode="json")
    obsolete_shape["consumers"] = obsolete_shape.pop("bindings")

    with pytest.raises(ValidationError):
        type(plan).model_validate(missing_location)
    with pytest.raises(ValidationError):
        type(plan).model_validate(obsolete_shape)


def test_pre_alpha_plan_rejects_the_obsolete_step_actor_field() -> None:
    plan = _planner().create(
        _report((KeyMatch(input_selector="STORAGE_KEY", resource_id=RESOURCE_ID, key_slot="key1"),)),
        TENANT_ID,
    )
    payload = plan.model_dump(mode="json")
    payload["steps"][0]["actor"] = "azurator"

    with pytest.raises(ValidationError):
        type(plan).model_validate(payload)


def test_selected_slot_without_candidate_metadata_fails_closed() -> None:
    report = _report((KeyMatch(input_selector="STORAGE_KEY", resource_id=RESOURCE_ID, key_slot="key1"),))
    report = report.model_copy(
        update={
            "inspections": (
                CandidateInspection(
                    resource_id=RESOURCE_ID,
                    status=CandidateInspectionStatus.unavailable,
                ),
            )
        }
    )

    with pytest.raises(PlanningError, match="supported candidate metadata"):
        _planner().create(report, TENANT_ID)

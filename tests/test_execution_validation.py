"""Execution plan, operation, and provider-contract validation tests."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from azurator.execution import ExecutionError, ExecutionService
from azurator.models import (
    AzureBindingInspection,
    BindingLocation,
    BindingManagement,
    PlanSource,
    PlanState,
    PlanStepAction,
    PlanWarning,
    RotationPlan,
    WarningCategory,
    WarningImpact,
)
from azurator.operation import (
    OperationState,
    OperationStatus,
    OperationStore,
    PendingOperationStep,
    operation_intent_digest,
)
from azurator.providers.base import BINDING_VERIFICATION_MISMATCH_CODE
from azurator.providers.dotenv_file import DotenvFileProvider
from tests.execution_test_support import (
    BINDING_ID,
    KEY_STATE_SALT,
    NOW,
    OPERATION_ID,
    FakeBindingProvider,
    FakeRotationProvider,
    make_dotenv_file_plans,
    make_plans,
    make_service,
    make_slot_fingerprints,
    replace_step,
)


def _operation(
    plan: RotationPlan,
    rotation: FakeRotationProvider,
    *,
    status: OperationStatus,
    completed_steps: tuple[int, ...] = (),
    pending_step: PendingOperationStep | None = None,
    error_code: str | None = None,
    error_message: str | None = None,
) -> OperationState:
    return OperationState(
        operation_id=OPERATION_ID,
        plan=plan,
        intent_digest=operation_intent_digest(plan),
        started_at=NOW,
        updated_at=NOW,
        status=status,
        key_state_salt=KEY_STATE_SALT,
        slot_fingerprints=make_slot_fingerprints(plan, rotation.values),
        completed_steps=completed_steps,
        pending_step=pending_step,
        error_code=error_code,
        error_message=error_message,
    )


def test_plan_validation_rejects_malformed_execution_contracts() -> None:
    plan, _ = make_plans()
    regeneration_index = next(
        index for index, step in enumerate(plan.steps) if step.action is PlanStepAction.regenerate_key
    )
    cases: tuple[tuple[str, RotationPlan], ...] = (
        ("plan-schema-unsupported", plan.model_copy(update={"schema_version": "unsupported"})),
        ("plan-warning-impact-invalid", plan.model_copy(update={"state": PlanState.blocked})),
        (
            "plan-blocked",
            plan.model_copy(
                update={
                    "state": PlanState.blocked,
                    "warnings": (
                        PlanWarning(
                            code="test-block",
                            message="The test plan is blocked.",
                            impact=WarningImpact.blocking,
                            category=WarningCategory.contract,
                        ),
                    ),
                }
            ),
        ),
        (
            "plan-warning-impact-invalid",
            plan.model_copy(
                update={
                    "warnings": (
                        PlanWarning(
                            code="hidden-block",
                            message="A blocking warning cannot appear on a ready plan.",
                            impact=WarningImpact.blocking,
                            category=WarningCategory.contract,
                        ),
                    ),
                }
            ),
        ),
        (
            "plan-no-changes",
            plan.model_copy(update={"scheduled_slots": (), "steps": (), "state": PlanState.no_changes}),
        ),
        ("plan-step-order-invalid", replace_step(plan, 0, sequence=2)),
        ("plan-precondition-invalid", plan.model_copy(update={"preconditions": ()})),
        ("plan-selection-source-invalid", plan.model_copy(update={"source_selectors": ()})),
        (
            "plan-selection-source-invalid",
            plan.model_copy(update={"source_format": PlanSource.direct_selection}),
        ),
        ("plan-identity-conflict", plan.model_copy(update={"resources": (*plan.resources, plan.resources[0])})),
        ("plan-step-target-invalid", replace_step(plan, 0, key_slot="unknown-slot")),
        (
            "plan-step-target-invalid",
            replace_step(plan, regeneration_index, binding_id=BINDING_ID),
        ),
    )
    service = make_service(FakeRotationProvider(), FakeBindingProvider())

    for expected_code, invalid in cases:
        with pytest.raises(ExecutionError) as caught:
            service.validate_start(invalid, invalid)
        assert caught.value.code == expected_code


def test_plan_validation_accepts_consistent_direct_selection_source() -> None:
    plan, _ = make_plans()
    direct = plan.model_copy(
        update={
            "source_format": PlanSource.direct_selection,
            "source_selectors": (),
            "scheduled_slots": tuple(slot.model_copy(update={"input_selectors": ()}) for slot in plan.scheduled_slots),
        }
    )

    make_service(FakeRotationProvider(), FakeBindingProvider()).validate_start(direct, direct)


def test_plan_validation_rejects_azure_binding_metadata_when_inspection_was_skipped() -> None:
    plan, _ = make_plans()
    invalid = plan.model_copy(update={"azure_binding_inspection": AzureBindingInspection.skipped})

    with pytest.raises(ExecutionError) as caught:
        make_service(FakeRotationProvider(), FakeBindingProvider()).validate_start(invalid, invalid)

    assert caught.value.code == "plan-binding-inspection-invalid"


def test_plan_validation_rejects_binding_inspection_location_drift() -> None:
    plan, _ = make_plans()
    inspections = tuple(
        inspection.model_copy(update={"location": BindingLocation.local}) for inspection in plan.binding_inspections
    )
    invalid = plan.model_copy(update={"binding_inspections": inspections})

    with pytest.raises(ExecutionError) as caught:
        make_service(FakeRotationProvider(), FakeBindingProvider()).validate_start(invalid, invalid)

    assert caught.value.code == "plan-binding-location-invalid"


def test_plan_validation_keeps_local_dotenv_binding_when_azure_bindings_were_skipped(tmp_path: Path) -> None:
    _, plan, fresh = make_dotenv_file_plans(tmp_path)
    skipped = plan.model_copy(update={"azure_binding_inspection": AzureBindingInspection.skipped})
    fresh_skipped = fresh.model_copy(update={"azure_binding_inspection": AzureBindingInspection.skipped})
    service = ExecutionService((FakeRotationProvider(),), (DotenvFileProvider(),))

    service.validate_start(skipped, fresh_skipped)


def test_obsolete_interactive_plan_source_is_rejected() -> None:
    plan, _ = make_plans()
    payload = plan.model_dump(mode="json")
    payload["source_format"] = "interactive"

    with pytest.raises(ValidationError):
        RotationPlan.model_validate(payload)


def test_plan_validation_requires_installed_rotation_binding_and_version_contracts() -> None:
    plan, _ = make_plans()

    with pytest.raises(ExecutionError) as missing_rotation:
        ExecutionService((), (FakeBindingProvider(),)).validate_start(plan, plan)
    assert missing_rotation.value.code == "plan-rotation-provider-unavailable"

    with pytest.raises(ExecutionError) as missing_binding:
        ExecutionService((FakeRotationProvider(),), ()).validate_start(plan, plan)
    assert missing_binding.value.code == "plan-binding-provider-unavailable"

    observed_only_bindings = tuple(
        binding.model_copy(update={"management": BindingManagement.observed_only}) for binding in plan.bindings
    )
    observed_only_plan = plan.model_copy(update={"bindings": observed_only_bindings})
    with pytest.raises(ExecutionError) as observed_only:
        make_service(FakeRotationProvider(), FakeBindingProvider()).validate_start(
            observed_only_plan,
            observed_only_plan,
        )
    assert observed_only.value.code == "plan-binding-automation-unavailable"

    changed_providers = tuple(
        provider.model_copy(update={"contract_version": "different"}) if provider.name == "azure-storage" else provider
        for provider in plan.providers
    )
    with pytest.raises(ExecutionError) as version_mismatch:
        make_service(FakeRotationProvider(), FakeBindingProvider()).validate_start(
            plan.model_copy(update={"providers": changed_providers}),
            plan.model_copy(update={"providers": changed_providers}),
        )
    assert version_mismatch.value.code == "plan-provider-version-mismatch"


def test_plan_validation_checks_installed_inspection_provider_without_steps() -> None:
    plan, _ = make_plans()
    regeneration_steps = tuple(
        step.model_copy(update={"sequence": index})
        for index, step in enumerate(
            (step for step in plan.steps if step.action is PlanStepAction.regenerate_key),
            start=1,
        )
    )
    inspection_only = plan.model_copy(
        update={
            "bindings": (),
            "steps": regeneration_steps,
            "providers": tuple(
                provider.model_copy(update={"contract_version": "different"})
                if provider.name == "azure-foundry-connections"
                else provider
                for provider in plan.providers
            ),
        }
    )

    with pytest.raises(ExecutionError) as caught:
        make_service(FakeRotationProvider(), FakeBindingProvider()).validate_start(
            inspection_only,
            inspection_only,
        )

    assert caught.value.code == "plan-provider-version-mismatch"


def test_plan_validation_does_not_require_unrecorded_extra_installed_provider() -> None:
    plan, _ = make_plans()

    ExecutionService(
        (FakeRotationProvider(),),
        (FakeBindingProvider(), DotenvFileProvider()),
    ).validate_start(plan, plan)


def test_fresh_plan_detects_non_scope_contract_drift() -> None:
    plan, fresh = make_plans()
    changed = fresh.model_copy(update={"source_selectors": ("DIFFERENT_SELECTOR",)})

    with pytest.raises(ExecutionError) as caught:
        make_service(FakeRotationProvider(), FakeBindingProvider()).validate_start(plan, changed)

    assert caught.value.code == "plan-drift-detected"


def test_execution_service_rejects_duplicate_provider_names() -> None:
    rotation = FakeRotationProvider()
    binding = FakeBindingProvider()

    with pytest.raises(ValueError, match="rotation providers contain duplicate names"):
        ExecutionService((rotation, rotation), ())
    with pytest.raises(ValueError, match="managed binding providers contain duplicate names"):
        ExecutionService((), (binding, binding))


def test_resume_of_completed_operation_returns_without_another_azure_call(tmp_path: Path) -> None:
    plan, fresh = make_plans()
    rotation = FakeRotationProvider()
    binding = FakeBindingProvider()
    service = make_service(rotation, binding)
    store = OperationStore(tmp_path / "operation.json")
    completed = service.start(plan, fresh, store, OPERATION_ID)
    calls = (tuple(rotation.calls), tuple(binding.calls))

    resumed = service.resume(store)

    assert resumed == completed
    assert (tuple(rotation.calls), tuple(binding.calls)) == calls


def test_resume_retries_pending_binding_update_only_after_verification_mismatch(tmp_path: Path) -> None:
    plan, _ = make_plans()
    rotation = FakeRotationProvider()
    binding = FakeBindingProvider()
    first_step = plan.steps[0]
    store = OperationStore(tmp_path / "operation.json")
    store.create(
        _operation(
            plan,
            rotation,
            status=OperationStatus.failed,
            pending_step=PendingOperationStep(
                sequence=first_step.sequence,
                action=first_step.action,
                resource_id=first_step.resource_id,
                key_slot=first_step.key_slot,
                binding_id=first_step.binding_id,
            ),
            error_code=BINDING_VERIFICATION_MISMATCH_CODE,
            error_message="Synthetic verification mismatch.",
        )
    )
    progress: list[int] = []

    completed = make_service(rotation, binding).resume(
        store,
        progress=lambda step: progress.append(step.sequence),
    )

    assert completed.status is OperationStatus.completed
    assert binding.calls[:2] == [("verify", BINDING_ID), ("update", BINDING_ID)]
    assert progress == list(range(1, 6))


def test_resume_retries_pending_regeneration_that_provably_did_not_run(tmp_path: Path) -> None:
    plan, _ = make_plans()
    rotation = FakeRotationProvider()
    binding = FakeBindingProvider()
    binding.stored[BINDING_ID] = rotation.values["key2"]
    regeneration = next(step for step in plan.steps if step.action is PlanStepAction.regenerate_key)
    store = OperationStore(tmp_path / "operation.json")
    store.create(
        _operation(
            plan,
            rotation,
            status=OperationStatus.running,
            completed_steps=(1, 2),
            pending_step=PendingOperationStep(
                sequence=regeneration.sequence,
                action=regeneration.action,
                resource_id=regeneration.resource_id,
                key_slot=regeneration.key_slot,
            ),
        )
    )

    completed = make_service(rotation, binding).resume(store)

    assert completed.status is OperationStatus.completed
    assert rotation.regeneration_count == 1


def test_resume_retries_unchanged_pending_regeneration_after_unclassified_failure(tmp_path: Path) -> None:
    plan, _ = make_plans()
    rotation = FakeRotationProvider()
    binding = FakeBindingProvider()
    regeneration = next(step for step in plan.steps if step.action is PlanStepAction.regenerate_key)
    store = OperationStore(tmp_path / "operation.json")
    store.create(
        _operation(
            plan,
            rotation,
            status=OperationStatus.failed,
            completed_steps=(1, 2),
            pending_step=PendingOperationStep(
                sequence=regeneration.sequence,
                action=regeneration.action,
                resource_id=regeneration.resource_id,
                key_slot=regeneration.key_slot,
            ),
            error_code="unclassified-provider-failure",
            error_message="Synthetic failure with an unknown Azure outcome.",
        )
    )

    completed = make_service(rotation, binding).resume(store)

    assert completed.status is OperationStatus.completed
    assert rotation.regeneration_count == 1


def test_resume_reconciles_managed_binding_drift_before_regeneration(tmp_path: Path) -> None:
    plan, _ = make_plans()
    rotation = FakeRotationProvider()
    binding = FakeBindingProvider()
    binding.stored[BINDING_ID] = rotation.values["key1"]

    def require_bridge() -> None:
        assert binding.stored[BINDING_ID] == rotation.values["key2"]

    rotation.before_regeneration = require_bridge
    store = OperationStore(tmp_path / "operation.json")
    store.create(
        _operation(
            plan,
            rotation,
            status=OperationStatus.running,
            completed_steps=(1, 2),
        )
    )

    completed = make_service(rotation, binding).resume(store)

    assert completed.status is OperationStatus.completed
    assert rotation.regeneration_count == 1
    assert binding.calls[:3] == [
        ("verify", BINDING_ID),
        ("update", BINDING_ID),
        ("verify", BINDING_ID),
    ]
    assert binding.stored[BINDING_ID] == "new-storage-secret-1"


def test_resume_blocks_on_non_mismatch_binding_checkpoint_failure(tmp_path: Path) -> None:
    plan, _ = make_plans()
    rotation = FakeRotationProvider()
    binding = FakeBindingProvider()
    binding.stored[BINDING_ID] = rotation.values["key2"]
    binding.fail_verification_once = True
    store = OperationStore(tmp_path / "operation.json")
    store.create(
        _operation(
            plan,
            rotation,
            status=OperationStatus.running,
            completed_steps=(1, 2),
        )
    )

    with pytest.raises(ExecutionError) as caught:
        make_service(rotation, binding).resume(store)

    assert caught.value.code == "foundry-connection-verification-failed"
    assert rotation.regeneration_count == 0
    assert binding.calls == [("verify", BINDING_ID)]
    assert store.load().pending_step is not None


def test_operation_model_never_accepts_secret_fields() -> None:
    plan, _ = make_plans()
    rotation = FakeRotationProvider()
    payload = _operation(plan, rotation, status=OperationStatus.running).model_dump(mode="json")
    payload["raw_key"] = "must-not-be-accepted"

    with pytest.raises(Exception):
        OperationState.model_validate(payload)

"""Guarded rotation-operation and resume execution tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from azurator import operation as operation_module
from azurator.execution import ExecutionError, ExecutionService
from azurator.models import PlanStepAction, RotationPlan
from azurator.operation import (
    OperationError,
    OperationState,
    OperationStatus,
    OperationStore,
    PendingOperationStep,
    operation_intent_digest,
)
from azurator.providers.base import ProviderOperationError
from tests.execution_test_support import (
    BINDING_ID,
    COGNITIVE_OPERATION_ID,
    COGNITIVE_RESOURCE_ID,
    KEY_STATE_SALT,
    NOW,
    OPERATION_ID,
    FakeBindingProvider,
    FakeCognitiveProvider,
    FakeRotationProvider,
    make_cognitive_plans,
    make_cognitive_service,
    make_plans,
    make_service,
    make_slot_fingerprints,
)


def _start(
    service: ExecutionService,
    plan: RotationPlan,
    fresh: RotationPlan,
    store: OperationStore,
) -> OperationState:
    return service.start(plan, fresh, store, OPERATION_ID)


def test_execution_runs_bridge_sequence_and_persists_no_secret(tmp_path: Path) -> None:
    plan, fresh = make_plans()
    rotation = FakeRotationProvider()
    binding = FakeBindingProvider()
    store = OperationStore(tmp_path / "operation.json")

    result = _start(make_service(rotation, binding), plan, fresh, store)

    assert result.status is OperationStatus.completed
    assert result.plan == plan
    assert result.completed_steps == tuple(range(1, 6))
    assert rotation.regeneration_count == 1
    assert binding.stored[BINDING_ID] == "new-storage-secret-1"
    serialized = store.path.read_text(encoding="utf-8")
    assert "old-storage-secret" not in serialized
    assert "bridge-storage-secret" not in serialized
    assert "new-storage-secret" not in serialized
    assert result.slot_fingerprints == make_slot_fingerprints(plan, rotation.values)


def test_resume_accepts_an_already_applied_pending_binding_transition_without_repeating_it(
    tmp_path: Path,
) -> None:
    plan, fresh = make_plans()
    rotation = FakeRotationProvider()
    binding = FakeBindingProvider()
    binding.fail_update_after_apply_once = True
    store = OperationStore(tmp_path / "operation.json")
    service = make_service(rotation, binding)

    with pytest.raises(ExecutionError) as caught:
        _start(service, plan, fresh, store)

    assert caught.value.code == "fake-binding-update-failed"
    assert store.load().pending_step == PendingOperationStep(
        sequence=1,
        action=PlanStepAction.update_binding,
        resource_id=plan.resources[0].resource_id,
        key_slot="key2",
        binding_id=BINDING_ID,
    )
    assert binding.stored[BINDING_ID] == "bridge-storage-secret"
    assert binding.calls.count(("update", BINDING_ID)) == 1

    completed = service.resume(store)

    assert completed.status is OperationStatus.completed
    assert binding.calls.count(("update", BINDING_ID)) == 2
    assert binding.stored[BINDING_ID] == "new-storage-secret-1"


def test_resume_retries_an_unapplied_pending_binding_transition_from_its_expected_value(
    tmp_path: Path,
) -> None:
    plan, fresh = make_plans()
    rotation = FakeRotationProvider()
    binding = FakeBindingProvider()
    binding.fail_update_before_apply_once = True
    store = OperationStore(tmp_path / "operation.json")
    service = make_service(rotation, binding)

    with pytest.raises(ExecutionError):
        _start(service, plan, fresh, store)

    assert binding.stored[BINDING_ID] == "old-storage-secret"

    completed = service.resume(store)

    assert completed.status is OperationStatus.completed
    assert binding.calls.count(("update", BINDING_ID)) == 3
    assert binding.stored[BINDING_ID] == "new-storage-secret-1"


def test_resume_blocks_a_pending_binding_transition_from_a_third_value(tmp_path: Path) -> None:
    plan, fresh = make_plans()
    rotation = FakeRotationProvider()
    binding = FakeBindingProvider()
    binding.fail_update_before_apply_once = True
    store = OperationStore(tmp_path / "operation.json")
    service = make_service(rotation, binding)

    with pytest.raises(ExecutionError):
        _start(service, plan, fresh, store)
    binding.stored[BINDING_ID] = "external-third-value"

    with pytest.raises(ExecutionError) as caught:
        service.resume(store)

    assert caught.value.code == "fake-binding-drift-detected"
    assert binding.stored[BINDING_ID] == "external-third-value"
    assert rotation.regeneration_count == 0
    assert "external-third-value" not in store.path.read_text(encoding="utf-8")


def test_regeneration_is_recorded_pending_before_the_provider_call(tmp_path: Path) -> None:
    plan, fresh = make_plans()
    rotation = FakeRotationProvider()
    store = OperationStore(tmp_path / "operation.json")
    regeneration = next(step for step in plan.steps if step.action is PlanStepAction.regenerate_key)

    def require_pending_state() -> None:
        operation = store.load()
        assert operation.pending_step is not None
        assert operation.pending_step.sequence == regeneration.sequence
        assert operation.pending_step.action is PlanStepAction.regenerate_key
        assert operation.pending_step.resource_id == regeneration.resource_id
        assert operation.pending_step.key_slot == regeneration.key_slot

    rotation.before_regeneration = require_pending_state

    result = _start(
        make_service(rotation, FakeBindingProvider()),
        plan,
        fresh,
        store,
    )

    assert result.status is OperationStatus.completed


def test_execution_preflights_operation_growth_before_any_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, fresh = make_plans()
    rotation = FakeRotationProvider()
    binding = FakeBindingProvider()
    store = OperationStore(tmp_path / "operation.json")
    monkeypatch.setattr(operation_module, "MAX_OPERATION_STATE_BYTES", 1)

    with pytest.raises(OperationError, match="exceeds"):
        _start(make_service(rotation, binding), plan, fresh, store)

    assert rotation.regeneration_count == 0
    assert binding.calls == []
    assert not store.path.exists()


def test_execution_reconciles_changed_target_after_ambiguous_provider_error(tmp_path: Path) -> None:
    plan, fresh = make_plans()
    rotation = FakeRotationProvider()
    rotation.error_after_regeneration = ProviderOperationError(
        "fake-response-lost",
        "The fake response was lost after the request was sent.",
    )
    binding = FakeBindingProvider()
    store = OperationStore(tmp_path / "operation.json")

    completed = _start(make_service(rotation, binding), plan, fresh, store)

    assert completed.status is OperationStatus.completed
    assert rotation.regeneration_count == 1
    assert rotation.calls.count(("regenerate", "key1")) == 1
    assert binding.stored[BINDING_ID] == "new-storage-secret-1"


def test_execution_delegates_retries_and_stops_after_terminal_unchanged_failure(tmp_path: Path) -> None:
    plan, fresh = make_plans()
    rotation = FakeRotationProvider()
    rotation.regeneration_errors.append(
        ProviderOperationError(
            "fake-response-ambiguous",
            "The fake mutation outcome is ambiguous.",
        )
    )
    binding = FakeBindingProvider()
    store = OperationStore(tmp_path / "operation.json")

    with pytest.raises(ExecutionError) as caught:
        _start(make_service(rotation, binding), plan, fresh, store)

    assert caught.value.code == "fake-response-ambiguous"
    assert rotation.calls.count(("regenerate", "key1")) == 1
    assert rotation.regeneration_count == 0


def test_execution_bounds_failure_metadata_reserved_by_preflight(tmp_path: Path) -> None:
    plan, fresh = make_plans()
    rotation = FakeRotationProvider()
    rotation.regeneration_errors.append(
        ProviderOperationError(
            "fake-response-ambiguous",
            "x" * (operation_module.MAX_OPERATION_ERROR_MESSAGE_CHARACTERS + 1),
        )
    )
    store = OperationStore(tmp_path / "operation.json")

    with pytest.raises(ExecutionError):
        _start(make_service(rotation, FakeBindingProvider()), plan, fresh, store)

    failed = store.load()
    assert failed.status is OperationStatus.failed
    assert failed.error_message == "x" * operation_module.MAX_OPERATION_ERROR_MESSAGE_CHARACTERS


def test_execution_blocks_when_regeneration_also_changes_sibling_slot(tmp_path: Path) -> None:
    plan, fresh = make_plans()
    rotation = FakeRotationProvider()
    rotation.change_sibling_on_regeneration = True
    binding = FakeBindingProvider()
    store = OperationStore(tmp_path / "operation.json")

    with pytest.raises(ExecutionError) as caught:
        _start(make_service(rotation, binding), plan, fresh, store)

    assert caught.value.code == "azure-key-slot-drift"
    assert rotation.regeneration_count == 1
    failed = store.load()
    assert failed.status is OperationStatus.failed
    assert failed.pending_step is not None
    serialized = store.path.read_text(encoding="utf-8")
    assert "unexpected-sibling-secret" not in serialized


def test_cognitive_regeneration_completes_without_persisting_key_material(tmp_path: Path) -> None:
    plan, fresh = make_cognitive_plans()
    provider = FakeCognitiveProvider()
    store = OperationStore(tmp_path / "cognitive-operation.json")

    result = make_cognitive_service(provider).start(
        plan,
        fresh,
        store,
        COGNITIVE_OPERATION_ID,
    )

    assert result.status is OperationStatus.completed
    assert result.slot_fingerprints == make_slot_fingerprints(plan, provider.values)
    assert provider.regeneration_count == 1
    serialized = store.path.read_text(encoding="utf-8")
    assert "old-ai-secret" not in serialized
    assert "new-ai-secret" not in serialized


def test_resume_reconciles_completed_cognitive_regeneration_without_repeating_it(tmp_path: Path) -> None:
    plan, _ = make_cognitive_plans()
    provider = FakeCognitiveProvider()
    before = make_slot_fingerprints(plan, provider.values)
    provider.values["Key1"] = "new-ai-secret"
    store = OperationStore(tmp_path / "cognitive-operation.json")
    store.create(
        OperationState(
            operation_id=COGNITIVE_OPERATION_ID,
            plan=plan,
            intent_digest=operation_intent_digest(plan),
            started_at=NOW,
            updated_at=NOW,
            status=OperationStatus.running,
            key_state_salt=KEY_STATE_SALT,
            slot_fingerprints=before,
            pending_step=PendingOperationStep(
                sequence=1,
                action=PlanStepAction.regenerate_key,
                resource_id=COGNITIVE_RESOURCE_ID,
                key_slot="Key1",
            ),
        )
    )

    completed = make_cognitive_service(provider).resume(store)

    assert completed.status is OperationStatus.completed
    assert provider.regeneration_count == 0


def test_execution_stops_on_verification_failure_and_resumes_before_regeneration(tmp_path: Path) -> None:
    plan, fresh = make_plans()
    rotation = FakeRotationProvider()
    binding = FakeBindingProvider()
    binding.fail_verification_once = True
    store = OperationStore(tmp_path / "operation.json")
    service = make_service(rotation, binding)

    with pytest.raises(ExecutionError) as caught:
        _start(service, plan, fresh, store)

    failed = store.load()
    assert caught.value.code == "foundry-connection-verification-failed"
    assert failed.status is OperationStatus.failed
    assert failed.completed_steps == (1,)
    assert failed.pending_step is not None
    assert failed.pending_step.sequence == 2
    assert rotation.regeneration_count == 0

    completed = service.resume(store)

    assert completed.status is OperationStatus.completed
    assert rotation.regeneration_count == 1


def test_resume_reconciles_completed_regeneration_without_repeating_it(tmp_path: Path) -> None:
    plan, fresh = make_plans()
    rotation = FakeRotationProvider()
    rotation.fail_next_state_read_after_regeneration = True
    binding = FakeBindingProvider()
    store = OperationStore(tmp_path / "operation.json")
    service = make_service(rotation, binding)

    with pytest.raises(ExecutionError) as caught:
        _start(service, plan, fresh, store)

    failed = store.load()
    assert caught.value.code == "fake-key-state-read-failed"
    assert failed.completed_steps == (1, 2)
    assert failed.pending_step is not None
    assert failed.pending_step.sequence == 3
    assert rotation.regeneration_count == 1

    completed = service.resume(store)

    assert completed.status is OperationStatus.completed
    assert rotation.regeneration_count == 1
    assert binding.stored[BINDING_ID] == "new-storage-secret-1"


def test_resume_blocks_when_unrelated_recorded_slot_changed_externally(tmp_path: Path) -> None:
    plan, fresh = make_plans()
    rotation = FakeRotationProvider()
    binding = FakeBindingProvider()
    binding.fail_verification_once = True
    store = OperationStore(tmp_path / "operation.json")
    service = make_service(rotation, binding)

    with pytest.raises(ExecutionError):
        _start(service, plan, fresh, store)
    rotation.values["key2"] = "externally-rotated-secret"

    with pytest.raises(ExecutionError) as caught:
        service.resume(store)

    assert caught.value.code == "azure-key-slot-drift"
    assert rotation.regeneration_count == 0


def test_never_started_operation_requires_fresh_matching_before_resume(tmp_path: Path) -> None:
    plan, fresh = make_plans()
    rotation = FakeRotationProvider()
    binding = FakeBindingProvider()
    store = OperationStore(tmp_path / "operation.json")
    store.create(
        OperationState(
            operation_id=OPERATION_ID,
            plan=plan,
            intent_digest=operation_intent_digest(plan),
            started_at=NOW,
            updated_at=NOW,
            status=OperationStatus.running,
            key_state_salt=KEY_STATE_SALT,
            slot_fingerprints=make_slot_fingerprints(plan, rotation.values),
        )
    )
    service = make_service(rotation, binding)

    with pytest.raises(ExecutionError) as caught:
        service.resume(store)

    assert caught.value.code == "resume-fresh-validation-required"

    completed = service.resume(store, fresh_plan=fresh)

    assert completed.status is OperationStatus.completed


def test_fresh_plan_drift_blocks_before_creating_operation(tmp_path: Path) -> None:
    plan, fresh = make_plans()
    changed = fresh.model_copy(update={"tenant_id": "different-tenant"})
    store = OperationStore(tmp_path / "operation.json")

    with pytest.raises(ExecutionError) as caught:
        _start(
            make_service(FakeRotationProvider(), FakeBindingProvider()),
            plan,
            changed,
            store,
        )

    assert caught.value.code == "plan-scope-drift"
    assert not store.path.exists()


def test_incomplete_provider_key_state_blocks_before_operation_or_mutation(tmp_path: Path) -> None:
    plan, fresh = make_plans()
    rotation = FakeRotationProvider()
    missing_value = rotation.values.pop("key2")
    binding = FakeBindingProvider()
    store = OperationStore(tmp_path / "operation.json")

    with pytest.raises(ExecutionError) as caught:
        _start(make_service(rotation, binding), plan, fresh, store)

    assert caught.value.code == "key-state-response-invalid"
    assert missing_value not in str(caught.value)
    assert rotation.regeneration_count == 0
    assert not store.path.exists()


def test_resume_rejects_modified_embedded_rotation_intent(tmp_path: Path) -> None:
    plan, fresh = make_plans()
    rotation = FakeRotationProvider()
    binding = FakeBindingProvider()
    store = OperationStore(tmp_path / "operation.json")
    service = make_service(rotation, binding)
    completed = _start(service, plan, fresh, store)
    altered = completed.model_copy(update={"plan": plan.model_copy(update={"tenant_id": "different-tenant"})})
    store.save(altered)

    with pytest.raises(ExecutionError) as caught:
        service.resume(store)

    assert caught.value.code == "operation-intent-invalid"


def test_operation_validation_rejects_non_prefix_progress(tmp_path: Path) -> None:
    plan, fresh = make_plans()
    rotation = FakeRotationProvider()
    binding = FakeBindingProvider()
    store = OperationStore(tmp_path / "operation.json")
    service = make_service(rotation, binding)
    completed = _start(service, plan, fresh, store)
    invalid = completed.model_copy(
        update={
            "status": OperationStatus.failed,
            "completed_steps": (1, 3),
        }
    )
    store.save(invalid)

    with pytest.raises(ExecutionError) as caught:
        service.resume(store)

    assert caught.value.code == "operation-progress-invalid"


def test_operation_validation_rejects_inconsistent_failure_state(tmp_path: Path) -> None:
    plan, fresh = make_plans()
    store = OperationStore(tmp_path / "operation.json")
    service = make_service(FakeRotationProvider(), FakeBindingProvider())
    completed = _start(service, plan, fresh, store)
    store.save(
        completed.model_copy(
            update={
                "status": OperationStatus.failed,
                "error_code": "fabricated-failure",
                "error_message": "Fabricated failure without a pending operation.",
            }
        )
    )

    with pytest.raises(ExecutionError) as caught:
        service.resume(store)

    assert caught.value.code == "operation-status-invalid"

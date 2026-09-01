"""Two-slot rotation execution, recovery, drift, and redaction tests."""

from pathlib import Path

import pytest

from azurator.execution import ExecutionError
from azurator.models import PlanStepAction
from azurator.operation import OperationStatus, OperationStore, PendingOperationStep
from tests.execution_test_support import (
    BINDING_ID,
    OPERATION_ID,
    SECOND_BINDING_ID,
    FakeBindingProvider,
    FakeRotationProvider,
    make_service,
    make_slot_fingerprints,
    make_two_slot_binding_plans,
)


def test_two_slot_execution_restores_each_attributed_binding_to_its_original_slot(
    tmp_path: Path,
) -> None:
    plan, fresh = make_two_slot_binding_plans()
    rotation = FakeRotationProvider()
    binding = FakeBindingProvider()
    store = OperationStore(tmp_path / "operation.json")

    result = make_service(rotation, binding).start(plan, fresh, store, OPERATION_ID)

    assert result.status is OperationStatus.completed
    assert result.completed_steps == tuple(range(1, 11))
    assert [call for call in rotation.calls if call[0] == "regenerate"] == [
        ("regenerate", "key1"),
        ("regenerate", "key2"),
    ]
    assert binding.stored[BINDING_ID] == "new-storage-secret-1"
    assert binding.stored[SECOND_BINDING_ID] == "new-storage-secret-2"
    serialized = store.path.read_text(encoding="utf-8")
    for secret in (
        "old-storage-secret",
        "bridge-storage-secret",
        "new-storage-secret-1",
        "new-storage-secret-2",
    ):
        assert secret not in serialized
    assert result.slot_fingerprints == make_slot_fingerprints(plan, rotation.values)


def test_two_slot_resume_accepts_an_already_applied_final_slot_restore(
    tmp_path: Path,
) -> None:
    plan, fresh = make_two_slot_binding_plans()
    rotation = FakeRotationProvider()
    binding = FakeBindingProvider()
    binding.fail_update_after_apply_on_call = 4
    store = OperationStore(tmp_path / "operation.json")
    service = make_service(rotation, binding)

    with pytest.raises(ExecutionError) as caught:
        service.start(plan, fresh, store, OPERATION_ID)

    assert caught.value.code == "fake-binding-update-failed"
    assert store.load().pending_step == PendingOperationStep(
        sequence=9,
        action=PlanStepAction.update_binding,
        resource_id=plan.resources[0].resource_id,
        key_slot="key2",
        binding_id=SECOND_BINDING_ID,
    )
    assert binding.stored[SECOND_BINDING_ID] == "new-storage-secret-2"

    completed = service.resume(store)

    assert completed.status is OperationStatus.completed
    assert rotation.regeneration_count == 2
    assert binding.stored[BINDING_ID] == "new-storage-secret-1"
    assert binding.stored[SECOND_BINDING_ID] == "new-storage-secret-2"


def test_two_slot_resume_blocks_final_slot_restore_from_a_third_value(tmp_path: Path) -> None:
    plan, fresh = make_two_slot_binding_plans()
    rotation = FakeRotationProvider()
    binding = FakeBindingProvider()
    binding.fail_update_before_apply_on_call = 4
    store = OperationStore(tmp_path / "operation.json")
    service = make_service(rotation, binding)

    with pytest.raises(ExecutionError):
        service.start(plan, fresh, store, OPERATION_ID)
    assert store.load().pending_step is not None
    binding.stored[SECOND_BINDING_ID] = "external-third-value"

    with pytest.raises(ExecutionError) as caught:
        service.resume(store)

    assert caught.value.code == "fake-binding-drift-detected"
    assert rotation.regeneration_count == 2
    assert binding.stored[SECOND_BINDING_ID] == "external-third-value"
    assert "external-third-value" not in store.path.read_text(encoding="utf-8")

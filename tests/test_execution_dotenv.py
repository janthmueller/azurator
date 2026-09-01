"""Managed dotenv execution tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from azurator.execution import ExecutionError, ExecutionService
from azurator.operation import OperationStatus, OperationStore
from azurator.providers.dotenv_file import DotenvFileProvider
from tests.execution_test_support import (
    KEY_STATE_SALT,
    NOW,
    OPERATION_ID,
    FakeRotationProvider,
    make_dotenv_file_plans,
    make_two_slot_dotenv_file_plans,
)


def test_execution_updates_and_verifies_a_managed_dotenv_file_through_the_bridge(tmp_path: Path) -> None:
    source, plan, fresh = make_dotenv_file_plans(tmp_path)
    rotation = FakeRotationProvider()
    service = ExecutionService(
        (rotation,),
        (DotenvFileProvider(),),
        clock=lambda: NOW,
        key_state_salt_factory=lambda: KEY_STATE_SALT,
    )
    store = OperationStore(tmp_path / "operation.json")

    completed = service.start(plan, fresh, store, OPERATION_ID)

    assert completed.status is OperationStatus.completed
    content = source.read_text(encoding="utf-8")
    assert "STORAGE_KEY='new-storage-secret-1'" in content
    assert "UNRELATED=leave-me" in content
    operation_payload = (tmp_path / "operation.json").read_text(encoding="utf-8")
    assert "old-storage-secret" not in operation_payload
    assert "bridge-storage-secret" not in operation_payload
    assert "new-storage-secret-1" not in operation_payload


def test_two_slot_execution_preserves_dotenv_alias_groups_on_their_original_slots(
    tmp_path: Path,
) -> None:
    source, plan, fresh = make_two_slot_dotenv_file_plans(tmp_path)
    rotation = FakeRotationProvider()
    service = ExecutionService(
        (rotation,),
        (DotenvFileProvider(),),
        clock=lambda: NOW,
        key_state_salt_factory=lambda: KEY_STATE_SALT,
    )
    operation_path = tmp_path / "operation.json"

    completed = service.start(plan, fresh, OperationStore(operation_path), OPERATION_ID)

    assert completed.status is OperationStatus.completed
    content = source.read_text(encoding="utf-8")
    assert "PRIMARY_KEY='new-storage-secret-1'" in content
    assert "PRIMARY_ALIAS='new-storage-secret-1'" in content
    assert "SECONDARY_KEY='new-storage-secret-2'" in content
    assert "SECONDARY_ALIAS='new-storage-secret-2'" in content
    assert "UNRELATED=leave-me" in content
    operation_payload = operation_path.read_text(encoding="utf-8")
    for secret in (
        "old-storage-secret",
        "bridge-storage-secret",
        "new-storage-secret-1",
        "new-storage-secret-2",
    ):
        assert secret not in operation_payload


def test_plan_validation_rejects_tampered_dotenv_file_source_contracts(tmp_path: Path) -> None:
    source, plan, _ = make_dotenv_file_plans(tmp_path)
    binding = next(item for item in plan.bindings if item.provider == "local-dotenv-file")
    duplicate_slot = plan.scheduled_slots[0].model_copy(update={"key_slot": "key2"})
    duplicate_binding = binding.model_copy(
        update={
            "binding_id": f"{binding.binding_id}-duplicate",
            "key_slot": "key2",
        }
    )
    invalid_plans = (
        plan.model_copy(update={"source_path": str(source.parent / "different.env")}),
        plan.model_copy(
            update={
                "bindings": tuple(
                    item.model_copy(update={"selectors": ("DIFFERENT_SELECTOR",)})
                    if item.binding_id == binding.binding_id
                    else item
                    for item in plan.bindings
                )
            }
        ),
        plan.model_copy(
            update={
                "scheduled_slots": (*plan.scheduled_slots, duplicate_slot),
                "bindings": (*plan.bindings, duplicate_binding),
            }
        ),
    )
    service = ExecutionService((FakeRotationProvider(),), (DotenvFileProvider(),))

    for invalid in invalid_plans:
        with pytest.raises(ExecutionError) as caught:
            service.validate_start(invalid, invalid)
        assert caught.value.code == "plan-selection-source-invalid"

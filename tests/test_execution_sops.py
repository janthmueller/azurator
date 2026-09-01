"""Managed SOPS dotenv execution and plan-validation tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from azurator.execution import ExecutionError, ExecutionService
from azurator.operation import OperationStatus, OperationStore
from azurator.providers.sops_dotenv_file import SopsDotenvFileProvider
from tests.execution_test_support import (
    KEY_STATE_SALT,
    NOW,
    OPERATION_ID,
    FakeRotationProvider,
    make_sops_dotenv_file_plans,
    make_two_slot_sops_dotenv_file_plans,
)
from tests.sops_test_support import FakeSopsCommand


def test_execution_updates_and_verifies_sops_dotenv_through_the_bridge(tmp_path: Path) -> None:
    source, plan, fresh = make_sops_dotenv_file_plans(tmp_path)
    rotation = FakeRotationProvider()
    command = FakeSopsCommand()
    service = ExecutionService(
        (rotation,),
        (SopsDotenvFileProvider(command),),
        clock=lambda: NOW,
        key_state_salt_factory=lambda: KEY_STATE_SALT,
    )
    operation_path = tmp_path / "operation.json"

    completed = service.start(plan, fresh, OperationStore(operation_path), OPERATION_ID)

    assert completed.status is OperationStatus.completed
    content = command.decrypt_dotenv(source)
    assert "STORAGE_KEY='new-storage-secret-1'" in content
    assert "UNRELATED=leave-me" in content
    operation_payload = operation_path.read_text(encoding="utf-8")
    assert "old-storage-secret" not in operation_payload
    assert "bridge-storage-secret" not in operation_payload
    assert "new-storage-secret-1" not in operation_payload


def test_two_slot_execution_preserves_sops_alias_groups_on_their_original_slots(
    tmp_path: Path,
) -> None:
    source, plan, fresh = make_two_slot_sops_dotenv_file_plans(tmp_path)
    rotation = FakeRotationProvider()
    command = FakeSopsCommand()
    service = ExecutionService(
        (rotation,),
        (SopsDotenvFileProvider(command),),
        clock=lambda: NOW,
        key_state_salt_factory=lambda: KEY_STATE_SALT,
    )
    operation_path = tmp_path / "operation.json"

    completed = service.start(plan, fresh, OperationStore(operation_path), OPERATION_ID)

    assert completed.status is OperationStatus.completed
    content = command.decrypt_dotenv(source)
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


def test_plan_validation_rejects_tampered_sops_source_contracts(tmp_path: Path) -> None:
    source, plan, _ = make_sops_dotenv_file_plans(tmp_path)
    binding = next(item for item in plan.bindings if item.provider == "local-sops-dotenv-file")
    invalid_plans = (
        plan.model_copy(update={"source_path": str(source.parent / "different.enc.env")}),
        plan.model_copy(
            update={
                "bindings": tuple(
                    item.model_copy(update={"provider": "local-dotenv-file"})
                    if item.binding_id == binding.binding_id
                    else item
                    for item in plan.bindings
                )
            }
        ),
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
    )
    service = ExecutionService((FakeRotationProvider(),), (SopsDotenvFileProvider(FakeSopsCommand()),))

    for invalid in invalid_plans:
        with pytest.raises(ExecutionError) as caught:
            service.validate_start(invalid, invalid)
        assert caught.value.code == "plan-selection-source-invalid"

"""Tests for private, transient rotation-operation persistence."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

import pytest

from azurator import operation as operation_module
from azurator.operation import (
    OperationError,
    OperationSlotFingerprint,
    OperationState,
    OperationStatus,
    OperationStore,
    operation_intent_digest,
)
from tests.execution_test_support import RESOURCE_ID, make_plans

OPERATION_ID = UUID("33333333-3333-4333-8333-333333333333")


def _operation(*, status: OperationStatus = OperationStatus.running) -> OperationState:
    now = datetime(2000, 1, 2, 12, 0, tzinfo=timezone.utc)
    plan, _ = make_plans()
    resource = next(
        resource for resource in plan.resources if any(step.resource_id == resource.resource_id for step in plan.steps)
    )
    return OperationState(
        operation_id=OPERATION_ID,
        plan=plan,
        intent_digest=operation_intent_digest(plan),
        started_at=now,
        updated_at=now,
        status=status,
        key_state_salt="00" * 32,
        slot_fingerprints=tuple(
            OperationSlotFingerprint(
                resource_id=RESOURCE_ID,
                key_slot=slot.name,
                fingerprint=f"sha256:v1:{'1' * 64}",
            )
            for slot in resource.key_slots
        ),
        completed_steps=(tuple(step.sequence for step in plan.steps) if status is OperationStatus.completed else ()),
    )


def test_operation_create_is_private_and_does_not_replace_existing_state(tmp_path: Path) -> None:
    store = OperationStore(
        tmp_path / str(OPERATION_ID) / "operation.json",
        expected_operation_id=OPERATION_ID,
    )
    original = _operation()

    store.create(original)

    assert store.load() == original
    if os.name != "nt":
        assert store.path.stat().st_mode & 0o777 == 0o600
        assert store.path.parent.stat().st_mode & 0o777 == 0o700
    with pytest.raises(OperationError, match="already exists"):
        store.create(_operation(status=OperationStatus.completed))
    assert store.load() == original


@pytest.mark.parametrize("payload", ("not-json", "{}"))
def test_operation_load_rejects_invalid_content(tmp_path: Path, payload: str) -> None:
    store = OperationStore(tmp_path / "operation.json")
    store.path.write_text(payload, encoding="utf-8")
    store.path.chmod(0o600)

    with pytest.raises(OperationError, match="missing, unsafe, or invalid"):
        store.load()


def test_operation_load_rejects_missing_unsafe_and_mismatched_paths(tmp_path: Path) -> None:
    missing = OperationStore(tmp_path / "missing.json")
    with pytest.raises(OperationError, match="missing, unsafe, or invalid"):
        missing.load()

    target = tmp_path / "target.json"
    target.write_text(_operation().model_dump_json(), encoding="utf-8")
    target.chmod(0o600)
    link = tmp_path / "operation.json"
    link.symlink_to(target)
    with pytest.raises(OperationError, match="missing, unsafe, or invalid"):
        OperationStore(link).load()

    with pytest.raises(OperationError, match="does not match"):
        OperationStore(
            target,
            expected_operation_id=UUID("44444444-4444-4444-8444-444444444444"),
        ).load()

    with pytest.raises(OperationError, match="path does not match"):
        OperationStore(
            target,
            expected_operation_id=OPERATION_ID,
        ).load()


def test_operation_load_rejects_the_obsolete_plan_and_journal_shape(tmp_path: Path) -> None:
    store = OperationStore(tmp_path / "operation.json")
    payload = _operation().model_dump(mode="json")
    plan = payload.pop("plan")
    payload["plan_id"] = "44444444-4444-4444-8444-444444444444"
    payload["plan_digest"] = "a" * 64
    payload["tenant_id"] = plan["tenant_id"]
    payload["subscription_id"] = plan["subscription_id"]
    store.path.write_text(json.dumps(payload), encoding="utf-8")
    store.path.chmod(0o600)

    with pytest.raises(OperationError, match="missing, unsafe, or invalid"):
        store.load()


def test_operation_create_and_load_share_the_artifact_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = OperationStore(tmp_path / "operation.json")
    payload = _operation().model_dump_json()
    monkeypatch.setattr(operation_module, "MAX_OPERATION_STATE_BYTES", 1)

    with pytest.raises(OperationError, match="exceeds"):
        store.create(_operation())
    assert not store.path.exists()

    store.path.write_text(payload, encoding="utf-8")
    store.path.chmod(0o600)
    with pytest.raises(OperationError, match="missing, unsafe, or invalid"):
        store.load()


def test_operation_wraps_create_and_save_failures(tmp_path: Path) -> None:
    parent_file = tmp_path / "not-a-directory"
    parent_file.write_text("occupied", encoding="utf-8")
    store = OperationStore(parent_file / "operation.json")

    with pytest.raises(OperationError, match="persisted safely"):
        store.create(_operation())
    with pytest.raises(OperationError, match="persisted safely"):
        store.save(_operation())


def test_only_the_exact_completed_operation_is_removed(tmp_path: Path) -> None:
    store = OperationStore(
        tmp_path / str(OPERATION_ID) / "operation.json",
        expected_operation_id=OPERATION_ID,
    )
    running = _operation()
    store.create(running)

    with pytest.raises(OperationError, match="only a completed"):
        store.remove_completed(running)
    assert store.path.exists()

    completed = running.model_copy(update={"status": OperationStatus.completed})
    store.save(completed)
    store.remove_completed(completed)

    assert not store.path.exists()
    assert not store.path.parent.exists()


def test_completed_cleanup_refuses_changed_persisted_state(tmp_path: Path) -> None:
    store = OperationStore(tmp_path / "operation-id" / "operation.json")
    completed = _operation(status=OperationStatus.completed)
    store.create(completed)
    changed = completed.model_copy(update={"updated_at": datetime(2000, 1, 2, 12, 1, tzinfo=timezone.utc)})

    with pytest.raises(OperationError, match="changed before cleanup"):
        store.remove_completed(changed)

    assert store.path.exists()

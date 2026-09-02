"""CLI tests for read-only retained rotation-operation inspection."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

import pytest
from typer.testing import CliRunner

import azurator.cli as cli_module
from azurator.cli import app
from azurator.operation import OperationState, OperationStatus, OperationStore
from tests.cli_test_support import make_operation_state
from tests.execution_test_support import RESOURCE_ID, make_plans, make_sops_dotenv_file_plans

_OPERATION_ID = UUID("55555555-5555-4555-8555-555555555555")
_SECOND_OPERATION_ID = UUID("66666666-6666-4666-8666-666666666666")
_SECRET_MARKER = "raw-key-must-not-render"


def _operation_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "operations"
    monkeypatch.setattr(cli_module, "_operation_root", lambda: root)
    return root


def _write_operation(
    root: Path,
    *,
    operation_id: UUID = _OPERATION_ID,
    status: OperationStatus = OperationStatus.failed,
    completed_steps: tuple[int, ...] | None = (1,),
    updated_at: datetime | None = None,
) -> OperationState:
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    plan, _ = make_plans()
    operation = make_operation_state(
        plan,
        status=status,
        completed_steps=completed_steps,
        operation_id=operation_id,
    )
    operation = operation.model_copy(
        update={
            "updated_at": updated_at or operation.updated_at,
            "error_message": _SECRET_MARKER if status is OperationStatus.failed else None,
        }
    )
    OperationStore(
        root / str(operation_id) / "operation.json",
        expected_operation_id=operation_id,
    ).create(operation)
    return operation


def _forbid_remote_boundaries(monkeypatch: pytest.MonkeyPatch) -> None:
    def unexpected(*args: object, **kwargs: object) -> None:
        del args, kwargs
        pytest.fail("local operation inspection must not authenticate or construct Azure services")

    monkeypatch.setattr(cli_module, "_authenticator", unexpected)
    monkeypatch.setattr(cli_module, "_execution_service", unexpected)
    monkeypatch.setattr(cli_module, "_discover_inventory", unexpected)


def test_operation_list_is_empty_without_creating_state_or_contacting_azure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _operation_root(tmp_path, monkeypatch)
    _forbid_remote_boundaries(monkeypatch)

    result = CliRunner().invoke(app, ["operation", "list"])

    assert result.exit_code == 0
    assert "No retained rotation operations." in result.output
    assert "do not retain local operation history" not in result.output
    assert not root.exists()

    verbose = CliRunner().invoke(app, ["-v", "operation", "list"])
    assert verbose.exit_code == 0
    assert "do not retain local operation history" in verbose.output


def test_operation_list_renders_valid_progress_and_failure_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _operation_root(tmp_path, monkeypatch)
    operation = _write_operation(root)
    _forbid_remote_boundaries(monkeypatch)

    result = CliRunner().invoke(
        app,
        ["operation", "list"],
        terminal_width=240,
    )

    assert result.exit_code == 0
    assert str(operation.operation_id) in result.output
    assert "failed" in result.output
    assert "Example Production" in result.output
    assert operation.plan.subscription_id in result.output
    assert f"1/{len(operation.plan.steps)}" in result.output
    assert operation.error_code is not None
    assert operation.error_code not in result.output
    assert "pending" in result.output
    assert _SECRET_MARKER not in result.output
    assert "Azure was not contacted" not in " ".join(result.output.split())

    verbose = CliRunner().invoke(
        app,
        ["-v", "operation", "list"],
        terminal_width=240,
    )
    assert verbose.exit_code == 0
    assert operation.error_code in verbose.output
    assert "Azure was not contacted" in " ".join(verbose.output.split())
    assert _SECRET_MARKER not in verbose.output


def test_operation_list_sorts_valid_operations_by_latest_update(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _operation_root(tmp_path, monkeypatch)
    _write_operation(
        root,
        operation_id=_OPERATION_ID,
        updated_at=datetime(2000, 1, 1, 12, 1, tzinfo=timezone.utc),
    )
    _write_operation(
        root,
        operation_id=_SECOND_OPERATION_ID,
        updated_at=datetime(2000, 1, 1, 13, 1, tzinfo=timezone.utc),
    )

    result = CliRunner().invoke(app, ["operation", "list", "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert [item["operation_id"] for item in payload["operations"]] == [
        str(_SECOND_OPERATION_ID),
        str(_OPERATION_ID),
    ]


def test_operation_show_explains_the_pending_checkpoint_and_resume_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _operation_root(tmp_path, monkeypatch)
    operation = _write_operation(root)
    _forbid_remote_boundaries(monkeypatch)

    result = CliRunner().invoke(
        app,
        ["operation", "show", str(operation.operation_id)],
        terminal_width=180,
    )

    assert result.exit_code == 0
    assert "Pending checkpoint" in result.output
    assert "Current Azure state will be reconciled before this step is resumed" in result.output
    assert "accountone" in result.output
    assert "Storage Account" in result.output
    assert "key1" in result.output
    assert operation.error_code is not None
    assert operation.error_code in result.output
    assert f"azurator rotate --resume {operation.operation_id}" in result.output
    assert "Resume repeats" not in result.output
    assert _SECRET_MARKER not in result.output
    assert RESOURCE_ID not in result.output

    verbose = CliRunner().invoke(
        app,
        ["-v", "operation", "show", str(operation.operation_id)],
        terminal_width=180,
    )
    assert verbose.exit_code == 0
    assert "Resume repeats" in verbose.output
    assert "Azure" in verbose.output
    assert _SECRET_MARKER not in verbose.output
    assert RESOURCE_ID not in verbose.output


def test_operation_json_is_a_minimal_projection_without_recovery_verifiers_or_plan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _operation_root(tmp_path, monkeypatch)
    operation = _write_operation(root)
    _forbid_remote_boundaries(monkeypatch)

    listed = CliRunner().invoke(app, ["operation", "list", "--json"])
    shown = CliRunner().invoke(app, ["operation", "show", str(operation.operation_id), "--json"])

    assert listed.exit_code == 0
    assert shown.exit_code == 0
    list_payload = json.loads(listed.stdout)
    show_payload = json.loads(shown.stdout)
    assert list_payload["schema_version"] == "1"
    assert list_payload["operations"] == [show_payload]
    assert list_payload["invalid_operation_ids"] == []
    assert show_payload["operation_id"] == str(operation.operation_id)
    assert show_payload["status"] == "failed"
    assert show_payload["current_step"]["state"] == "pending"
    assert show_payload["resources"][0] == {
        "name": "accountone",
        "provider": "azure-storage",
        "kind": "StorageV2",
        "key_slots": ["key1"],
    }
    serialized = listed.stdout + shown.stdout
    for forbidden in (
        "key_state_salt",
        "slot_fingerprints",
        "fingerprint",
        "intent_digest",
        "error_message",
        _SECRET_MARKER,
        RESOURCE_ID,
    ):
        assert forbidden not in serialized


def test_operation_list_isolates_invalid_uuid_entries_without_rendering_content(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _operation_root(tmp_path, monkeypatch)
    root.mkdir(mode=0o700)
    invalid_directory = root / str(_OPERATION_ID)
    invalid_directory.mkdir(mode=0o700)
    invalid_file = invalid_directory / "operation.json"
    invalid_file.write_text(f'{{"secret": "{_SECRET_MARKER}"}}', encoding="utf-8")
    invalid_file.chmod(0o600)

    listed = CliRunner().invoke(app, ["operation", "list", "--json"])
    shown = CliRunner().invoke(app, ["operation", "show", str(_OPERATION_ID), "--json"])

    assert listed.exit_code == 0
    payload = json.loads(listed.stdout)
    assert payload["operations"] == []
    assert payload["invalid_operation_ids"] == [str(_OPERATION_ID)]
    assert _SECRET_MARKER not in listed.output
    assert shown.exit_code == 1
    assert "missing, unsafe, or invalid" in shown.output
    assert _SECRET_MARKER not in shown.output


def test_operation_list_rejects_an_intent_digest_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _operation_root(tmp_path, monkeypatch)
    operation = _write_operation(root)
    store = OperationStore(
        root / str(operation.operation_id) / "operation.json",
        expected_operation_id=operation.operation_id,
    )
    store.save(operation.model_copy(update={"intent_digest": "f" * 64}))

    result = CliRunner().invoke(app, ["operation", "list", "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["operations"] == []
    assert payload["invalid_operation_ids"] == [str(operation.operation_id)]


def test_operation_list_ignores_noncanonical_unrelated_entries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _operation_root(tmp_path, monkeypatch)
    root.mkdir(mode=0o700)
    unrelated = root / _SECRET_MARKER
    unrelated.mkdir(mode=0o700)
    (root / "notes").write_text(_SECRET_MARKER, encoding="utf-8")

    result = CliRunner().invoke(app, ["operation", "list", "--json"])

    assert result.exit_code == 0
    assert json.loads(result.stdout) == {
        "schema_version": "1",
        "operations": [],
        "invalid_operation_ids": [],
    }
    assert _SECRET_MARKER not in result.output


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits are not an input contract on Windows")
def test_operation_list_rejects_a_public_operation_root_without_hardening_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _operation_root(tmp_path, monkeypatch)
    root.mkdir(mode=0o755)

    result = CliRunner().invoke(app, ["operation", "list"])

    assert result.exit_code == 1
    assert "unsafe or cannot be inspected" in result.output
    assert root.stat().st_mode & 0o777 == 0o755


def test_operation_list_rejects_a_symlinked_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "actual-operations"
    target.mkdir(mode=0o700)
    root = tmp_path / "operations"
    try:
        root.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable")
    monkeypatch.setattr(cli_module, "_operation_root", lambda: root)

    result = CliRunner().invoke(app, ["operation", "list"])

    assert result.exit_code == 1
    assert "unsafe or cannot be inspected" in result.output


def test_operation_show_reports_a_completed_cleanup_artifact_without_a_current_step(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _operation_root(tmp_path, monkeypatch)
    operation = _write_operation(
        root,
        status=OperationStatus.completed,
        completed_steps=None,
    )

    result = CliRunner().invoke(app, ["operation", "show", str(operation.operation_id), "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "completed"
    assert payload["completed_steps"] == payload["total_steps"]
    assert payload["current_step"] is None
    assert payload["error_code"] is None


def test_operation_show_adds_fresh_stdin_to_a_pristine_streamed_resume_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _operation_root(tmp_path, monkeypatch)
    operation = _write_operation(
        root,
        status=OperationStatus.running,
        completed_steps=(),
    )

    result = CliRunner().invoke(app, ["operation", "show", str(operation.operation_id), "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["current_step"]["state"] == "next"
    assert payload["resume_command"] == f"azurator rotate --resume {operation.operation_id} --stdin"


def test_operation_show_hides_a_managed_sops_path_from_the_resume_projection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _operation_root(tmp_path, monkeypatch)
    root.mkdir(mode=0o700)
    source, plan, _ = make_sops_dotenv_file_plans(tmp_path)
    operation = make_operation_state(
        plan,
        status=OperationStatus.running,
        completed_steps=(),
        operation_id=_OPERATION_ID,
    )
    OperationStore(
        root / str(operation.operation_id) / "operation.json",
        expected_operation_id=operation.operation_id,
    ).create(operation)
    _forbid_remote_boundaries(monkeypatch)

    result = CliRunner().invoke(app, ["operation", "show", str(operation.operation_id), "--json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["resume_command"] == f"azurator rotate --resume {operation.operation_id}"
    assert str(source) not in result.stdout
    assert "--sops-file" not in result.stdout

"""CLI rotate and transient-operation resume tests."""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path
from uuid import UUID

import pytest
from typer.testing import CliRunner

import azurator.cli as cli_module
from azurator.cli import app
from azurator.execution import ExecutionError, ExecutionService
from azurator.models import Inventory, KeySlotSelection, MatchReport, PlanStep, RotationPlan, SelectionReport
from azurator.operation import OperationError, OperationState, OperationStatus, OperationStore
from tests.cli_test_support import (
    CLI_OPERATION_ID,
    SUBSCRIPTION_ID,
    FakeExecutionService,
    make_inventory,
    make_match_report,
    make_operation_state,
    patch_automatic_operation_path,
    patch_direct_plan_boundary,
    patch_plan_boundary,
    write_cli_plan,
    write_direct_cli_plan,
    write_dotenv_file_cli_plan,
)


def _patch_execution_service(
    monkeypatch: pytest.MonkeyPatch,
    service: FakeExecutionService,
) -> None:
    def execution_service(subscription_id: str) -> FakeExecutionService:
        assert subscription_id == SUBSCRIPTION_ID
        return service

    monkeypatch.setattr(cli_module, "_execution_service", execution_service)


def _deny_mutation(prompt: str) -> bool:
    del prompt
    return False


def test_plan_loader_uses_plan_artifact_limit_not_generic_private_file_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan_path, plan = write_direct_cli_plan(tmp_path, monkeypatch)
    payload = plan_path.read_text(encoding="utf-8") + (" " * 1_048_576)
    plan_path.write_text(payload, encoding="utf-8")
    plan_path.chmod(0o600)

    loaded = cli_module._load_rotation_plan(plan_path)  # pyright: ignore[reportPrivateUsage]

    assert len(payload.encode("utf-8")) > 1_048_576
    assert loaded == plan


def test_automatic_operation_path_uses_one_uuid_scoped_state_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if os.name == "nt":
        pytest.skip("XDG_STATE_HOME is a Unix platform convention")
    state_root = tmp_path / "state"
    operation_id = UUID("22222222-2222-4222-8222-222222222222")
    monkeypatch.setenv("XDG_STATE_HOME", str(state_root))

    operation_path = cli_module._automatic_operation_path(  # pyright: ignore[reportPrivateUsage]
        operation_id
    )

    assert operation_path == (state_root / "azurator" / "operations" / str(operation_id) / "operation.json")


def test_operation_root_is_created_private_without_creating_an_operation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if os.name == "nt":
        pytest.skip("Unix mode assertions do not apply on Windows")
    state_root = tmp_path / "state"
    monkeypatch.setenv("XDG_STATE_HOME", str(state_root))

    cli_module._prepare_operation_root()  # pyright: ignore[reportPrivateUsage]

    app_state = state_root / "azurator"
    operations = app_state / "operations"
    assert app_state.stat().st_mode & 0o777 == 0o700
    assert operations.stat().st_mode & 0o777 == 0o700
    assert list(operations.iterdir()) == []


def test_rotate_env_file_uses_one_operation_and_removes_it_after_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    patch_plan_boundary(monkeypatch)
    operation_path = patch_automatic_operation_path(tmp_path, monkeypatch)
    source = tmp_path / "secrets.env"
    source.write_text(
        "STORAGE_KEY=plan-input-secret\nSECOND_STORAGE_KEY=second-plan-secret\n",
        encoding="utf-8",
    )
    source.chmod(0o600)

    class OperationAwareExecutionService(FakeExecutionService):
        def start(
            self,
            plan: RotationPlan,
            fresh_plan: RotationPlan,
            store: OperationStore,
            operation_id: UUID,
            *,
            progress: Callable[[PlanStep], None],
        ) -> OperationState:
            completed = super().start(
                plan,
                fresh_plan,
                store,
                operation_id,
                progress=progress,
            )
            persisted = store.load()
            assert persisted.plan == plan
            assert persisted.operation_id == CLI_OPERATION_ID
            assert {item.name for item in store.path.parent.iterdir()} == {"operation.json"}
            payload = store.path.read_text(encoding="utf-8")
            assert payload.count(str(CLI_OPERATION_ID)) == 1
            assert '"plan_id"' not in payload
            assert "plan-input-secret" not in payload
            assert "second-plan-secret" not in payload
            return completed

    service = OperationAwareExecutionService()
    _patch_execution_service(monkeypatch, service)

    result = CliRunner().invoke(
        app,
        ["-v", "rotate", "--env-file", str(source), "--subscription", SUBSCRIPTION_ID, "--yes"],
    )

    assert result.exit_code == 0
    assert service.validated
    assert service.started
    assert not operation_path.exists()
    assert not operation_path.parent.exists()
    assert "Transient recovery state" in result.stdout
    assert "Transient recovery state was removed" in result.stdout
    assert result.stdout.count("If interrupted") == 1


def test_rotate_interactive_shortcut_uses_selected_plan_only_in_operation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inspected = patch_direct_plan_boundary(monkeypatch)
    operation_path = patch_automatic_operation_path(tmp_path, monkeypatch)
    service = FakeExecutionService()
    _patch_execution_service(monkeypatch, service)

    result = CliRunner().invoke(app, ["rotate", "--yes"], input="1\n")

    assert result.exit_code == 0
    assert service.started
    assert inspected == [
        (
            KeySlotSelection(
                resource_id=make_inventory().resources[0].resource_id,
                key_slot="key1",
            ),
        )
    ]
    assert not operation_path.exists()
    assert "Select Azure key slots for rotation" in result.stderr
    assert "Rotate selected keys" in result.stdout


def test_saved_direct_plan_repeats_recorded_skipped_azure_binding_mode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    patch_direct_plan_boundary(monkeypatch)
    plan_path = tmp_path / "skip-bindings-plan.json"
    generated = CliRunner().invoke(
        app,
        ["plan", "--skip-azure-bindings", "--out", str(plan_path)],
        input="1\n",
    )
    assert generated.exit_code == 0

    inspect_selection = cli_module._inspect_selection  # pyright: ignore[reportPrivateUsage]
    recorded_modes: list[bool] = []

    def inspect_recorded_mode(
        subscription_id: str,
        inventory: Inventory,
        selections: tuple[KeySlotSelection, ...],
        *,
        skip_azure_bindings: bool = False,
    ) -> SelectionReport:
        recorded_modes.append(skip_azure_bindings)
        return inspect_selection(
            subscription_id,
            inventory,
            selections,
            skip_azure_bindings=skip_azure_bindings,
        )

    monkeypatch.setattr(cli_module, "_inspect_selection", inspect_recorded_mode)
    operation_path = patch_automatic_operation_path(tmp_path, monkeypatch)
    service = FakeExecutionService()
    _patch_execution_service(monkeypatch, service)

    result = CliRunner().invoke(app, ["rotate", "--plan", str(plan_path), "--yes"])

    assert result.exit_code == 0
    assert recorded_modes == [True]
    assert service.started
    assert not operation_path.exists()


def test_rotate_cancellation_writes_no_operation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    patch_plan_boundary(monkeypatch)
    operation_path = patch_automatic_operation_path(tmp_path, monkeypatch)
    source = tmp_path / "secrets.env"
    source.write_text("STORAGE_KEY=plan-input-secret\n", encoding="utf-8")
    source.chmod(0o600)
    service = FakeExecutionService()
    _patch_execution_service(monkeypatch, service)
    monkeypatch.setattr(cli_module, "_confirm_mutation", _deny_mutation)

    result = CliRunner().invoke(app, ["rotate", "--env-file", str(source)])

    assert result.exit_code == 0
    assert service.validated
    assert not service.started
    assert not operation_path.exists()
    assert "Cancelled; no Azure resource was changed" in result.stdout


def test_rotate_interactive_shortcut_requires_controlling_terminal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli_module, "_interactive_terminal_available", lambda: False)

    result = CliRunner().invoke(app, ["rotate"])

    assert result.exit_code == 1
    assert "interactive rotation requires a terminal" in result.output


def test_rotate_validation_failure_writes_no_operation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    patch_plan_boundary(monkeypatch)
    operation_path = patch_automatic_operation_path(tmp_path, monkeypatch)
    source = tmp_path / "secrets.env"
    source.write_text("STORAGE_KEY=plan-input-secret\n", encoding="utf-8")
    source.chmod(0o600)

    class RejectingExecutionService(FakeExecutionService):
        def validate_start(self, plan: RotationPlan, fresh_plan: RotationPlan) -> None:
            del plan, fresh_plan
            raise ExecutionError("plan-blocked", "the generated plan is blocked")

    _patch_execution_service(monkeypatch, RejectingExecutionService())

    result = CliRunner().invoke(app, ["rotate", "--env-file", str(source), "--yes"])

    assert result.exit_code == 1
    assert "No recovery state was written" in result.output
    assert "no Azure resource was changed" in result.output
    assert not operation_path.exists()


def test_rotate_pre_operation_failure_leaves_no_recovery_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    patch_plan_boundary(monkeypatch)
    operation_path = patch_automatic_operation_path(tmp_path, monkeypatch)
    source = tmp_path / "secrets.env"
    source.write_text("STORAGE_KEY=plan-input-secret\n", encoding="utf-8")
    source.chmod(0o600)

    class PreOperationFailureExecutionService(FakeExecutionService):
        def start(
            self,
            plan: RotationPlan,
            fresh_plan: RotationPlan,
            store: OperationStore,
            operation_id: UUID,
            *,
            progress: Callable[[PlanStep], None],
        ) -> OperationState:
            del plan, fresh_plan, store, operation_id, progress
            raise ExecutionError("key-state-read-failed", "Azure key-state inspection failed")

    _patch_execution_service(monkeypatch, PreOperationFailureExecutionService())

    result = CliRunner().invoke(app, ["rotate", "--env-file", str(source), "--yes"])

    assert result.exit_code == 1
    assert not operation_path.exists()
    assert "No recovery state was written and no Azure resource was changed" in result.output
    assert "--resume" not in result.output


@pytest.mark.parametrize(
    "arguments",
    (
        ("--plan", "plan.json", "--env-file", "secrets.env"),
        ("--plan", "plan.json", "--subscription", SUBSCRIPTION_ID),
        ("--plan", "plan.json", "--skip-azure-bindings"),
        ("--resume", str(CLI_OPERATION_ID), "--plan", "plan.json"),
        ("--resume", str(CLI_OPERATION_ID), "--env-file", "secrets.env"),
        ("--resume", str(CLI_OPERATION_ID), "--skip-azure-bindings"),
        ("--stdin",),
    ),
)
def test_rotate_rejects_conflicting_or_unsupported_modes(arguments: tuple[str, ...]) -> None:
    result = CliRunner().invoke(app, ["rotate", *arguments], input="TOKEN=must-not-render\n")

    assert result.exit_code == 1
    assert "Error:" in result.output
    assert "must-not-render" not in result.output


def test_apply_command_is_removed() -> None:
    result = CliRunner().invoke(app, ["apply"])

    assert result.exit_code != 0
    assert "No such command" in result.output


def test_rotate_from_saved_stdin_plan_validates_and_cleans_operation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan_path, _ = write_cli_plan(tmp_path, monkeypatch)
    operation_path = patch_automatic_operation_path(tmp_path, monkeypatch)
    service = FakeExecutionService()
    _patch_execution_service(monkeypatch, service)

    result = CliRunner().invoke(
        app,
        ["rotate", "--plan", str(plan_path), "--stdin", "--yes"],
        input="TOKEN=rotate-input-secret\n",
    )

    assert result.exit_code == 0
    assert service.validated
    assert service.started
    assert plan_path.exists()
    assert not operation_path.exists()
    assert "Rotate selected keys" in result.stdout
    assert "Rotation completed" in result.stdout
    assert "rotate-input-secret" not in result.stdout


def test_rotate_revalidates_dotenv_plan_without_accepting_stdin_tokens(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan_path, source, _ = write_dotenv_file_cli_plan(tmp_path, monkeypatch)
    operation_path = patch_automatic_operation_path(tmp_path, monkeypatch)
    service = FakeExecutionService()
    _patch_execution_service(monkeypatch, service)

    rejected = CliRunner().invoke(
        app,
        ["rotate", "--plan", str(plan_path), "--stdin", "--yes"],
        input="TOKEN=must-not-render\n",
    )
    assert rejected.exit_code == 1
    assert "--stdin is accepted only for a saved stdin-based plan" in rejected.output
    assert "must-not-render" not in rejected.output
    assert not service.started

    result = CliRunner().invoke(app, ["-v", "rotate", "--plan", str(plan_path), "--yes"])

    assert result.exit_code == 0
    assert service.started
    assert not operation_path.exists()
    assert "Managed dotenv file" in result.stdout
    assert source.name in result.stdout
    assert "Temporary bridge key persisted" in result.stdout
    assert "Final rotated key verified" in result.stdout
    assert "verified final planned values" in result.stdout
    assert "plan-input-secret" not in result.stdout


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits are unavailable on Windows")
def test_rotate_accepts_broader_dotenv_permissions_without_plan_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan_path, source, _ = write_dotenv_file_cli_plan(tmp_path, monkeypatch)
    source.chmod(0o644)
    patch_automatic_operation_path(tmp_path, monkeypatch)

    class FreshContractExecutionService(FakeExecutionService):
        def validate_start(self, plan: RotationPlan, fresh_plan: RotationPlan) -> None:
            ExecutionService._validate_fresh_plan(  # pyright: ignore[reportPrivateUsage]
                plan,
                fresh_plan,
            )
            super().validate_start(plan, fresh_plan)

    service = FreshContractExecutionService()
    _patch_execution_service(monkeypatch, service)

    result = CliRunner().invoke(app, ["rotate", "--plan", str(plan_path), "--yes"])

    assert result.exit_code == 0
    assert service.validated
    assert service.started
    assert result.stderr.count("Warning: The dotenv file has broad permissions") == 1
    assert "broad permissions" not in result.stdout


def test_rotate_rebuilds_direct_selection_plan_without_token_input(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan_path, _ = write_direct_cli_plan(tmp_path, monkeypatch)
    patch_automatic_operation_path(tmp_path, monkeypatch)
    service = FakeExecutionService()
    _patch_execution_service(monkeypatch, service)

    rejected = CliRunner().invoke(
        app,
        ["rotate", "--plan", str(plan_path), "--stdin", "--yes"],
        input="TOKEN=must-not-render\n",
    )
    assert rejected.exit_code == 1
    assert "--stdin is accepted only for a saved stdin-based plan" in rejected.output
    assert not service.started

    result = CliRunner().invoke(app, ["rotate", "--plan", str(plan_path), "--yes"])

    assert result.exit_code == 0
    assert service.started
    assert "Rotation completed" in result.stdout


def test_pristine_direct_resume_repeats_fresh_inspection_and_then_cleans(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, plan = write_direct_cli_plan(tmp_path, monkeypatch)
    operation_path = patch_automatic_operation_path(tmp_path, monkeypatch)
    operation_path.parent.mkdir(parents=True)
    OperationStore(operation_path).create(
        make_operation_state(
            plan,
            status=OperationStatus.running,
            completed_steps=(),
        )
    )
    service = FakeExecutionService()
    _patch_execution_service(monkeypatch, service)

    result = CliRunner().invoke(
        app,
        ["rotate", "--resume", str(CLI_OPERATION_ID), "--yes"],
    )

    assert result.exit_code == 0
    assert service.validated
    assert service.resumed
    assert not operation_path.exists()
    assert "Rotation completed" in result.stdout


def test_rotate_default_no_cancels_before_operation_or_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan_path, _ = write_cli_plan(tmp_path, monkeypatch)
    operation_path = patch_automatic_operation_path(tmp_path, monkeypatch)
    service = FakeExecutionService()
    _patch_execution_service(monkeypatch, service)
    monkeypatch.setattr(cli_module, "_confirm_mutation", _deny_mutation)

    result = CliRunner().invoke(
        app,
        ["rotate", "--plan", str(plan_path), "--stdin"],
        input="TOKEN=rotate-input-secret\n",
    )

    assert result.exit_code == 0
    assert service.validated
    assert not service.started
    assert not operation_path.exists()
    assert "rotate-input-secret" not in result.stdout


def test_resume_started_operation_uses_embedded_plan_without_reading_tokens(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, plan = write_cli_plan(tmp_path, monkeypatch)
    operation_path = patch_automatic_operation_path(tmp_path, monkeypatch)
    operation_path.parent.mkdir(parents=True)
    OperationStore(operation_path).create(
        make_operation_state(
            plan,
            status=OperationStatus.failed,
            completed_steps=(1,),
        )
    )
    service = FakeExecutionService()
    _patch_execution_service(monkeypatch, service)

    def unexpected_resume_match(subscription_id: str, stream: object) -> MatchReport:
        del subscription_id, stream
        pytest.fail("started resume must not repeat raw-token matching")

    monkeypatch.setattr(cli_module, "_match_dotenv", unexpected_resume_match)

    result = CliRunner().invoke(
        app,
        ["rotate", "--resume", str(CLI_OPERATION_ID), "--yes"],
    )

    assert result.exit_code == 0
    assert service.resumed
    assert not operation_path.exists()
    assert "Resume rotation" in result.stdout


def test_pristine_stdin_resume_requires_fresh_tokens(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, plan = write_cli_plan(tmp_path, monkeypatch)
    operation_path = patch_automatic_operation_path(tmp_path, monkeypatch)
    operation_path.parent.mkdir(parents=True)
    OperationStore(operation_path).create(
        make_operation_state(
            plan,
            status=OperationStatus.running,
            completed_steps=(),
        )
    )
    service = FakeExecutionService()
    _patch_execution_service(monkeypatch, service)

    rejected = CliRunner().invoke(
        app,
        ["rotate", "--resume", str(CLI_OPERATION_ID), "--yes"],
    )

    assert rejected.exit_code == 1
    assert "requires --stdin" in rejected.output
    assert not service.resumed

    resumed = CliRunner().invoke(
        app,
        [
            "rotate",
            "--resume",
            str(CLI_OPERATION_ID),
            "--stdin",
            "--yes",
        ],
        input="TOKEN=rotate-input-secret\n",
    )

    assert resumed.exit_code == 0
    assert service.resumed
    assert not operation_path.exists()
    assert "rotate-input-secret" not in resumed.output


def test_rotate_rejects_public_or_symlinked_plan_before_matching(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan_path, _ = write_cli_plan(tmp_path, monkeypatch)
    called = False

    def unexpected_match(subscription_id: str, stream: object) -> MatchReport:
        nonlocal called
        del subscription_id, stream
        called = True
        return make_match_report()

    monkeypatch.setattr(cli_module, "_match_dotenv", unexpected_match)
    if os.name != "nt":
        plan_path.chmod(0o644)
        result = CliRunner().invoke(
            app,
            ["rotate", "--plan", str(plan_path), "--stdin", "--yes"],
            input="TOKEN=must-not-render\n",
        )
        assert result.exit_code == 1
        assert "missing, unsafe, or invalid" in result.output
        assert not called

    plan_path.chmod(0o600)
    link = tmp_path / "plan-link.json"
    link.symlink_to(plan_path)
    result = CliRunner().invoke(
        app,
        ["rotate", "--plan", str(link), "--stdin", "--yes"],
        input="TOKEN=must-not-render\n",
    )

    assert result.exit_code == 1
    assert "missing, unsafe, or invalid" in result.output
    assert not called
    assert "must-not-render" not in result.output


def test_started_failure_retains_one_operation_and_prints_exact_resume_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan_path, expected_plan = write_direct_cli_plan(tmp_path, monkeypatch)
    operation_path = patch_automatic_operation_path(tmp_path, monkeypatch)

    class FailingExecutionService(FakeExecutionService):
        def start(
            self,
            plan: RotationPlan,
            fresh_plan: RotationPlan,
            store: OperationStore,
            operation_id: UUID,
            *,
            progress: Callable[[PlanStep], None],
        ) -> OperationState:
            del fresh_plan, progress
            assert plan == expected_plan
            failed = make_operation_state(
                plan,
                status=OperationStatus.failed,
                completed_steps=(),
                operation_id=operation_id,
            )
            store.create(failed)
            raise ExecutionError("synthetic-failure", "Synthetic secret-free failure.")

    _patch_execution_service(monkeypatch, FailingExecutionService())

    result = CliRunner().invoke(app, ["-v", "rotate", "--plan", str(plan_path), "--yes"])

    assert result.exit_code == 1
    assert operation_path.exists()
    assert not (operation_path.parent / "plan.json").exists()
    assert not (operation_path.parent / "journal.json").exists()
    assert f"azurator rotate --resume {CLI_OPERATION_ID}" in result.output
    assert str(operation_path) in result.output


def test_failure_does_not_suggest_resume_for_an_invalid_operation_entry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan_path, expected_plan = write_direct_cli_plan(tmp_path, monkeypatch)
    operation_path = patch_automatic_operation_path(tmp_path, monkeypatch)
    marker = "invalid-operation-content-must-not-render"

    class InvalidStateExecutionService(FakeExecutionService):
        def start(
            self,
            plan: RotationPlan,
            fresh_plan: RotationPlan,
            store: OperationStore,
            operation_id: UUID,
            *,
            progress: Callable[[PlanStep], None],
        ) -> OperationState:
            del fresh_plan, operation_id, progress
            assert plan == expected_plan
            store.path.parent.mkdir(mode=0o700)
            store.path.write_text(marker, encoding="utf-8")
            store.path.chmod(0o600)
            raise ExecutionError("synthetic-failure", "Synthetic secret-free failure.")

    _patch_execution_service(monkeypatch, InvalidStateExecutionService())

    result = CliRunner().invoke(app, ["rotate", "--plan", str(plan_path), "--yes"])

    assert result.exit_code == 1
    assert operation_path.exists()
    assert "invalid recovery entry remains" in result.output
    assert "cannot suggest a resume command" in result.output
    assert f"azurator rotate --resume {CLI_OPERATION_ID}" not in result.output
    assert marker not in result.output


def test_cleanup_failure_does_not_reclassify_successful_rotation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan_path, _ = write_direct_cli_plan(tmp_path, monkeypatch)
    operation_path = patch_automatic_operation_path(tmp_path, monkeypatch)
    service = FakeExecutionService()
    _patch_execution_service(monkeypatch, service)

    def fail_cleanup(self: OperationStore, operation: OperationState) -> None:
        del self, operation
        raise OperationError("synthetic cleanup failure")

    monkeypatch.setattr(OperationStore, "remove_completed", fail_cleanup)

    result = CliRunner().invoke(app, ["rotate", "--plan", str(plan_path), "--yes"])

    assert result.exit_code == 0
    assert operation_path.exists()
    assert "Rotation succeeded" in result.output
    assert "could not be removed" in result.output


def test_resume_of_stale_completed_operation_only_cleans_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, plan = write_direct_cli_plan(tmp_path, monkeypatch)
    operation_path = patch_automatic_operation_path(tmp_path, monkeypatch)
    operation_path.parent.mkdir(parents=True)
    OperationStore(operation_path).create(make_operation_state(plan, status=OperationStatus.completed))
    service = FakeExecutionService()
    _patch_execution_service(monkeypatch, service)

    result = CliRunner().invoke(
        app,
        ["rotate", "--resume", str(CLI_OPERATION_ID), "--yes"],
    )

    assert result.exit_code == 0
    assert not service.resumed
    assert not operation_path.exists()
    assert "was already complete" in result.output
    assert "no Azure call was made" not in result.output
    assert "Transient recovery state was removed" not in result.output

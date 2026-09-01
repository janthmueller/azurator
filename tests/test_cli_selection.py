"""CLI tests for exact scriptable Azure resource/key-slot selection."""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

import pytest
from typer.testing import CliRunner

import azurator.cli as cli_module
from azurator.auth import SubscriptionSelection
from azurator.cli import app
from azurator.exporting import DotenvExportAssignment
from azurator.models import CandidateInspectionStatus, Inventory, KeySlotSelection, SelectionReport
from tests.cli_test_support import (
    SUBSCRIPTION_ID,
    SUBSCRIPTION_NAME,
    FakeExecutionService,
    make_inventory,
    patch_automatic_operation_path,
    patch_direct_plan_boundary,
)

_OTHER_SUBSCRIPTION_ID = "22222222-2222-2222-2222-222222222222"
_EXPORTED_KEY = "exported-key-must-not-print"


def _resource_id(*, subscription_id: str = SUBSCRIPTION_ID) -> str:
    return make_inventory(subscription_id).resources[0].resource_id


def _selector(slot: str = "key1", *, subscription_id: str = SUBSCRIPTION_ID) -> str:
    return f"{_resource_id(subscription_id=subscription_id)}#{slot}"


class _FakeExportService:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[DotenvExportAssignment, ...]]] = []

    def render(
        self,
        subscription_id: str,
        assignments: Sequence[DotenvExportAssignment],
    ) -> str:
        captured = tuple(assignments)
        self.calls.append((subscription_id, captured))
        selector = captured[0].selector
        return f"{selector}='{_EXPORTED_KEY}'\n"


def test_selector_parser_accepts_exact_top_level_arm_ids() -> None:
    selections = cli_module._parse_key_slot_selectors(  # pyright: ignore[reportPrivateUsage]
        (_selector("key1"), _selector("key2")),
        SUBSCRIPTION_ID,
    )

    assert selections == (
        KeySlotSelection(resource_id=_resource_id(), key_slot="key1"),
        KeySlotSelection(resource_id=_resource_id(), key_slot="key2"),
    )


@pytest.mark.parametrize(
    ("selectors", "message"),
    (
        (("must-not-render",), "exact form"),
        ((f"{_resource_id()}#",), "exact form"),
        ((f"{_resource_id()}/projects/project-a#key1",), "top-level"),
        ((f"{_resource_id()}?api-version=must-not-render#key1",), "top-level"),
        ((_selector("key1"), _selector("key1")), "more than once"),
    ),
)
def test_selector_parser_rejects_noncanonical_or_duplicate_metadata(
    selectors: tuple[str, ...],
    message: str,
) -> None:
    with pytest.raises(cli_module.DirectSelectionError, match=message):
        cli_module._parse_key_slot_selectors(  # pyright: ignore[reportPrivateUsage]
            selectors,
            SUBSCRIPTION_ID,
        )


def test_selector_parser_rejects_a_different_subscription() -> None:
    with pytest.raises(cli_module.DirectSelectionError, match="different Azure subscription"):
        cli_module._parse_key_slot_selectors(  # pyright: ignore[reportPrivateUsage]
            (_selector(subscription_id=_OTHER_SUBSCRIPTION_ID),),
            SUBSCRIPTION_ID,
        )


def test_scriptable_and_interactive_selection_produce_equivalent_plans(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inspected = patch_direct_plan_boundary(monkeypatch)

    interactive = CliRunner().invoke(app, ["plan", "--json"], input="1,2\n")
    assert interactive.exit_code == 0

    monkeypatch.setattr(cli_module, "_interactive_terminal_available", lambda: False)
    scriptable = CliRunner().invoke(
        app,
        [
            "plan",
            "--select",
            _selector("key1"),
            "--select",
            _selector("key2"),
            "--json",
        ],
    )

    assert scriptable.exit_code == 0
    interactive_plan = json.loads(interactive.stdout)
    scriptable_plan = json.loads(scriptable.stdout)
    interactive_plan.pop("created_at")
    scriptable_plan.pop("created_at")
    assert scriptable_plan == interactive_plan
    assert scriptable_plan["source_format"] == "direct-selection"
    assert inspected == [
        (
            KeySlotSelection(resource_id=_resource_id(), key_slot="key1"),
            KeySlotSelection(resource_id=_resource_id(), key_slot="key2"),
        ),
        (
            KeySlotSelection(resource_id=_resource_id(), key_slot="key1"),
            KeySlotSelection(resource_id=_resource_id(), key_slot="key2"),
        ),
    ]
    assert "Select Azure key slots for rotation" not in scriptable.stderr


def test_scriptable_plan_rejects_cross_subscription_before_discovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def resolve_subscription(value: str | None) -> SubscriptionSelection:
        assert value is None
        return SubscriptionSelection(SUBSCRIPTION_ID, SUBSCRIPTION_NAME, "tenant-id")

    def unexpected_discovery(subscription_id: str) -> Inventory:
        del subscription_id
        pytest.fail("cross-subscription selection must fail before Azure discovery")

    monkeypatch.setattr(cli_module, "_resolve_plan_subscription", resolve_subscription)
    monkeypatch.setattr(cli_module, "_discover_inventory", unexpected_discovery)
    monkeypatch.setattr(cli_module, "_interactive_terminal_available", lambda: False)

    result = CliRunner().invoke(
        app,
        ["plan", "--select", _selector(subscription_id=_OTHER_SUBSCRIPTION_ID)],
    )

    assert result.exit_code == 1
    assert "different Azure subscription" in result.output


def test_scriptable_plan_rejects_unknown_slot_before_candidate_inspection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inspected = patch_direct_plan_boundary(monkeypatch)
    monkeypatch.setattr(cli_module, "_interactive_terminal_available", lambda: False)

    result = CliRunner().invoke(app, ["plan", "--select", _selector("must-not-render")])

    assert result.exit_code == 1
    assert "not a supported rotatable slot" in result.output
    assert "must-not-render" not in result.output
    assert inspected == []


def test_scriptable_plan_rejects_unknown_resource_before_candidate_inspection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inspected = patch_direct_plan_boundary(monkeypatch)
    monkeypatch.setattr(cli_module, "_interactive_terminal_available", lambda: False)
    unknown = _resource_id().replace("/storageAccounts/a", "/storageAccounts/must-not-render")

    result = CliRunner().invoke(app, ["plan", "--select", f"{unknown}#key1"])

    assert result.exit_code == 1
    assert "not found among the supported key resources" in result.output
    assert "must-not-render" not in result.output
    assert inspected == []


def test_scriptable_plan_rejects_a_second_input_mode_before_reading_values() -> None:
    result = CliRunner().invoke(
        app,
        ["plan", "--select", _selector(), "--stdin"],
        input="TOKEN=must-not-render\n",
    )

    assert result.exit_code == 1
    assert "cannot be used together" in result.output
    assert "must-not-render" not in result.output


def test_scriptable_plan_keeps_incomplete_candidate_inspection_blocking(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    patch_direct_plan_boundary(monkeypatch)
    inspect_selection = cli_module._inspect_selection  # pyright: ignore[reportPrivateUsage]

    def inspect_incomplete(
        subscription_id: str,
        inventory: Inventory,
        selections: tuple[KeySlotSelection, ...],
        *,
        skip_azure_bindings: bool = False,
    ) -> SelectionReport:
        report = inspect_selection(
            subscription_id,
            inventory,
            selections,
            skip_azure_bindings=skip_azure_bindings,
        )
        return report.model_copy(
            update={
                "inspections": tuple(
                    inspection.model_copy(
                        update={
                            "status": CandidateInspectionStatus.unavailable,
                            "key_slots": (),
                        }
                    )
                    for inspection in report.inspections
                )
            }
        )

    monkeypatch.setattr(cli_module, "_inspect_selection", inspect_incomplete)
    monkeypatch.setattr(cli_module, "_interactive_terminal_available", lambda: False)

    result = CliRunner().invoke(app, ["plan", "--select", _selector(), "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["state"] == "blocked"
    assert "candidate-inspection-incomplete" in {warning["code"] for warning in payload["warnings"]}
    assert payload["steps"] == []


def test_scriptable_export_creates_only_the_selected_slot_without_a_terminal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "selected.env"
    service = _FakeExportService()

    def resolve_subscription(value: str | None) -> SubscriptionSelection:
        assert value is None
        return SubscriptionSelection(SUBSCRIPTION_ID, SUBSCRIPTION_NAME)

    def discover(subscription_id: str) -> Inventory:
        return make_inventory(subscription_id)

    def export_service(subscription_id: str) -> _FakeExportService:
        assert subscription_id == SUBSCRIPTION_ID
        return service

    monkeypatch.setattr(cli_module, "_resolve_subscription", resolve_subscription)
    monkeypatch.setattr(cli_module, "_discover_inventory", discover)
    monkeypatch.setattr(cli_module, "_export_service", export_service)
    monkeypatch.setattr(cli_module, "_interactive_terminal_available", lambda: False)

    result = CliRunner().invoke(
        app,
        ["export", "--select", _selector("key2"), "--out", str(destination), "--yes"],
    )

    assert result.exit_code == 0
    assert len(service.calls) == 1
    assert service.calls[0][0] == SUBSCRIPTION_ID
    assert [assignment.key_slot for assignment in service.calls[0][1]] == ["key2"]
    assert _EXPORTED_KEY in destination.read_text(encoding="utf-8")
    assert _EXPORTED_KEY not in result.output
    assert "Select Azure key slots to export" not in result.stderr


def test_scriptable_export_rejects_all_as_a_second_selection_mode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_subscription(value: str | None) -> SubscriptionSelection:
        del value
        pytest.fail("conflicting modes must fail before authentication or discovery")

    monkeypatch.setattr(cli_module, "_resolve_subscription", unexpected_subscription)

    result = CliRunner().invoke(
        app,
        [
            "export",
            "--all",
            "--select",
            _selector(),
            "--out",
            str(tmp_path / "keys.env"),
            "--yes",
        ],
    )

    assert result.exit_code == 1
    assert "--all and --select cannot be used together" in result.output


def test_scriptable_export_rejects_unknown_slot_before_key_retrieval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "not-created.env"
    service = _FakeExportService()

    def resolve_subscription(value: str | None) -> SubscriptionSelection:
        assert value is None
        return SubscriptionSelection(SUBSCRIPTION_ID, SUBSCRIPTION_NAME)

    def discover(subscription_id: str) -> Inventory:
        assert subscription_id == SUBSCRIPTION_ID
        return make_inventory(subscription_id)

    def export_service(subscription_id: str) -> _FakeExportService:
        assert subscription_id == SUBSCRIPTION_ID
        return service

    monkeypatch.setattr(cli_module, "_resolve_subscription", resolve_subscription)
    monkeypatch.setattr(cli_module, "_discover_inventory", discover)
    monkeypatch.setattr(cli_module, "_export_service", export_service)
    monkeypatch.setattr(cli_module, "_interactive_terminal_available", lambda: False)

    result = CliRunner().invoke(
        app,
        [
            "export",
            "--select",
            _selector("must-not-render"),
            "--out",
            str(destination),
            "--yes",
        ],
    )

    assert result.exit_code == 1
    assert "not a supported retrievable slot" in result.output
    assert "must-not-render" not in result.output
    assert service.calls == []
    assert not destination.exists()


def test_scriptable_rotate_runs_the_same_direct_plan_without_a_terminal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inspected = patch_direct_plan_boundary(monkeypatch)
    monkeypatch.setattr(cli_module, "_interactive_terminal_available", lambda: False)
    operation_path = patch_automatic_operation_path(tmp_path, monkeypatch)
    service = FakeExecutionService()

    def execution_service(subscription_id: str) -> FakeExecutionService:
        assert subscription_id == SUBSCRIPTION_ID
        return service

    monkeypatch.setattr(cli_module, "_execution_service", execution_service)

    result = CliRunner().invoke(app, ["rotate", "--select", _selector(), "--yes"])

    assert result.exit_code == 0
    assert service.validated
    assert service.started
    assert inspected == [(KeySlotSelection(resource_id=_resource_id(), key_slot="key1"),)]
    assert not operation_path.exists()
    assert "Select Azure key slots for rotation" not in result.stderr
    assert "Rotate selected keys" in result.stdout


def test_scriptable_rotate_rejects_unknown_slot_before_recovery_or_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inspected = patch_direct_plan_boundary(monkeypatch)
    monkeypatch.setattr(cli_module, "_interactive_terminal_available", lambda: False)
    operation_path = patch_automatic_operation_path(tmp_path, monkeypatch)

    def unexpected_execution_service(subscription_id: str) -> FakeExecutionService:
        del subscription_id
        pytest.fail("invalid direct selection must fail before execution service construction")

    monkeypatch.setattr(cli_module, "_execution_service", unexpected_execution_service)

    result = CliRunner().invoke(
        app,
        ["rotate", "--select", _selector("must-not-render"), "--yes"],
    )

    assert result.exit_code == 1
    assert "not a supported rotatable slot" in result.output
    assert "must-not-render" not in result.output
    assert inspected == []
    assert not operation_path.exists()


@pytest.mark.parametrize(
    "arguments",
    (
        ("--plan", "plan.json", "--select", _selector()),
        ("--env-file", "secrets.env", "--select", _selector()),
        ("--resume", "55555555-5555-4555-8555-555555555555", "--select", _selector()),
        ("--select", _selector(), "--stdin"),
    ),
)
def test_rotate_rejects_select_with_another_rotation_source(arguments: tuple[str, ...]) -> None:
    result = CliRunner().invoke(app, ["rotate", *arguments], input="TOKEN=must-not-render\n")

    assert result.exit_code == 1
    assert "Error:" in result.output
    assert "must-not-render" not in result.output

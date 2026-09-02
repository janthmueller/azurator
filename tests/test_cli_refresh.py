"""CLI tests for one-way key-map refresh of existing dotenv files."""

from __future__ import annotations

import os
from collections.abc import Sequence
from pathlib import Path

import pytest
from azure.core.exceptions import ServiceRequestError, ServiceResponseError
from rich.text import Text
from typer.testing import CliRunner

import azurator.cli as cli_module
from azurator.auth import SubscriptionSelection
from azurator.cli import app
from azurator.exporting import DotenvExportAssignment
from azurator.models import Inventory, KeyMap, KeyMapEntry
from azurator.refreshing import SopsDotenvRefreshService
from tests.cli_test_support import SUBSCRIPTION_ID, SUBSCRIPTION_NAME, make_inventory
from tests.sops_test_support import FakeSopsCommand, write_fake_sops_file

_PRIMARY = "current-primary-secret-must-not-render"
_SECONDARY = "current-secondary-secret-must-not-render"


class FakeExportService:
    def __init__(self, payload: str, error: Exception | None = None) -> None:
        self._payload = payload
        self._error = error
        self.calls: list[tuple[str, tuple[DotenvExportAssignment, ...]]] = []

    def render(
        self,
        subscription_id: str,
        assignments: Sequence[DotenvExportAssignment],
    ) -> str:
        self.calls.append((subscription_id, tuple(assignments)))
        if self._error is not None:
            raise self._error
        return self._payload


def _write_key_map(path: Path, *, subscription_id: str = SUBSCRIPTION_ID) -> KeyMap:
    resource = make_inventory(subscription_id).resources[0]
    key_map = KeyMap(
        subscription_id=subscription_id,
        mappings=(
            KeyMapEntry(selector="PRIMARY_KEY", key_resource_id=resource.resource_id, key_slot="key1"),
            KeyMapEntry(selector="PRIMARY_ALIAS", key_resource_id=resource.resource_id, key_slot="key1"),
            KeyMapEntry(selector="SECONDARY_KEY", key_resource_id=resource.resource_id, key_slot="key2"),
        ),
    )
    path.write_text(key_map.model_dump_json(indent=2) + "\n", encoding="utf-8")
    return key_map


def _target_content() -> str:
    return f"# keep\nPRIMARY_KEY=stale-primary\nUNRELATED=preserve-me\nPRIMARY_ALIAS='{_PRIMARY}'\nSECONDARY_KEY=\n"


def _current_payload() -> str:
    return f"PRIMARY_KEY='{_PRIMARY}'\nPRIMARY_ALIAS='{_PRIMARY}'\nSECONDARY_KEY='{_SECONDARY}'\n"


def _patch_azure_boundary(
    monkeypatch: pytest.MonkeyPatch,
    service: FakeExportService,
    *,
    inventory: Inventory | None = None,
) -> None:
    selected_inventory = inventory or make_inventory()

    def resolve_subscription(value: str | None) -> SubscriptionSelection:
        assert value in {None, SUBSCRIPTION_ID}
        return SubscriptionSelection(SUBSCRIPTION_ID, SUBSCRIPTION_NAME)

    def discover(subscription_id: str) -> Inventory:
        assert subscription_id == SUBSCRIPTION_ID
        return selected_inventory

    def export_service(subscription_id: str) -> FakeExportService:
        assert subscription_id == SUBSCRIPTION_ID
        return service

    monkeypatch.setattr(cli_module, "_resolve_subscription", resolve_subscription)
    monkeypatch.setattr(cli_module, "_discover_inventory", discover)
    monkeypatch.setattr(cli_module, "_export_service", export_service)


def _reject_confirmation(_prompt: str) -> bool:
    return False


def _fail_subscription_resolution(_value: str | None) -> SubscriptionSelection:
    pytest.fail("Azure access must not begin")


def _resolve_default_subscription(_value: str | None) -> SubscriptionSelection:
    return SubscriptionSelection(SUBSCRIPTION_ID, SUBSCRIPTION_NAME)


def _fail_discovery(_subscription_id: str) -> Inventory:
    pytest.fail("Azure discovery must not begin")


def test_refresh_help_exposes_one_key_map_and_two_existing_file_modes() -> None:
    result = CliRunner().invoke(app, ["refresh", "--help"])
    output = Text.from_ansi(result.output).plain

    assert result.exit_code == 0
    assert "--key-map" in output
    assert "--env-file" in output
    assert "--sops-file" in output
    assert "--yes" in output


def test_refresh_updates_plaintext_values_and_preserves_unmapped_content(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key_map = tmp_path / "azurator.keys.json"
    target = tmp_path / "secrets.env"
    _write_key_map(key_map)
    target.write_text(_target_content(), encoding="utf-8")
    if os.name != "nt":
        target.chmod(0o600)
    service = FakeExportService(_current_payload())
    _patch_azure_boundary(monkeypatch, service)

    result = CliRunner().invoke(
        app,
        ["refresh", "--key-map", str(key_map), "--env-file", str(target), "--yes"],
    )

    assert result.exit_code == 0
    assert target.read_text(encoding="utf-8") == (
        "# keep\n"
        f"PRIMARY_KEY='{_PRIMARY}'\n"
        "UNRELATED=preserve-me\n"
        f"PRIMARY_ALIAS='{_PRIMARY}'\n"
        f"SECONDARY_KEY='{_SECONDARY}'\n"
    )
    assert len(service.calls) == 1
    assert [assignment.selector for assignment in service.calls[0][1]] == [
        "PRIMARY_KEY",
        "PRIMARY_ALIAS",
        "SECONDARY_KEY",
    ]
    normalized = " ".join(result.output.split())
    assert "Plaintext dotenv refresh · 2 key slots, 3 assignments" in normalized
    assert "rg / account-a" in normalized
    assert "Refreshed 2 mapped assignments" in normalized
    assert "1 mapped assignment was already current" in normalized
    assert _PRIMARY not in result.output
    assert _SECONDARY not in result.output


def test_refresh_updates_sops_values_through_one_encrypted_transaction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key_map = tmp_path / "azurator.keys.json"
    target = tmp_path / "secrets.enc.env"
    _write_key_map(key_map)
    write_fake_sops_file(target, _target_content())
    key_service = FakeExportService(_current_payload())
    command = FakeSopsCommand()
    _patch_azure_boundary(monkeypatch, key_service)
    monkeypatch.setattr(cli_module, "_sops_refresh_service", lambda: SopsDotenvRefreshService(command))

    result = CliRunner().invoke(
        app,
        ["-v", "refresh", "--key-map", str(key_map), "--sops-file", str(target), "--yes"],
    )

    assert result.exit_code == 0
    assert command.set_calls == ["PRIMARY_KEY", "SECONDARY_KEY"]
    assert command.decrypt_dotenv(target) == (
        "# keep\n"
        f"PRIMARY_KEY='{_PRIMARY}'\n"
        "UNRELATED=preserve-me\n"
        f"PRIMARY_ALIAS='{_PRIMARY}'\n"
        f"SECONDARY_KEY='{_SECONDARY}'\n"
    )
    assert "No plaintext file is written" in " ".join(result.output.split())
    assert _PRIMARY not in result.output
    assert _SECONDARY not in result.output


def test_refresh_cancellation_retrieves_no_azure_keys_and_changes_nothing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key_map = tmp_path / "azurator.keys.json"
    target = tmp_path / "secrets.env"
    _write_key_map(key_map)
    target.write_text(_target_content(), encoding="utf-8")
    original = target.read_bytes()
    service = FakeExportService(_current_payload())
    _patch_azure_boundary(monkeypatch, service)
    monkeypatch.setattr(cli_module, "_confirm_mutation", _reject_confirmation)

    result = CliRunner().invoke(
        app,
        ["refresh", "--key-map", str(key_map), "--env-file", str(target)],
    )

    assert result.exit_code == 0
    assert "Refresh cancelled." in result.output
    assert service.calls == []
    assert target.read_bytes() == original


def test_refresh_rejects_missing_mapped_selector_before_azure_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key_map = tmp_path / "azurator.keys.json"
    target = tmp_path / "secrets.env"
    _write_key_map(key_map)
    target.write_text("PRIMARY_KEY=old\nPRIMARY_ALIAS=old\n", encoding="utf-8")
    monkeypatch.setattr(
        cli_module,
        "_resolve_subscription",
        _fail_subscription_resolution,
    )

    result = CliRunner().invoke(
        app,
        ["refresh", "--key-map", str(key_map), "--env-file", str(target), "--yes"],
    )

    assert result.exit_code == 1
    assert "SECONDARY_KEY" in result.output
    assert "stale" not in result.output


def test_refresh_rejects_target_mode_conflicts_and_key_map_aliasing_before_azure_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key_map = tmp_path / "azurator.keys.json"
    target = tmp_path / "secrets.env"
    _write_key_map(key_map)
    target.write_text(_target_content(), encoding="utf-8")
    monkeypatch.setattr(
        cli_module,
        "_resolve_subscription",
        _fail_subscription_resolution,
    )

    missing = CliRunner().invoke(app, ["refresh", "--key-map", str(key_map), "--yes"])
    conflicting = CliRunner().invoke(
        app,
        [
            "refresh",
            "--key-map",
            str(key_map),
            "--env-file",
            str(target),
            "--sops-file",
            str(target),
            "--yes",
        ],
    )
    same_path = CliRunner().invoke(
        app,
        ["refresh", "--key-map", str(target), "--env-file", str(target), "--yes"],
    )

    assert missing.exit_code == 1
    assert conflicting.exit_code == 1
    assert same_path.exit_code == 1
    assert "select one refresh target" in missing.output
    assert "select one refresh target" in conflicting.output
    assert "must not refer to the dotenv target file" in same_path.output


def test_refresh_rejects_cross_subscription_map_before_discovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key_map = tmp_path / "other.keys.json"
    target = tmp_path / "secrets.env"
    _write_key_map(key_map, subscription_id="22222222-2222-2222-2222-222222222222")
    target.write_text(_target_content(), encoding="utf-8")
    monkeypatch.setattr(
        cli_module,
        "_resolve_subscription",
        _resolve_default_subscription,
    )
    monkeypatch.setattr(
        cli_module,
        "_discover_inventory",
        _fail_discovery,
    )

    result = CliRunner().invoke(
        app,
        ["refresh", "--key-map", str(key_map), "--env-file", str(target), "--yes"],
    )

    assert result.exit_code == 1
    assert "does not match the subscription recorded in the key map" in result.output


def test_refresh_reports_inconsistent_resource_identity_before_key_retrieval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key_map = tmp_path / "azurator.keys.json"
    target = tmp_path / "secrets.env"
    _write_key_map(key_map)
    target.write_text(_target_content(), encoding="utf-8")
    original = target.read_bytes()
    inventory = make_inventory()
    resource = inventory.resources[0]
    inconsistent = inventory.model_copy(update={"resources": (resource.model_copy(update={"name": "different-name"}),)})
    service = FakeExportService(_current_payload())
    _patch_azure_boundary(monkeypatch, service, inventory=inconsistent)

    result = CliRunner().invoke(
        app,
        ["refresh", "--key-map", str(key_map), "--env-file", str(target), "--yes"],
    )

    assert result.exit_code == 1
    assert "resource identity contract" in result.output
    assert service.calls == []
    assert target.read_bytes() == original


def test_refresh_redacts_azure_transport_failures_and_keeps_the_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key_map = tmp_path / "azurator.keys.json"
    target = tmp_path / "secrets.env"
    _write_key_map(key_map)
    target.write_text(_target_content(), encoding="utf-8")
    original = target.read_bytes()
    leaked = "provider-error-contained-secret"
    service = FakeExportService("", ServiceRequestError(leaked))
    _patch_azure_boundary(monkeypatch, service)

    result = CliRunner().invoke(
        app,
        ["refresh", "--key-map", str(key_map), "--env-file", str(target), "--yes"],
    )

    assert result.exit_code == 1
    assert "file was not refreshed" in result.output
    assert leaked not in result.output
    assert target.read_bytes() == original


@pytest.mark.parametrize("error_type", (ServiceRequestError, ServiceResponseError))
def test_refresh_redacts_discovery_transport_failures_before_key_retrieval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    error_type: type[Exception],
) -> None:
    key_map = tmp_path / "azurator.keys.json"
    target = tmp_path / "secrets.env"
    _write_key_map(key_map)
    target.write_text(_target_content(), encoding="utf-8")
    original = target.read_bytes()
    leaked = "discovery-error-contained-secret"
    service = FakeExportService(_current_payload())
    _patch_azure_boundary(monkeypatch, service)

    def fail_discovery(_subscription_id: str) -> Inventory:
        raise error_type(leaked)

    monkeypatch.setattr(cli_module, "_discover_inventory", fail_discovery)

    result = CliRunner().invoke(
        app,
        ["refresh", "--key-map", str(key_map), "--env-file", str(target), "--yes"],
    )

    assert result.exit_code == 1
    assert "Azure key-resource discovery for refresh failed" in result.output
    assert leaked not in result.output
    assert service.calls == []
    assert target.read_bytes() == original

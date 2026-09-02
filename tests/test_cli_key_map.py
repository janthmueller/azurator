"""CLI tests for reusable secret-free key maps."""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Sequence
from pathlib import Path

import pytest
from click import unstyle
from typer.testing import CliRunner

import azurator.cli as cli_module
from azurator.auth import SubscriptionSelection
from azurator.cli import app
from azurator.exporting import DotenvExportAssignment
from azurator.models import Inventory, KeyMap, KeyMapEntry, MatchReport
from tests.cli_test_support import (
    SUBSCRIPTION_ID,
    SUBSCRIPTION_NAME,
    make_inventory,
    make_match_report,
    patch_match_boundary,
)

_KEY_ONE = "key-one-must-not-render"
_KEY_TWO = "key-two-must-not-render"


class FakeExportService:
    def __init__(self, payload: str) -> None:
        self.payload = payload
        self.calls: list[tuple[str, tuple[DotenvExportAssignment, ...]]] = []

    def render(
        self,
        subscription_id: str,
        assignments: Sequence[DotenvExportAssignment],
    ) -> str:
        self.calls.append((subscription_id, tuple(assignments)))
        return self.payload


class FakeSopsExportService:
    def __init__(self) -> None:
        self.validation_calls = 0
        self.encrypt_calls: list[tuple[str, Path]] = []

    def validate_environment(self) -> None:
        self.validation_calls += 1

    def encrypt(self, plaintext: str, destination: Path) -> bytearray:
        self.encrypt_calls.append((plaintext, destination))
        return bytearray(b"verified-ciphertext")


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


def _patch_export_boundary(
    monkeypatch: pytest.MonkeyPatch,
    service: FakeExportService,
) -> None:
    def resolve_subscription(value: str | None) -> SubscriptionSelection:
        assert value in {None, SUBSCRIPTION_ID}
        return SubscriptionSelection(SUBSCRIPTION_ID, SUBSCRIPTION_NAME)

    def discover(subscription_id: str) -> Inventory:
        assert subscription_id == SUBSCRIPTION_ID
        return make_inventory(subscription_id)

    def export_service(subscription_id: str) -> FakeExportService:
        assert subscription_id == SUBSCRIPTION_ID
        return service

    monkeypatch.setattr(cli_module, "_resolve_subscription", resolve_subscription)
    monkeypatch.setattr(cli_module, "_discover_inventory", discover)
    monkeypatch.setattr(cli_module, "_export_service", export_service)


def _fail_subscription_resolution(_value: str | None) -> SubscriptionSelection:
    pytest.fail("Azure access must not begin")


def _fail_discovery(_subscription_id: str) -> Inventory:
    pytest.fail("Azure discovery must not begin")


def _resolve_default_subscription(_value: str | None) -> SubscriptionSelection:
    return SubscriptionSelection(SUBSCRIPTION_ID, SUBSCRIPTION_NAME)


def test_export_help_exposes_key_map_as_a_selection_mode() -> None:
    result = CliRunner().invoke(app, ["export", "--help"])
    output = unstyle(result.output)

    assert result.exit_code == 0
    assert "--key-map" in output


def test_match_writes_minimal_private_key_map_from_confirmed_matches(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    patch_match_boundary(monkeypatch)
    destination = tmp_path / "azurator.keys.json"
    source = tmp_path / "secrets.env"
    source.write_text("TOKEN=must-not-render\n", encoding="utf-8")
    if os.name != "nt":
        source.chmod(0o600)

    result = CliRunner().invoke(
        app,
        ["match", "--env-file", str(source), "--key-map-out", str(destination)],
    )

    assert result.exit_code == 0
    payload = json.loads(destination.read_text(encoding="utf-8"))
    assert set(payload) == {"schema_version", "subscription_id", "mappings"}
    assert payload["subscription_id"] == SUBSCRIPTION_ID
    assert payload["mappings"] == [
        {
            "selector": "STORAGE_KEY",
            "key_resource_id": make_match_report().matches[0].resource_id,
            "key_slot": "key1",
        },
        {
            "selector": "SECOND_STORAGE_KEY",
            "key_resource_id": make_match_report().matches[1].resource_id,
            "key_slot": "key2",
        },
    ]
    if os.name != "nt":
        assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert "Wrote 2 confirmed key mappings" in result.output
    assert "must-not-render" not in result.output
    assert "generated_at" not in destination.read_text(encoding="utf-8")
    assert str(source) not in destination.read_text(encoding="utf-8")


def test_match_key_map_rejects_conflicting_output_modes_and_source_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        cli_module,
        "_resolve_subscription",
        _fail_subscription_resolution,
    )
    source = tmp_path / "secrets.env"
    source.write_text("TOKEN=must-not-render\n", encoding="utf-8")

    json_conflict = CliRunner().invoke(
        app,
        ["match", "--stdin", "--json", "--key-map-out", str(tmp_path / "map.json")],
        input="TOKEN=must-not-render\n",
    )
    same_path = CliRunner().invoke(
        app,
        ["match", "--env-file", str(source), "--key-map-out", str(source)],
    )

    assert json_conflict.exit_code == 1
    assert "cannot be used together" in json_conflict.output
    assert same_path.exit_code == 1
    assert "must not refer to the dotenv input file" in same_path.output
    assert source.read_text(encoding="utf-8") == "TOKEN=must-not-render\n"
    assert "must-not-render" not in json_conflict.output
    assert "must-not-render" not in same_path.output


def test_match_does_not_create_an_empty_key_map(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = make_match_report().model_copy(update={"matches": ()})

    def resolve_subscription(_value: str | None) -> SubscriptionSelection:
        return SubscriptionSelection(SUBSCRIPTION_ID, SUBSCRIPTION_NAME)

    def match_empty(
        _subscription_id: str,
        _stream: object,
        *,
        skip_azure_bindings: bool = False,
    ) -> MatchReport:
        del skip_azure_bindings
        return report

    monkeypatch.setattr(cli_module, "_resolve_subscription", resolve_subscription)
    monkeypatch.setattr(cli_module, "_match_dotenv", match_empty)
    destination = tmp_path / "empty.json"

    result = CliRunner().invoke(
        app,
        ["match", "--stdin", "--key-map-out", str(destination)],
        input="TOKEN=must-not-render\n",
    )

    assert result.exit_code == 1
    assert "no confirmed Azure key matches" in result.output
    assert not destination.exists()
    assert "must-not-render" not in result.output


def test_export_uses_key_map_selectors_slots_and_aliases_from_a_shared_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key_map_path = tmp_path / "azurator.keys.json"
    _write_key_map(key_map_path)
    if os.name != "nt":
        key_map_path.chmod(0o644)
    destination = tmp_path / "secrets.env"
    payload = f"PRIMARY_KEY='{_KEY_ONE}'\nPRIMARY_ALIAS='{_KEY_ONE}'\nSECONDARY_KEY='{_KEY_TWO}'\n"
    service = FakeExportService(payload)
    _patch_export_boundary(monkeypatch, service)

    result = CliRunner().invoke(
        app,
        ["export", "--key-map", str(key_map_path), "--out", str(destination), "--yes"],
    )

    assert result.exit_code == 0
    assert destination.read_text(encoding="utf-8") == payload
    assert len(service.calls) == 1
    assignments = service.calls[0][1]
    assert [assignment.selector for assignment in assignments] == [
        "PRIMARY_KEY",
        "PRIMARY_ALIAS",
        "SECONDARY_KEY",
    ]
    assert [assignment.key_slot for assignment in assignments] == ["key1", "key1", "key2"]
    normalized = " ".join(result.output.split())
    assert "Plaintext dotenv export · 2 key slots, 3 assignments" in normalized
    assert "Exported 2 Azure key slots as 3 dotenv assignments" in normalized
    assert _KEY_ONE not in result.output
    assert _KEY_TWO not in result.output


def test_export_key_map_reuses_existing_sops_export_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key_map_path = tmp_path / "azurator.keys.json"
    _write_key_map(key_map_path)
    destination = tmp_path / "secrets.enc.env"
    payload = f"PRIMARY_KEY='{_KEY_ONE}'\nPRIMARY_ALIAS='{_KEY_ONE}'\nSECONDARY_KEY='{_KEY_TWO}'\n"
    service = FakeExportService(payload)
    sops_service = FakeSopsExportService()
    _patch_export_boundary(monkeypatch, service)
    monkeypatch.setattr(cli_module, "_sops_export_service", lambda: sops_service)

    result = CliRunner().invoke(
        app,
        ["export", "--key-map", str(key_map_path), "--sops-out", str(destination), "--yes"],
    )

    assert result.exit_code == 0
    assert destination.read_bytes() == b"verified-ciphertext"
    assert sops_service.validation_calls == 1
    assert sops_service.encrypt_calls == [(payload, destination.resolve())]
    assert "Exported 2 Azure key slots as 3 dotenv assignments" in " ".join(result.output.split())
    assert _KEY_ONE not in result.output
    assert _KEY_TWO not in result.output


def test_export_rejects_invalid_or_cross_subscription_key_map_before_azure_discovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    invalid = tmp_path / "invalid.json"
    invalid.write_text('{"schema_version":"unexpected"}\n', encoding="utf-8")
    wrong_scope = tmp_path / "wrong-scope.json"
    _write_key_map(wrong_scope, subscription_id="22222222-2222-2222-2222-222222222222")
    monkeypatch.setattr(
        cli_module,
        "_discover_inventory",
        _fail_discovery,
    )
    monkeypatch.setattr(
        cli_module,
        "_resolve_subscription",
        _resolve_default_subscription,
    )

    invalid_result = CliRunner().invoke(
        app,
        ["export", "--key-map", str(invalid), "--out", str(tmp_path / "invalid.env"), "--yes"],
    )
    scope_result = CliRunner().invoke(
        app,
        ["export", "--key-map", str(wrong_scope), "--out", str(tmp_path / "wrong.env"), "--yes"],
    )

    assert invalid_result.exit_code == 1
    assert "current Azurator key-map format" in invalid_result.output
    assert scope_result.exit_code == 1
    assert "does not match the subscription recorded in the key map" in scope_result.output
    assert not (tmp_path / "invalid.env").exists()
    assert not (tmp_path / "wrong.env").exists()


def test_export_rejects_invalid_key_map_coordinates_before_azure_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key_map_path = tmp_path / "invalid-coordinate.json"
    key_map = _write_key_map(key_map_path)
    invalid = key_map.model_copy(
        update={
            "mappings": (
                key_map.mappings[0].model_copy(update={"key_resource_id": "not-an-arm-resource-id"}),
                *key_map.mappings[1:],
            )
        }
    )
    key_map_path.write_text(invalid.model_dump_json(indent=2) + "\n", encoding="utf-8")
    monkeypatch.setattr(cli_module, "_resolve_subscription", _fail_subscription_resolution)

    result = CliRunner().invoke(
        app,
        ["export", "--key-map", str(key_map_path), "--out", str(tmp_path / "keys.env"), "--yes"],
    )

    assert result.exit_code == 1
    assert "invalid top-level Azure resource ID" in result.output
    assert not (tmp_path / "keys.env").exists()


def test_export_key_map_is_a_separate_selection_mode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key_map_path = tmp_path / "azurator.keys.json"
    _write_key_map(key_map_path)
    monkeypatch.setattr(
        cli_module,
        "_resolve_subscription",
        _fail_subscription_resolution,
    )

    result = CliRunner().invoke(
        app,
        [
            "export",
            "--key-map",
            str(key_map_path),
            "--all",
            "--out",
            str(tmp_path / "keys.env"),
            "--yes",
        ],
    )

    assert result.exit_code == 1
    assert "cannot be used together" in result.output


@pytest.mark.skipif(os.name == "nt", reason="symlink setup requires POSIX semantics")
def test_export_rejects_a_symlink_key_map_before_azure_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "target.json"
    _write_key_map(target)
    link = tmp_path / "azurator.keys.json"
    link.symlink_to(target)
    monkeypatch.setattr(
        cli_module,
        "_resolve_subscription",
        _fail_subscription_resolution,
    )

    result = CliRunner().invoke(
        app,
        ["export", "--key-map", str(link), "--out", str(tmp_path / "keys.env"), "--yes"],
    )

    assert result.exit_code == 1
    assert "key-map file is missing, unsafe" in result.output
    assert not (tmp_path / "keys.env").exists()

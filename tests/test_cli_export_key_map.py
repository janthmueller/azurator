"""CLI tests for companion key-map creation during dotenv export."""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Sequence
from pathlib import Path

import pytest
from typer.testing import CliRunner

import azurator.cli as cli_module
from azurator.auth import SubscriptionSelection
from azurator.cli import app
from azurator.files import UnsafeOutputPathError
from azurator.models import DotenvKeyAssignment, Inventory
from azurator.providers.base import ProviderOperationError
from tests.cli_test_support import SUBSCRIPTION_ID, SUBSCRIPTION_NAME, make_inventory

_KEY_ONE = "storage-key-one-must-not-print"
_KEY_TWO = "storage-key-two-must-not-print"


class FakeExportService:
    def __init__(self, payload: str, error: Exception | None = None) -> None:
        self._payload = payload
        self._error = error
        self.calls: list[tuple[str, tuple[DotenvKeyAssignment, ...]]] = []

    def render(
        self,
        subscription_id: str,
        assignments: Sequence[DotenvKeyAssignment],
    ) -> str:
        captured = tuple(assignments)
        self.calls.append((subscription_id, captured))
        if self._error is not None:
            raise self._error
        return self._payload


class FakeSopsExportService:
    def __init__(self) -> None:
        self.validation_calls = 0
        self.encrypt_calls: list[tuple[str, Path]] = []

    def validate_environment(self) -> None:
        self.validation_calls += 1

    def encrypt(self, plaintext: str, destination: Path) -> bytearray:
        self.encrypt_calls.append((plaintext, destination))
        return bytearray(b"synthetic-sops-ciphertext")


def _patch_export_boundary(
    monkeypatch: pytest.MonkeyPatch,
    service: FakeExportService,
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


def _fail_subscription_resolution(value: str | None) -> SubscriptionSelection:
    del value
    pytest.fail("subscription resolution must not run")


def test_export_all_creates_a_companion_key_map_from_the_same_assignments(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "azure-keys.env"
    key_map_destination = tmp_path / "azurator.keys.json"
    payload = (
        f"AZURATOR_AZURE_STORAGE_ACCOUNT_A_KEY1='{_KEY_ONE}'\nAZURATOR_AZURE_STORAGE_ACCOUNT_A_KEY2='{_KEY_TWO}'\n"
    )
    service = FakeExportService(payload)
    _patch_export_boundary(monkeypatch, service)

    result = CliRunner().invoke(
        app,
        [
            "export",
            "--all",
            "--out",
            str(destination),
            "--key-map-out",
            str(key_map_destination),
            "--yes",
        ],
    )

    assert result.exit_code == 0
    assert destination.read_text(encoding="utf-8") == payload
    key_map = json.loads(key_map_destination.read_text(encoding="utf-8"))
    assert key_map == {
        "schema_version": "1",
        "subscription_id": SUBSCRIPTION_ID,
        "mappings": [
            {
                "selector": "AZURATOR_AZURE_STORAGE_ACCOUNT_A_KEY1",
                "key_resource_id": make_inventory().resources[0].resource_id,
                "key_slot": "key1",
            },
            {
                "selector": "AZURATOR_AZURE_STORAGE_ACCOUNT_A_KEY2",
                "key_resource_id": make_inventory().resources[0].resource_id,
                "key_slot": "key2",
            },
        ],
    }
    if os.name != "nt":
        assert stat.S_IMODE(destination.stat().st_mode) == 0o600
        assert stat.S_IMODE(key_map_destination.stat().st_mode) == 0o600
    normalized = " ".join(result.output.split())
    assert "Key map" in normalized
    assert "and wrote key map" in normalized
    assert _KEY_ONE not in result.output
    assert _KEY_TWO not in result.output


def test_sops_export_creates_verified_ciphertext_with_its_companion_key_map(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "azure-keys.enc.env"
    key_map_destination = tmp_path / "azurator.keys.json"
    payload = f"AZURATOR_AZURE_STORAGE_ACCOUNT_A_KEY1='{_KEY_ONE}'\n"
    key_service = FakeExportService(payload)
    sops_service = FakeSopsExportService()
    _patch_export_boundary(monkeypatch, key_service)
    monkeypatch.setattr(cli_module, "_sops_export_service", lambda: sops_service)

    result = CliRunner().invoke(
        app,
        [
            "export",
            "--select",
            f"{make_inventory().resources[0].resource_id}#key1",
            "--sops-out",
            str(destination),
            "--key-map-out",
            str(key_map_destination),
            "--yes",
        ],
    )

    assert result.exit_code == 0
    assert destination.read_bytes() == b"synthetic-sops-ciphertext"
    assert json.loads(key_map_destination.read_text(encoding="utf-8"))["mappings"] == [
        {
            "selector": "AZURATOR_AZURE_STORAGE_ACCOUNT_A_KEY1",
            "key_resource_id": make_inventory().resources[0].resource_id,
            "key_slot": "key1",
        }
    ]
    assert sops_service.validation_calls == 1
    assert sops_service.encrypt_calls == [(payload, destination.resolve())]
    assert _KEY_ONE not in result.output


def test_export_with_key_map_cancellation_writes_neither_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "cancelled.env"
    key_map_destination = tmp_path / "cancelled.keys.json"
    service = FakeExportService(f"TOKEN='{_KEY_ONE}'\n")
    _patch_export_boundary(monkeypatch, service)

    def reject_confirmation(prompt: str) -> bool:
        assert "dotenv file and key map" in prompt
        return False

    monkeypatch.setattr(cli_module, "_confirm_mutation", reject_confirmation)

    result = CliRunner().invoke(
        app,
        [
            "export",
            "--all",
            "--out",
            str(destination),
            "--key-map-out",
            str(key_map_destination),
        ],
    )

    assert result.exit_code == 0
    assert service.calls == []
    assert not destination.exists()
    assert not key_map_destination.exists()
    assert "Export cancelled." in result.output


def test_export_with_key_map_retrieval_failure_writes_neither_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "failed.env"
    key_map_destination = tmp_path / "failed.keys.json"
    service = FakeExportService("", ProviderOperationError("failed", f"included {_KEY_ONE}"))
    _patch_export_boundary(monkeypatch, service)

    result = CliRunner().invoke(
        app,
        [
            "export",
            "--all",
            "--out",
            str(destination),
            "--key-map-out",
            str(key_map_destination),
            "--yes",
        ],
    )

    assert result.exit_code == 1
    assert not destination.exists()
    assert not key_map_destination.exists()
    assert _KEY_ONE not in result.output


def test_export_with_key_map_redacts_an_unproven_file_rollback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "failed.env"
    key_map_destination = tmp_path / "failed.keys.json"
    service = FakeExportService(f"TOKEN='{_KEY_ONE}'\n")
    _patch_export_boundary(monkeypatch, service)

    def fail_file_set(_outputs: object) -> None:
        raise UnsafeOutputPathError(f"rollback failure included {_KEY_ONE}")

    monkeypatch.setattr(cli_module, "create_private_file_set", fail_file_set)

    result = CliRunner().invoke(
        app,
        [
            "export",
            "--all",
            "--out",
            str(destination),
            "--key-map-out",
            str(key_map_destination),
            "--yes",
        ],
    )

    assert result.exit_code == 1
    assert "inspect the displayed destinations" in result.output
    assert _KEY_ONE not in result.output


def test_export_rejects_invalid_key_map_output_before_azure_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "keys.env"
    existing_map = tmp_path / "azurator.keys.json"
    existing_map.write_text("keep\n", encoding="utf-8")
    monkeypatch.setattr(cli_module, "_resolve_subscription", _fail_subscription_resolution)

    same_path = CliRunner().invoke(
        app,
        ["export", "--all", "--out", str(destination), "--key-map-out", str(destination), "--yes"],
    )
    existing = CliRunner().invoke(
        app,
        ["export", "--all", "--out", str(destination), "--key-map-out", str(existing_map), "--yes"],
    )

    assert same_path.exit_code == 1
    assert "must not refer to the dotenv export destination" in same_path.output
    assert existing.exit_code == 1
    assert "refusing to replace an existing key-map export destination" in existing.output
    assert existing_map.read_text(encoding="utf-8") == "keep\n"
    assert not destination.exists()


def test_export_rejects_a_missing_key_map_parent_before_azure_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "keys.env"
    key_map_destination = tmp_path / "missing" / "azurator.keys.json"
    monkeypatch.setattr(cli_module, "_resolve_subscription", _fail_subscription_resolution)

    result = CliRunner().invoke(
        app,
        [
            "export",
            "--all",
            "--out",
            str(destination),
            "--key-map-out",
            str(key_map_destination),
            "--yes",
        ],
    )

    assert result.exit_code == 1
    assert "key-map export destination has a missing or unsafe parent" in result.output
    assert not destination.exists()
    assert not key_map_destination.exists()

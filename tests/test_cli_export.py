"""CLI tests for explicit private plaintext and SOPS dotenv export."""

from __future__ import annotations

import os
import stat
from collections.abc import Sequence
from pathlib import Path

import pytest
from azure.core.exceptions import (
    HttpResponseError,
    ServiceRequestError,
    ServiceResponseError,
)
from azure.identity import CredentialUnavailableError
from typer.testing import CliRunner

import azurator.cli as cli_module
from azurator.auth import SubscriptionSelection
from azurator.cli import app
from azurator.files import PrivateFileExistsError
from azurator.models import DotenvKeyAssignment, Inventory
from azurator.providers.base import ProviderOperationError
from azurator.sops import SopsError
from tests.cli_test_support import (
    SUBSCRIPTION_ID,
    SUBSCRIPTION_NAME,
    make_inventory,
)

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
    def __init__(
        self,
        ciphertext: bytes = b"synthetic-sops-ciphertext",
        *,
        validation_error: Exception | None = None,
        encryption_error: Exception | None = None,
    ) -> None:
        self._ciphertext = ciphertext
        self._validation_error = validation_error
        self._encryption_error = encryption_error
        self.validation_calls = 0
        self.encrypt_calls: list[tuple[str, Path]] = []

    def validate_environment(self) -> None:
        self.validation_calls += 1
        if self._validation_error is not None:
            raise self._validation_error

    def encrypt(self, plaintext: str, destination: Path) -> bytearray:
        self.encrypt_calls.append((plaintext, destination))
        if self._encryption_error is not None:
            raise self._encryption_error
        return bytearray(self._ciphertext)


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


def test_export_all_creates_one_private_file_without_printing_values(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "azure-keys.env"
    payload = (
        f"AZURATOR_AZURE_STORAGE_ACCOUNT_A_KEY1='{_KEY_ONE}'\nAZURATOR_AZURE_STORAGE_ACCOUNT_A_KEY2='{_KEY_TWO}'\n"
    )
    service = FakeExportService(payload)
    _patch_export_boundary(monkeypatch, service)

    result = CliRunner().invoke(
        app,
        ["export", "--all", "--out", str(destination), "--yes"],
    )

    assert result.exit_code == 0
    assert destination.read_text(encoding="utf-8") == payload
    if os.name != "nt":
        assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert len(service.calls) == 1
    assert service.calls[0][0] == SUBSCRIPTION_ID
    assert [assignment.key_slot for assignment in service.calls[0][1]] == ["key1", "key2"]
    assert "Plaintext dotenv export · 2 key slots" in result.output
    assert "rg / account-a" in " ".join(result.output.split())
    assert f"Subscription {SUBSCRIPTION_NAME} ({SUBSCRIPTION_ID})" in result.output
    assert str(destination.resolve()) in result.output
    assert "Exported 2 Azure key slots" in result.output
    assert _KEY_ONE not in result.output
    assert _KEY_TWO not in result.output


def test_export_picker_retrieves_only_the_selected_slot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "selected.env"
    payload = f"AZURATOR_AZURE_STORAGE_ACCOUNT_A_KEY2='{_KEY_TWO}'\n"
    service = FakeExportService(payload)
    _patch_export_boundary(monkeypatch, service)
    monkeypatch.setattr(cli_module, "_interactive_terminal_available", lambda: True)

    result = CliRunner().invoke(
        app,
        ["export", "--out", str(destination), "--yes"],
        input="2\n",
    )

    assert result.exit_code == 0
    assert destination.read_text(encoding="utf-8") == payload
    assert len(service.calls) == 1
    assignments = service.calls[0][1]
    assert len(assignments) == 1
    assert assignments[0].key_slot == "key2"
    assert assignments[0].selector == "AZURATOR_AZURE_STORAGE_ACCOUNT_A_KEY2"
    assert _KEY_TWO not in result.output


def test_sops_export_creates_only_verified_ciphertext(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "azure-keys.enc.env"
    payload = (
        f"AZURATOR_AZURE_STORAGE_ACCOUNT_A_KEY1='{_KEY_ONE}'\nAZURATOR_AZURE_STORAGE_ACCOUNT_A_KEY2='{_KEY_TWO}'\n"
    )
    key_service = FakeExportService(payload)
    sops_service = FakeSopsExportService()
    _patch_export_boundary(monkeypatch, key_service)
    monkeypatch.setattr(cli_module, "_sops_export_service", lambda: sops_service)

    result = CliRunner().invoke(
        app,
        ["-v", "export", "--all", "--sops-out", str(destination), "--yes"],
    )

    assert result.exit_code == 0
    assert destination.read_bytes() == b"synthetic-sops-ciphertext"
    if os.name != "nt":
        assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert sops_service.validation_calls == 1
    assert sops_service.encrypt_calls == [(payload, destination.resolve())]
    assert "SOPS-encrypted dotenv export · 2 key slots" in result.output
    assert "No plaintext file is written" in " ".join(result.output.split())
    assert "Exported 2 Azure key slots to SOPS-encrypted dotenv file" in result.output
    assert _KEY_ONE not in result.output
    assert _KEY_TWO not in result.output


def test_export_requires_exactly_one_plaintext_or_sops_destination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli_module, "_resolve_subscription", _fail_subscription_resolution)

    missing = CliRunner().invoke(app, ["export", "--all", "--yes"])
    conflicting = CliRunner().invoke(
        app,
        [
            "export",
            "--all",
            "--out",
            str(tmp_path / "plain.env"),
            "--sops-out",
            str(tmp_path / "encrypted.env"),
            "--yes",
        ],
    )

    assert missing.exit_code == 1
    assert "select one export destination" in missing.output
    assert conflicting.exit_code == 1
    assert "cannot be used together" in conflicting.output


def test_export_cancellation_reads_no_keys_and_writes_no_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "cancelled.env"
    service = FakeExportService(f"TOKEN='{_KEY_ONE}'\n")
    _patch_export_boundary(monkeypatch, service)

    def reject_confirmation(prompt: str) -> bool:
        assert "plaintext dotenv file" in prompt
        return False

    monkeypatch.setattr(cli_module, "_confirm_mutation", reject_confirmation)

    result = CliRunner().invoke(
        app,
        ["export", "--all", "--out", str(destination)],
    )

    assert result.exit_code == 0
    assert service.calls == []
    assert not destination.exists()
    assert "Export cancelled." in result.output
    assert _KEY_ONE not in result.output


def test_sops_export_cancellation_constructs_no_sops_service_and_reads_no_keys(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "cancelled.enc.env"
    service = FakeExportService(f"TOKEN='{_KEY_ONE}'\n")
    _patch_export_boundary(monkeypatch, service)

    def reject_confirmation(_prompt: str) -> bool:
        return False

    monkeypatch.setattr(cli_module, "_confirm_mutation", reject_confirmation)
    monkeypatch.setattr(
        cli_module,
        "_sops_export_service",
        lambda: pytest.fail("SOPS must not be constructed before confirmation"),
    )

    result = CliRunner().invoke(
        app,
        ["export", "--all", "--sops-out", str(destination)],
    )

    assert result.exit_code == 0
    assert service.calls == []
    assert not destination.exists()
    assert "Export cancelled." in result.output


@pytest.mark.parametrize("output_option", ("--out", "--sops-out"))
def test_export_refuses_an_existing_destination_before_azure_access(
    output_option: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "existing.env"
    destination.write_text("EXISTING=must-remain\n", encoding="utf-8")
    monkeypatch.setattr(cli_module, "_resolve_subscription", _fail_subscription_resolution)

    result = CliRunner().invoke(
        app,
        ["export", "--all", output_option, str(destination), "--yes"],
    )

    assert result.exit_code == 1
    assert destination.read_text(encoding="utf-8") == "EXISTING=must-remain\n"
    assert "refusing to replace an existing dotenv export destination" in result.output


def test_export_rejects_a_missing_parent_before_azure_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "missing" / "keys.env"
    monkeypatch.setattr(cli_module, "_resolve_subscription", _fail_subscription_resolution)

    result = CliRunner().invoke(
        app,
        ["export", "--all", "--out", str(destination), "--yes"],
    )

    assert result.exit_code == 1
    assert not destination.exists()
    assert "missing or unsafe parent directory" in result.output


def test_export_requires_an_explicit_selection_without_a_controlling_terminal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli_module, "_interactive_terminal_available", lambda: False)
    monkeypatch.setattr(cli_module, "_resolve_subscription", _fail_subscription_resolution)

    result = CliRunner().invoke(
        app,
        ["export", "--out", str(tmp_path / "keys.env"), "--yes"],
    )

    assert result.exit_code == 1
    assert "use --select, --all, or --key-map instead" in result.output


@pytest.mark.parametrize(
    "failure",
    (
        ProviderOperationError("export-failed", f"provider included {_KEY_ONE}"),
        HttpResponseError(message=f"response included {_KEY_ONE}"),
        ServiceRequestError(f"request included {_KEY_ONE}"),
        ServiceResponseError(f"response included {_KEY_ONE}"),
    ),
)
def test_export_redacts_provider_and_transport_failures(
    failure: Exception,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "failed.env"
    service = FakeExportService("", failure)
    _patch_export_boundary(monkeypatch, service)

    result = CliRunner().invoke(
        app,
        ["export", "--all", "--out", str(destination), "--yes"],
    )

    assert result.exit_code == 1
    assert not destination.exists()
    assert "no file was created" in result.output
    assert _KEY_ONE not in result.output
    assert "Traceback" not in result.output


def test_export_redacts_authentication_failure_after_confirmation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "failed.env"
    service = FakeExportService("", CredentialUnavailableError(f"credential included {_KEY_ONE}"))
    _patch_export_boundary(monkeypatch, service)

    result = CliRunner().invoke(
        app,
        ["export", "--all", "--out", str(destination), "--yes"],
    )

    assert result.exit_code == 1
    assert not destination.exists()
    assert "authentication method is unavailable" in result.output
    assert _KEY_ONE not in result.output


def test_sops_export_validates_sops_before_retrieving_keys_and_redacts_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "failed.enc.env"
    key_service = FakeExportService(f"TOKEN='{_KEY_ONE}'\n")
    sops_service = FakeSopsExportService(validation_error=SopsError("synthetic", f"failure included {_KEY_ONE}"))
    _patch_export_boundary(monkeypatch, key_service)
    monkeypatch.setattr(cli_module, "_sops_export_service", lambda: sops_service)

    result = CliRunner().invoke(
        app,
        ["export", "--all", "--sops-out", str(destination), "--yes"],
    )

    assert result.exit_code == 1
    assert sops_service.validation_calls == 1
    assert key_service.calls == []
    assert not destination.exists()
    assert "SOPS could not create and verify" in result.output
    assert _KEY_ONE not in result.output


def test_sops_export_failure_after_retrieval_writes_no_file_and_redacts_details(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "failed.enc.env"
    key_service = FakeExportService(f"TOKEN='{_KEY_ONE}'\n")
    sops_service = FakeSopsExportService(encryption_error=SopsError("synthetic", f"failure included {_KEY_ONE}"))
    _patch_export_boundary(monkeypatch, key_service)
    monkeypatch.setattr(cli_module, "_sops_export_service", lambda: sops_service)

    result = CliRunner().invoke(
        app,
        ["export", "--all", "--sops-out", str(destination), "--yes"],
    )

    assert result.exit_code == 1
    assert len(key_service.calls) == 1
    assert not destination.exists()
    assert "SOPS could not create and verify" in result.output
    assert _KEY_ONE not in result.output


def test_export_loses_the_destination_race_without_replacing_the_winner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "raced.env"
    service = FakeExportService(f"TOKEN='{_KEY_ONE}'\n")
    _patch_export_boundary(monkeypatch, service)

    def lose_race(path: Path, content: str) -> None:
        assert path == destination.resolve()
        assert _KEY_ONE in content
        raise PrivateFileExistsError(f"winner included {_KEY_TWO}")

    monkeypatch.setattr(cli_module, "create_private_text", lose_race)

    result = CliRunner().invoke(
        app,
        ["export", "--all", "--out", str(destination), "--yes"],
    )

    assert result.exit_code == 1
    assert not destination.exists()
    assert "appeared concurrently" in result.output
    assert _KEY_ONE not in result.output
    assert _KEY_TWO not in result.output


def test_sops_export_loses_the_destination_race_without_replacing_the_winner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "raced.enc.env"
    key_service = FakeExportService(f"TOKEN='{_KEY_ONE}'\n")
    sops_service = FakeSopsExportService()
    _patch_export_boundary(monkeypatch, key_service)
    monkeypatch.setattr(cli_module, "_sops_export_service", lambda: sops_service)

    def lose_race(path: Path, content: bytes | bytearray) -> None:
        assert path == destination.resolve()
        assert bytes(content) == b"synthetic-sops-ciphertext"
        destination.write_bytes(b"winner-ciphertext")
        raise PrivateFileExistsError(f"winner included {_KEY_TWO}")

    monkeypatch.setattr(cli_module, "create_private_bytes", lose_race)

    result = CliRunner().invoke(
        app,
        ["export", "--all", "--sops-out", str(destination), "--yes"],
    )

    assert result.exit_code == 1
    assert destination.read_bytes() == b"winner-ciphertext"
    assert "appeared concurrently" in result.output
    assert _KEY_ONE not in result.output
    assert _KEY_TWO not in result.output

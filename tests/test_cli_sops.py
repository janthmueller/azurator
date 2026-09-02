"""Command-boundary tests for managed SOPS dotenv input."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

import azurator.cli as cli_module
from azurator.auth import SubscriptionSelection
from azurator.cli import app
from azurator.inputs import consume_dotenv
from azurator.models import RotationPlan
from azurator.providers.sops_dotenv_file import (
    attach_sops_dotenv_file_bindings,
    normalize_sops_dotenv_file_path,
)
from tests.cli_test_support import (
    SUBSCRIPTION_ID,
    SUBSCRIPTION_NAME,
    FakeExecutionService,
    patch_automatic_operation_path,
    patch_plan_boundary,
)


def _patch_sops_boundary(monkeypatch: pytest.MonkeyPatch, source: Path) -> None:
    patch_plan_boundary(monkeypatch)

    def resolve_subscription(_value: str | None) -> SubscriptionSelection:
        return SubscriptionSelection(SUBSCRIPTION_ID, SUBSCRIPTION_NAME, "tenant-id")

    monkeypatch.setattr(cli_module, "_resolve_subscription", resolve_subscription)

    def match_sops(
        subscription_id: str,
        path: Path,
        *,
        skip_azure_bindings: bool = False,
    ):
        assert subscription_id == SUBSCRIPTION_ID
        assert normalize_sops_dotenv_file_path(path) == source
        report = cli_module._match_dotenv(  # pyright: ignore[reportPrivateUsage]
            subscription_id,
            object(),  # type: ignore[arg-type]
            skip_azure_bindings=skip_azure_bindings,
        )
        return attach_sops_dotenv_file_bindings(report, source), source

    monkeypatch.setattr(cli_module, "_match_sops_dotenv_file", match_sops)


def _source(tmp_path: Path) -> Path:
    source = tmp_path / "secrets.enc.env"
    source.write_text("synthetic-ciphertext-without-key-values\n", encoding="utf-8")
    source.chmod(0o644)
    return source


def test_decrypted_sops_buffer_is_released_when_dotenv_parsing_finishes() -> None:
    stream = cli_module._EphemeralStringIO("TOKEN=temporary-secret\n")  # pyright: ignore[reportPrivateUsage]

    result = consume_dotenv(stream, lambda _selector, _value: None)

    assert result.selectors == ("TOKEN",)
    assert stream.closed


def test_match_sops_file_keeps_local_binding_when_azure_bindings_are_skipped(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _source(tmp_path)
    _patch_sops_boundary(monkeypatch, source)

    result = CliRunner().invoke(
        app,
        ["match", "--sops-file", str(source), "--skip-azure-bindings", "--json"],
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["azure_binding_inspection"] == "skipped"
    assert {binding["provider"] for binding in payload["bindings"]} == {"local-sops-dotenv-file"}
    assert {binding["location"] for binding in payload["bindings"]} == {"local"}
    assert {warning["code"] for warning in payload["warnings"]} >= {
        "azure-binding-inspection-skipped",
        "sops-file-managed-update",
    }
    assert "plan-input-secret" not in result.output

    readable = CliRunner().invoke(app, ["match", "--sops-file", str(source)])
    assert readable.exit_code == 0
    assert "SOPS dotenv assignments" in readable.stdout
    assert source.name in readable.stdout


def test_match_sops_file_writes_only_portable_key_map_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _source(tmp_path)
    destination = tmp_path / "azurator.keys.json"
    _patch_sops_boundary(monkeypatch, source)

    result = CliRunner().invoke(
        app,
        ["match", "--sops-file", str(source), "--key-map-out", str(destination)],
    )

    assert result.exit_code == 0
    payload = json.loads(destination.read_text(encoding="utf-8"))
    assert payload["subscription_id"] == SUBSCRIPTION_ID
    assert [mapping["selector"] for mapping in payload["mappings"]] == [
        "STORAGE_KEY",
        "SECOND_STORAGE_KEY",
    ]
    assert str(source) not in destination.read_text(encoding="utf-8")
    assert "source_path" not in payload


def test_plan_sops_file_persists_exact_encrypted_source_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _source(tmp_path)
    destination = tmp_path / "plan.json"
    _patch_sops_boundary(monkeypatch, source)

    result = CliRunner().invoke(app, ["plan", "--sops-file", str(source), "--out", str(destination)])

    assert result.exit_code == 0
    plan = RotationPlan.model_validate_json(destination.read_text(encoding="utf-8"))
    assert plan.source_format.value == "sops-dotenv-file"
    assert plan.source_path == str(source)
    assert {binding.provider for binding in plan.bindings if binding.location.value == "local"} == {
        "local-sops-dotenv-file"
    }
    assert "Managed SOPS dotenv file" in result.stdout
    assert result.stdout.count("may remain on a valid sibling key") == 1
    assert "plan-input-secret" not in destination.read_text(encoding="utf-8")


def test_direct_and_saved_plan_sops_rotation_use_the_same_plan_model(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _source(tmp_path)
    destination = tmp_path / "plan.json"
    _patch_sops_boundary(monkeypatch, source)
    operation_path = patch_automatic_operation_path(tmp_path, monkeypatch)
    direct_service = FakeExecutionService()

    def direct_execution_service(_subscription_id: str) -> FakeExecutionService:
        return direct_service

    monkeypatch.setattr(cli_module, "_execution_service", direct_execution_service)

    direct = CliRunner().invoke(app, ["-v", "rotate", "--sops-file", str(source), "--yes"])

    assert direct.exit_code == 0
    assert direct_service.started
    assert "Managed SOPS dotenv file" in direct.stdout
    assert "managed SOPS-encrypted dotenv assignments" in direct.stdout
    assert not operation_path.exists()

    planned = CliRunner().invoke(app, ["plan", "--sops-file", str(source), "--out", str(destination)])
    assert planned.exit_code == 0
    saved_service = FakeExecutionService()

    def saved_execution_service(_subscription_id: str) -> FakeExecutionService:
        return saved_service

    monkeypatch.setattr(cli_module, "_execution_service", saved_execution_service)

    saved = CliRunner().invoke(app, ["rotate", "--plan", str(destination), "--yes"])

    assert saved.exit_code == 0
    assert saved_service.started
    assert not operation_path.exists()


@pytest.mark.parametrize(
    "arguments",
    (
        ("--stdin",),
        ("--env-file", "plain.env"),
        ("--select", f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/X/y#key1"),
    ),
)
def test_sops_file_rejects_a_second_selection_source(
    tmp_path: Path,
    arguments: tuple[str, ...],
) -> None:
    source = _source(tmp_path)

    result = CliRunner().invoke(
        app,
        ["plan", "--sops-file", str(source), *arguments],
        input="TOKEN=must-not-render\n",
    )

    assert result.exit_code == 1
    assert "cannot be used together" in result.output
    assert "must-not-render" not in result.output


def test_plan_refuses_to_overwrite_sops_source(tmp_path: Path) -> None:
    source = _source(tmp_path)

    result = CliRunner().invoke(
        app,
        ["plan", "--sops-file", str(source), "--out", str(source)],
    )

    assert result.exit_code == 1
    assert "--out must not refer to the managed input file" in result.output

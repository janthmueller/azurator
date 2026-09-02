"""CLI matching and planning tests."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from azure.core.exceptions import HttpResponseError
from typer.core import TyperGroup, TyperOption
from typer.main import get_command
from typer.testing import CliRunner

import azurator.cli as cli_module
from azurator.auth import SubscriptionSelection
from azurator.cli import app
from azurator.models import (
    BindingInspection,
    BindingInspectionStatus,
    BindingLocation,
    BindingManagement,
    CredentialBinding,
    DiscoveryWarning,
    KeySlotSelection,
    MatchReport,
    ProviderInfo,
    WarningCategory,
    WarningImpact,
)
from tests.cli_test_support import (
    SUBSCRIPTION_ID,
    SUBSCRIPTION_NAME,
    make_ai_inventory,
    make_inventory,
    make_match_report,
    patch_direct_plan_boundary,
    patch_match_boundary,
    patch_plan_boundary,
)


def test_match_requires_explicit_stdin_mode() -> None:
    result = CliRunner().invoke(app, ["match"], input="TOKEN=must-not-render\n")

    assert result.exit_code == 1
    assert "--stdin" in result.output
    assert "must-not-render" not in result.output


def test_match_accepts_one_managed_dotenv_file_and_reports_assignments(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    patch_match_boundary(monkeypatch)
    source = tmp_path / "secrets.env"
    source.write_text("STORAGE_KEY=must-not-render\nSECOND_STORAGE_KEY=also-secret\n", encoding="utf-8")
    source.chmod(0o600)

    result = CliRunner().invoke(app, ["match", "--env-file", str(source)])

    assert result.exit_code == 0
    assert "Dotenv assignments" in result.stdout
    assert "2 assignments" in result.stdout
    assert "secrets.env" in result.stdout
    assert "STORAGE_KEY" in result.stdout
    assert "SECOND_STORAGE_KEY" in result.stdout
    assert "Plaintext dotenv file" not in result.stdout
    assert "The dotenv file has broad permissions" not in result.stderr
    assert "must-not-render" not in result.output
    assert "also-secret" not in result.output

    verbose = CliRunner().invoke(app, ["-v", "match", "--env-file", str(source)])

    assert verbose.exit_code == 0
    assert "Plaintext dotenv file" in verbose.stdout
    assert "Compared" in verbose.stdout
    assert "must-not-render" not in verbose.output
    assert "also-secret" not in verbose.output


def test_match_skip_azure_bindings_keeps_explicit_local_dotenv_bindings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    patch_match_boundary(monkeypatch)
    source = tmp_path / "secrets.env"
    source.write_text("STORAGE_KEY=must-not-render\n", encoding="utf-8")
    source.chmod(0o600)

    result = CliRunner().invoke(
        app,
        ["match", "--env-file", str(source), "--skip-azure-bindings", "--json"],
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["azure_binding_inspection"] == "skipped"
    assert {binding["location"] for binding in payload["bindings"]} == {"local"}
    assert {inspection["location"] for inspection in payload["binding_inspections"]} == {"local"}
    assert {warning["code"] for warning in payload["warnings"]} >= {
        "azure-binding-inspection-skipped",
        "dotenv-file-plaintext-at-rest",
    }
    assert "must-not-render" not in result.output

    readable = CliRunner().invoke(
        app,
        ["match", "--env-file", str(source), "--skip-azure-bindings"],
    )
    assert readable.exit_code == 0
    normalized_output = " ".join(readable.stdout.split())
    assert "Azure credential-binding inspection was skipped" in normalized_output
    assert "Explicit local bindings remain included" in normalized_output


def test_match_rejects_ambiguous_input_and_warns_for_broad_file_permissions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    patch_match_boundary(monkeypatch)
    source = tmp_path / "secrets.env"
    source.write_text("TOKEN=must-not-render\n", encoding="utf-8")
    source.chmod(0o600)

    exclusive = CliRunner().invoke(
        app,
        ["match", "--stdin", "--env-file", str(source)],
        input="TOKEN=other-secret\n",
    )
    assert exclusive.exit_code == 1
    assert "cannot be used together" in exclusive.output
    assert "must-not-render" not in exclusive.output
    assert "other-secret" not in exclusive.output

    if os.name != "nt":
        source.chmod(0o644)
        broad = CliRunner().invoke(
            app,
            ["match", "--subscription", SUBSCRIPTION_ID, "--env-file", str(source)],
        )
        assert broad.exit_code == 0
        assert broad.stderr.count("Warning: The dotenv file has broad permissions") == 1
        assert "Consider restricting access to the minimum required." in broad.stderr
        assert "broad permissions" not in broad.stdout
        assert "must-not-render" not in broad.output


def test_match_help_does_not_infer_a_security_state() -> None:
    root_command = get_command(app)
    assert isinstance(root_command, TyperGroup)
    match_command = root_command.commands["match"]
    option_names = {
        name
        for parameter in match_command.params
        if isinstance(parameter, TyperOption)
        for name in (*parameter.opts, *parameter.secondary_opts)
    }

    result = CliRunner().invoke(app, ["match", "--help"])

    assert result.exit_code == 0
    assert "--stdin" in option_names
    assert "--key-map-out" in option_names
    assert "--tokens-stdin" not in option_names
    assert "--input-format" not in option_names
    assert "compromised" not in result.output.casefold()


@pytest.mark.parametrize("arguments", (("--tokens-stdin",), ("--input-format", "dotenv")))
def test_match_rejects_removed_stdin_options(arguments: tuple[str, ...]) -> None:
    result = CliRunner().invoke(app, ["match", *arguments], input="TOKEN=must-not-render\n")

    assert result.exit_code != 0
    assert "No such option" in result.output
    assert "must-not-render" not in result.output


def test_match_renders_sparse_secret_free_results(monkeypatch: pytest.MonkeyPatch) -> None:
    patch_match_boundary(monkeypatch)

    result = CliRunner().invoke(
        app,
        ["match", "--stdin"],
        input="TOKEN=must-not-render\n",
    )

    assert result.exit_code == 0
    assert "Azure key matches" in result.stdout
    assert "2 matches" in result.stdout
    assert f"Subscription {SUBSCRIPTION_NAME} ({SUBSCRIPTION_ID})" in result.stdout
    assert "Compared" not in result.stdout
    assert "STORAGE_KEY" in result.stdout
    assert "SECOND_STORAGE_KEY" in result.stdout
    assert "account-a" in result.stdout
    assert "key1" in result.stdout
    assert "key2" in result.stdout
    assert "openai-a" in result.stdout
    assert "AI key access" in result.stdout
    assert "Foundry connections" in result.stdout
    assert "Foundry project" in result.stdout
    assert "Connection name" in result.stdout
    assert "Target key resource" in result.stdout
    assert "Stored key slot" in result.stdout
    assert "storage-a" in result.stdout
    assert "project-a" in result.stdout
    assert "AzureStorageAccount/AccountKey" not in result.stdout
    assert "AzureOpenAI/ApiKey" not in result.stdout
    assert "Other Storage binding categories were not inspected" not in result.stdout
    assert "Running workloads were not tested" not in " ".join(result.stdout.split())
    assert "Known Foundry bindings" not in result.stdout
    assert "observe only" not in result.stdout
    assert "separate Azure objects" not in result.stdout
    assert "test workloads" not in result.stdout
    assert "must-not-render" not in result.stdout
    assert "/subscriptions/" not in result.stdout

    verbose = CliRunner().invoke(
        app,
        ["-v", "match", "--stdin"],
        input="TOKEN=must-not-render\n",
    )

    assert verbose.exit_code == 0
    assert "Compared 3 input values with 2 Azure key slots across 1 key resource" in verbose.stdout
    assert "AzureStorageAccount/AccountKey" in verbose.stdout
    assert "Other Storage binding categories were not inspected" in verbose.stdout
    assert "Running workloads were not tested" in " ".join(verbose.stdout.split())
    assert "must-not-render" not in verbose.output


def test_match_renders_app_service_setting_bindings_without_values(monkeypatch: pytest.MonkeyPatch) -> None:
    patch_match_boundary(monkeypatch)
    base = make_match_report()
    storage_id = base.matches[0].resource_id
    app_id = f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/app-rg/providers/Microsoft.Web/sites/example-app"
    report = base.model_copy(
        update={
            "providers": (
                *base.providers,
                ProviderInfo(
                    name="azure-app-service-settings",
                    contract_version="1",
                    resource_types=("Microsoft.Web/sites/config/appsettings",),
                ),
            ),
            "binding_inspections": (
                *base.binding_inspections,
                BindingInspection(
                    resource_id=storage_id,
                    provider="azure-app-service-settings",
                    location=BindingLocation.azure,
                    status=BindingInspectionStatus.inspected,
                    scopes_inspected=1,
                ),
            ),
            "bindings": (
                *base.bindings,
                CredentialBinding(
                    binding_id="app-service-settings:binding-id",
                    name="STORAGE_KEY, STORAGE_ALIAS",
                    binding_type="Microsoft.Web/sites/config/appsettings",
                    provider="azure-app-service-settings",
                    location=BindingLocation.azure,
                    scope_id=app_id,
                    scope_name="example-app",
                    key_resource_id=storage_id,
                    key_slot="key1",
                    target=app_id,
                    selectors=("STORAGE_KEY", "STORAGE_ALIAS"),
                    management=BindingManagement.update_and_verify,
                ),
            ),
            "warnings": (
                *base.warnings,
                DiscoveryWarning(
                    code="app-service-settings-binding-coverage-limited",
                    message="Only exact whole application-setting values were inspected.",
                    impact=WarningImpact.confirmation,
                    category=WarningCategory.credential_binding,
                    provider="azure-app-service-settings",
                ),
                DiscoveryWarning(
                    code="app-service-settings-restart-and-concurrency",
                    message="Updating example-app restarts it and requires exclusive settings access.",
                    impact=WarningImpact.confirmation,
                    category=WarningCategory.credential_binding,
                    provider="azure-app-service-settings",
                    resource_id=app_id,
                ),
            ),
        }
    )

    def match_app_service(
        subscription_id: str,
        stream: object,
        *,
        skip_azure_bindings: bool = False,
    ) -> MatchReport:
        del subscription_id, stream, skip_azure_bindings
        return report

    monkeypatch.setattr(cli_module, "_match_dotenv", match_app_service)

    result = CliRunner().invoke(
        app,
        ["match", "--stdin"],
        input="TOKEN=must-not-render\n",
    )

    assert result.exit_code == 0
    normalized = " ".join(result.stdout.split())
    assert "App Service settings · 2 matched settings" in normalized
    assert "example-app" in result.stdout
    assert "STORAGE_KEY" in normalized
    assert "STORAGE_ALIAS" in normalized
    assert "Only exact whole application-setting values were inspected" not in normalized
    assert "restarts it and requires exclusive settings access" not in normalized
    assert "must-not-render" not in result.output
    assert app_id not in result.output

    verbose = CliRunner().invoke(
        app,
        ["-v", "match", "--stdin"],
        input="TOKEN=must-not-render\n",
    )
    verbose_normalized = " ".join(verbose.stdout.split())

    assert verbose.exit_code == 0
    assert "Only exact whole application-setting values were inspected" in verbose_normalized
    assert "restarts it and requires exclusive settings access" in verbose_normalized
    assert "must-not-render" not in verbose.output
    assert app_id not in verbose.output


def test_match_renders_optional_matrix(monkeypatch: pytest.MonkeyPatch) -> None:
    patch_match_boundary(monkeypatch)

    result = CliRunner().invoke(
        app,
        ["match", "--stdin", "--matrix"],
        input="TOKEN=must-not-render\n",
    )

    assert result.exit_code == 0
    assert "Input selector" in result.stdout
    assert "account-a" in result.stdout
    assert "openai-a" in result.stdout
    assert "unavailable" in result.stdout
    assert "STORAGE_KEY" in result.stdout
    assert "key1" in result.stdout
    assert "UNMATCHED" in result.stdout
    assert "must-not-render" not in result.stdout


def test_match_does_not_claim_no_bindings_when_inspection_is_incomplete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    patch_match_boundary(monkeypatch)
    base = make_match_report()
    report = base.model_copy(
        update={
            "bindings": (),
            "binding_inspections": tuple(
                inspection.model_copy(update={"status": BindingInspectionStatus.unavailable})
                for inspection in base.binding_inspections
            ),
        }
    )

    def match_incomplete(
        subscription_id: str,
        stream: object,
        *,
        skip_azure_bindings: bool = False,
    ) -> MatchReport:
        del subscription_id, stream, skip_azure_bindings
        return report

    monkeypatch.setattr(cli_module, "_match_dotenv", match_incomplete)

    result = CliRunner().invoke(
        app,
        ["match", "--stdin"],
        input="TOKEN=must-not-render\n",
    )

    assert result.exit_code == 0
    assert "Credential-binding inspection was incomplete for account-a" in result.stdout
    assert "No supported Foundry key connection was confirmed" not in result.stdout
    assert "No checked Foundry project connection targeted" not in result.stdout
    assert "must-not-render" not in result.stdout


def test_match_renders_complete_secret_free_json(monkeypatch: pytest.MonkeyPatch) -> None:
    patch_match_boundary(monkeypatch)

    result = CliRunner().invoke(
        app,
        ["match", "--stdin", "--json"],
        input="TOKEN=must-not-render\n",
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["subscription_name"] == SUBSCRIPTION_NAME
    assert payload["candidate_slots_compared"] == 2
    assert payload["schema_version"] == "1"
    assert payload["matches"][0] == {
        "input_selector": "STORAGE_KEY",
        "resource_id": payload["resources"][0]["resource_id"],
        "key_slot": "key1",
    }
    assert payload["bindings"][0]["name"] == "storage-a"
    assert payload["bindings"][0]["key_slot"] == "key1"
    assert payload["bindings"][0]["management"] == "update-and-verify"
    assert "must-not-render" not in result.stdout
    assert "fingerprint" not in result.stdout

    diagnostic = CliRunner().invoke(
        app,
        ["-vv", "match", "--stdin", "--json"],
        input="TOKEN=must-not-render\n",
    )
    assert diagnostic.exit_code == 0
    assert json.loads(diagnostic.stdout) == payload
    assert "must-not-render" not in diagnostic.output


def test_match_rejects_matrix_with_json_before_reading_values() -> None:
    result = CliRunner().invoke(
        app,
        ["match", "--stdin", "--matrix", "--json"],
        input="TOKEN=must-not-render\n",
    )

    assert result.exit_code == 1
    assert "cannot be used together" in result.output
    assert "must-not-render" not in result.output


def test_plan_requires_a_terminal_without_explicit_stdin_mode() -> None:
    result = CliRunner().invoke(app, ["plan"], input="TOKEN=must-not-render\n")

    assert result.exit_code == 1
    assert "requires a terminal" in result.output
    assert "--stdin" in result.output
    assert "must-not-render" not in result.output


def test_selection_number_parser_is_strict_and_deduplicates() -> None:
    assert cli_module._parse_selection_numbers("1, 3, 1", 3) == (0, 2)  # pyright: ignore[reportPrivateUsage]

    for invalid in ("", "1,", "zero", "0", "4"):
        with pytest.raises(ValueError):
            cli_module._parse_selection_numbers(invalid, 3)  # pyright: ignore[reportPrivateUsage]


def test_plan_interactively_selects_exact_slots_without_input_selectors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inspected = patch_direct_plan_boundary(monkeypatch)
    destination = tmp_path / "direct-plan.json"

    result = CliRunner().invoke(
        app,
        ["plan", "--out", str(destination)],
        input="1\n",
    )

    assert result.exit_code == 0
    payload = json.loads(destination.read_text(encoding="utf-8"))
    assert payload["source_format"] == "direct-selection"
    assert payload["source_selectors"] == []
    assert payload["scheduled_slots"] == [
        {
            "resource_id": make_inventory().resources[0].resource_id,
            "key_slot": "key1",
            "input_selectors": [],
        }
    ]
    assert inspected == [(KeySlotSelection(resource_id=make_inventory().resources[0].resource_id, key_slot="key1"),)]
    assert "Selected key slots" in result.stdout
    assert "Input selectors" not in result.stdout
    assert "azurator rotate --plan" not in " ".join(result.stdout.split())
    assert "--stdin" not in result.stdout
    assert "Plan scope" not in result.stdout
    assert "Azure AI key" not in result.stdout

    verbose_destination = tmp_path / "direct-plan-verbose.json"
    verbose = CliRunner().invoke(
        app,
        ["-v", "plan", "--out", str(verbose_destination)],
        input="1\n",
    )

    assert verbose.exit_code == 0
    assert "azurator rotate --plan" in " ".join(verbose.stdout.split())
    assert "Plan scope: 1 Storage Account key slot selected on 1 key resource" in verbose.stdout


def test_plan_review_mentions_only_selected_ai_provider_and_binding_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    patch_direct_plan_boundary(monkeypatch, make_ai_inventory())

    result = CliRunner().invoke(app, ["plan"], input="1\n")

    assert result.exit_code == 0
    assert "Rotation plan · 1 key slot, 1 step" in result.stdout
    assert "Azure bindings checked: Foundry project key connections" in result.stdout
    assert "Plan scope" not in result.stdout
    assert "AzureOpenAI/ApiKey" not in result.stdout
    assert "Other AI binding categories" not in " ".join(result.stdout.split())
    assert "workloads" not in result.stdout
    assert "Storage Account" not in result.stdout
    assert "AzureStorageAccount/AccountKey" not in result.stdout
    assert "use 'azurator rotate' with the same selection to continue" not in " ".join(result.stdout.split())

    verbose = CliRunner().invoke(app, ["-v", "plan"], input="1\n")

    assert verbose.exit_code == 0
    assert "Plan scope: 1 Azure AI key slot selected on 1 key resource" in verbose.stdout
    assert "AzureOpenAI/ApiKey" in verbose.stdout
    assert "Other AI binding categories" in " ".join(verbose.stdout.split())
    assert "workloads" in verbose.stdout
    assert "Preview only. No plan file was written." in verbose.stdout


def test_interactive_plan_keeps_picker_output_out_of_json_stdout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    patch_direct_plan_boundary(monkeypatch)

    result = CliRunner().invoke(
        app,
        ["plan", "--json"],
        input="2\n",
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["source_format"] == "direct-selection"
    assert payload["scheduled_slots"][0]["key_slot"] == "key2"
    assert "Select Azure key slots for rotation" not in result.stdout
    assert "Select Azure key slots for rotation" in result.stderr


def test_direct_plan_records_explicitly_skipped_azure_binding_inspection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    patch_direct_plan_boundary(monkeypatch)

    result = CliRunner().invoke(
        app,
        ["plan", "--skip-azure-bindings", "--json"],
        input="1\n",
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["azure_binding_inspection"] == "skipped"
    assert payload["binding_inspections"] == []
    assert payload["bindings"] == []
    assert payload["state"] == "confirmation-required"
    assert "azure-binding-inspection-skipped" in {warning["code"] for warning in payload["warnings"]}

    readable = CliRunner().invoke(
        app,
        ["plan", "--skip-azure-bindings"],
        input="1\n",
    )
    assert readable.exit_code == 0
    assert "Azure credential-binding inspection was skipped" in readable.stdout
    assert "local bindings" not in readable.stdout


def test_plan_writes_private_secret_free_json_and_renders_order(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    patch_plan_boundary(monkeypatch)
    destination = tmp_path / "plan.json"

    result = CliRunner().invoke(
        app,
        ["plan", "--stdin", "--out", str(destination)],
        input="TOKEN=must-not-render\n",
    )

    assert result.exit_code == 0
    payload = json.loads(destination.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "1"
    assert "plan_id" not in payload
    assert payload["tenant_id"] == "tenant-id"
    assert payload["subscription_id"] == SUBSCRIPTION_ID
    assert payload["subscription_name"] == SUBSCRIPTION_NAME
    assert payload["state"] == "confirmation-required"
    assert [(slot["key_slot"], slot["input_selectors"]) for slot in payload["scheduled_slots"]] == [
        ("key1", ["STORAGE_KEY"]),
        ("key2", ["SECOND_STORAGE_KEY"]),
    ]
    assert [step["action"] for step in payload["steps"]] == [
        "update-binding",
        "verify-binding",
        "regenerate-key",
        "update-binding",
        "verify-binding",
        "regenerate-key",
    ]
    assert all("actor" not in step for step in payload["steps"])
    assert payload["preconditions"][0]["subject"] == "planning-snapshot"
    assert len(payload["preconditions"][0]["digest"]) == 64
    if os.name != "nt":
        assert destination.stat().st_mode & 0o777 == 0o600

    assert "Rotation plan" in result.stdout
    assert "Rotation plan · 2 key slots, 6 steps" in result.stdout
    assert "Selected key slots" in result.stdout
    assert "Ordered steps" in result.stdout
    assert "Persist temporary bridge key" in result.stdout
    assert "Regenerate Azure key" in result.stdout
    assert " By " not in result.stdout
    assert "No Azure resource was changed" not in result.stdout
    assert "azurator rotate --plan" not in " ".join(result.stdout.split())
    assert "must-not-render" not in result.stdout
    assert "must-not-render" not in destination.read_text(encoding="utf-8")
    assert "fingerprint" not in destination.read_text(encoding="utf-8")


def test_plan_rejects_an_artifact_above_the_supported_size_before_writing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    patch_plan_boundary(monkeypatch)
    monkeypatch.setattr(cli_module, "_MAX_JSON_ARTIFACT_BYTES", 1)
    destination = tmp_path / "plan.json"

    result = CliRunner().invoke(
        app,
        ["plan", "--stdin", "--out", str(destination)],
        input="TOKEN=must-not-render\n",
    )

    assert result.exit_code == 1
    assert "private artifact size limit" in result.output
    assert not destination.exists()
    assert "must-not-render" not in result.output


def test_plan_manages_a_dotenv_file_without_persisting_its_values(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    patch_plan_boundary(monkeypatch)
    source = tmp_path / "secrets.env"
    source.write_text(
        "STORAGE_KEY=must-not-render\nSECOND_STORAGE_KEY=also-must-not-render\nUNMATCHED=leave-me\n",
        encoding="utf-8",
    )
    source.chmod(0o600)
    destination = tmp_path / "file-plan.json"

    result = CliRunner().invoke(
        app,
        ["plan", "--env-file", str(source), "--out", str(destination)],
    )

    assert result.exit_code == 0
    payload = json.loads(destination.read_text(encoding="utf-8"))
    assert payload["source_format"] == "dotenv-file"
    assert payload["source_path"] == str(source)
    assert payload["source_selectors"] == ["STORAGE_KEY", "SECOND_STORAGE_KEY", "UNMATCHED"]
    dotenv_bindings = [binding for binding in payload["bindings"] if binding["provider"] == "local-dotenv-file"]
    assert {tuple(binding["selectors"]) for binding in dotenv_bindings} == {
        ("STORAGE_KEY",),
        ("SECOND_STORAGE_KEY",),
    }
    assert "local-dotenv-file" in {provider["name"] for provider in payload["providers"]}
    assert "dotenv-file-plaintext-at-rest" in {warning["code"] for warning in payload["warnings"]}
    assert "Managed dotenv file" in result.stdout
    assert source.name in result.stdout
    assert result.stdout.count("may remain on a valid sibling key") == 1
    assert "azurator rotate --plan" not in " ".join(result.stdout.split())
    assert "--stdin" not in result.stdout
    serialized = destination.read_text(encoding="utf-8")
    assert "must-not-render" not in serialized
    assert "also-must-not-render" not in serialized


def test_dotenv_file_plan_preview_is_compact_by_default_and_explained_when_verbose(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    patch_plan_boundary(monkeypatch)
    source = tmp_path / "secrets.env"
    source.write_text("STORAGE_KEY=must-not-render\n", encoding="utf-8")
    source.chmod(0o600)

    result = CliRunner().invoke(app, ["plan", "--env-file", str(source)])

    assert result.exit_code == 0
    assert "Preview only" not in result.stdout
    assert "must-not-render" not in result.output

    verbose = CliRunner().invoke(app, ["-v", "plan", "--env-file", str(source)])

    assert verbose.exit_code == 0
    assert "Preview only. No plan file was written." in verbose.stdout
    assert "must-not-render" not in verbose.output


def test_plan_refuses_to_overwrite_managed_dotenv_source(tmp_path: Path) -> None:
    source = tmp_path / "secrets.env"
    original = "TOKEN=must-not-render\n"
    source.write_text(original, encoding="utf-8")
    source.chmod(0o600)

    result = CliRunner().invoke(
        app,
        ["plan", "--env-file", str(source), "--out", str(source)],
    )

    assert result.exit_code == 1
    assert "--out must not refer to the managed input file" in result.output
    assert source.read_text(encoding="utf-8") == original
    assert "must-not-render" not in result.output


def test_plan_rechecks_managed_dotenv_output_collision_before_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    patch_plan_boundary(monkeypatch)
    source = tmp_path / "secrets.env"
    destination = tmp_path / "plan.json"
    source.write_text("STORAGE_KEY=must-not-render\n", encoding="utf-8")
    source.chmod(0o600)
    collision_checks = iter((False, True))

    def collision_after_planning(first: Path, second: Path) -> bool:
        assert {first, second} == {source, destination}
        return next(collision_checks)

    monkeypatch.setattr(cli_module, "_paths_refer_to_same_file", collision_after_planning)

    result = CliRunner().invoke(
        app,
        ["plan", "--env-file", str(source), "--out", str(destination)],
    )

    assert result.exit_code == 1
    assert "--out must not refer to the managed input file" in result.output
    assert not destination.exists()
    assert "must-not-render" not in result.output


def test_plan_refuses_hardlink_alias_of_managed_dotenv_as_output(tmp_path: Path) -> None:
    source = tmp_path / "secrets.env"
    alias = tmp_path / "plan.json"
    original = "TOKEN=must-not-render\n"
    source.write_text(original, encoding="utf-8")
    source.chmod(0o600)
    try:
        os.link(source, alias)
    except OSError:
        pytest.skip("hard links are unavailable on this filesystem")

    result = CliRunner().invoke(
        app,
        ["plan", "--env-file", str(source), "--out", str(alias)],
    )

    assert result.exit_code == 1
    assert "--out must not refer to the managed input file" in result.output
    assert source.read_text(encoding="utf-8") == original
    assert alias.read_text(encoding="utf-8") == original
    assert "must-not-render" not in result.output


def test_plan_default_is_console_preview_without_a_file(monkeypatch: pytest.MonkeyPatch) -> None:
    patch_plan_boundary(monkeypatch)
    write_called = False

    def write_unexpected(path: Path, content: str) -> None:
        nonlocal write_called
        del path, content
        write_called = True

    monkeypatch.setattr(cli_module, "write_private_text", write_unexpected)

    result = CliRunner().invoke(
        app,
        ["plan", "--stdin"],
        input="TOKEN=must-not-render\n",
    )

    assert result.exit_code == 0
    assert write_called is False
    assert "Rotation plan" in result.stdout
    assert "Preview only" not in result.stdout
    assert "rerun this streamed plan with --out" not in result.stdout
    assert "Saved secret-free plan" not in result.stdout
    assert "must-not-render" not in result.stdout

    verbose = CliRunner().invoke(
        app,
        ["-v", "plan", "--stdin"],
        input="TOKEN=must-not-render\n",
    )
    assert verbose.exit_code == 0
    assert "Preview only. No plan file was written." in verbose.stdout
    assert "must-not-render" not in verbose.output


def test_complete_no_match_is_rendered_and_serialized_as_no_changes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    patch_plan_boundary(monkeypatch)
    base = make_match_report()
    storage_id = base.matches[0].resource_id
    no_match = base.model_copy(
        update={
            "resources": tuple(resource for resource in base.resources if resource.resource_id == storage_id),
            "inspections": tuple(inspection for inspection in base.inspections if inspection.resource_id == storage_id),
            "matches": (),
            "binding_inspections": (),
            "bindings": (),
            "warnings": tuple(warning for warning in base.warnings if warning.impact is WarningImpact.advisory),
        }
    )

    def match_no_values(
        subscription_id: str,
        stream: object,
        *,
        skip_azure_bindings: bool = False,
    ) -> MatchReport:
        del subscription_id, stream, skip_azure_bindings
        return no_match

    monkeypatch.setattr(cli_module, "_match_dotenv", match_no_values)

    rendered = CliRunner().invoke(app, ["plan", "--stdin"], input="TOKEN=must-not-render\n")
    structured = CliRunner().invoke(
        app,
        ["plan", "--stdin", "--json"],
        input="TOKEN=must-not-render\n",
    )

    assert rendered.exit_code == 0
    assert "Rotation plan · no changes" in rendered.stdout
    assert "No supplied value matched a supported Azure key slot" in rendered.stdout
    assert "not executable" not in rendered.stdout
    assert "must-not-render" not in rendered.stdout
    assert structured.exit_code == 0
    assert json.loads(structured.stdout)["state"] == "no-changes"
    assert "must-not-render" not in structured.stdout


def test_plan_does_not_present_failed_discovery_as_ready_no_match(monkeypatch: pytest.MonkeyPatch) -> None:
    patch_plan_boundary(monkeypatch)
    failed_report = make_match_report().model_copy(
        update={
            "resources": (),
            "inspections": (),
            "candidate_slots_compared": 0,
            "matches": (),
            "binding_inspections": (),
            "bindings": (),
            "warnings": (
                DiscoveryWarning(
                    code="storage-discovery-failed",
                    message=(
                        "Storage Account discovery failed with an Azure HTTP error. "
                        "No Storage key-returning operation was attempted."
                    ),
                    impact=WarningImpact.blocking,
                    category=WarningCategory.contract,
                    provider="azure-storage",
                ),
            ),
        }
    )

    def match_failed(
        subscription_id: str,
        stream: object,
        *,
        skip_azure_bindings: bool = False,
    ) -> MatchReport:
        del subscription_id, stream, skip_azure_bindings
        return failed_report

    monkeypatch.setattr(cli_module, "_match_dotenv", match_failed)

    result = CliRunner().invoke(
        app,
        ["plan", "--stdin"],
        input="TOKEN=must-not-render\n",
    )

    assert result.exit_code == 0
    assert "Rotation plan · blocked" in result.stdout
    assert "No executable rotation steps were generated" in result.stdout
    assert "No Azure key slot matched" not in result.stdout
    assert "Storage discovery failure" in result.stdout
    assert "must-not-render" not in result.stdout


def test_plan_json_prints_the_complete_plan_without_writing(monkeypatch: pytest.MonkeyPatch) -> None:
    patch_plan_boundary(monkeypatch)
    write_called = False

    def write_unexpected(path: Path, content: str) -> None:
        nonlocal write_called
        del path, content
        write_called = True

    monkeypatch.setattr(cli_module, "write_private_text", write_unexpected)

    result = CliRunner().invoke(
        app,
        ["plan", "--stdin", "--json"],
        input="TOKEN=must-not-render\n",
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == "1"
    assert payload["state"] == "confirmation-required"
    assert payload["subscription_name"] == SUBSCRIPTION_NAME
    assert write_called is False
    assert "Rotation plan" not in result.stdout
    assert "must-not-render" not in result.stdout


def test_plan_rejects_json_with_out_before_reading_values(tmp_path: Path) -> None:
    destination = tmp_path / "plan.json"

    result = CliRunner().invoke(
        app,
        ["plan", "--stdin", "--json", "--out", str(destination)],
        input="TOKEN=must-not-render\n",
    )

    assert result.exit_code == 1
    assert "cannot be used together" in result.output
    assert destination.exists() is False
    assert "must-not-render" not in result.output


def test_plan_requires_verified_tenant_scope_before_matching(monkeypatch: pytest.MonkeyPatch) -> None:
    called = False

    def resolve_subscription(value: str | None) -> SubscriptionSelection:
        del value
        return SubscriptionSelection(SUBSCRIPTION_ID, SUBSCRIPTION_NAME)

    def match_fake(subscription_id: str, stream: object) -> MatchReport:
        nonlocal called
        del subscription_id, stream
        called = True
        return make_match_report()

    monkeypatch.setattr(cli_module, "_resolve_plan_subscription", resolve_subscription)
    monkeypatch.setattr(cli_module, "_match_dotenv", match_fake)

    result = CliRunner().invoke(
        app,
        ["plan", "--stdin"],
        input="TOKEN=must-not-render\n",
    )

    assert result.exit_code == 1
    assert "tenant ID" in result.output
    assert "azurator login" in result.output
    assert called is False
    assert "must-not-render" not in result.output


def test_plan_refuses_symlink_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    patch_plan_boundary(monkeypatch)
    target = tmp_path / "target"
    target.write_text("unchanged", encoding="utf-8")
    link = tmp_path / "plan.json"
    link.symlink_to(target)

    result = CliRunner().invoke(
        app,
        ["plan", "--stdin", "--out", str(link)],
        input="TOKEN=must-not-render\n",
    )

    assert result.exit_code == 1
    assert "could not safely write" in result.output
    assert target.read_text(encoding="utf-8") == "unchanged"
    assert "must-not-render" not in result.output


def test_plan_http_failure_is_redacted(monkeypatch: pytest.MonkeyPatch) -> None:
    def resolve_subscription(value: str | None) -> SubscriptionSelection:
        del value
        return SubscriptionSelection(SUBSCRIPTION_ID, SUBSCRIPTION_NAME, "tenant-id")

    def fail_matching(
        subscription_id: str,
        stream: object,
        *,
        skip_azure_bindings: bool = False,
    ) -> MatchReport:
        del subscription_id, stream, skip_azure_bindings
        raise HttpResponseError(message="must-not-render")

    monkeypatch.setattr(cli_module, "_resolve_plan_subscription", resolve_subscription)
    monkeypatch.setattr(cli_module, "_match_dotenv", fail_matching)

    result = CliRunner().invoke(
        app,
        ["plan", "--stdin"],
        input="TOKEN=another-secret\n",
    )

    assert result.exit_code == 1
    assert "Azure rotation planning failed" in result.output
    assert "must-not-render" not in result.output
    assert "another-secret" not in result.output

"""CLI discovery, support-listing, login, and authentication tests."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
import typer
from azure.core.exceptions import ClientAuthenticationError, HttpResponseError
from azure.identity import AuthenticationRequiredError, CredentialUnavailableError
from typer.testing import CliRunner

import azurator.cli as cli_module
from azurator.auth import (
    AuthConfig,
    AuthConfigurationError,
    AuthMethod,
    AuthStore,
    LoginResult,
    SubscriptionSelection,
)
from azurator.cli import app
from azurator.models import (
    DiscoveryWarning,
    Inventory,
    KeyAuthentication,
    WarningCategory,
    WarningImpact,
)
from tests.cli_test_support import (
    SUBSCRIPTION_ID,
    SUBSCRIPTION_NAME,
    make_inventory,
)


def test_discover_rejects_invalid_subscription_override() -> None:
    runner = CliRunner()

    malformed = runner.invoke(app, ["discover", "--subscription", "not-a-uuid"])

    assert malformed.exit_code == 2
    assert "must be an Azure subscription UUID" in malformed.output


def test_discover_rejects_all_zero_subscription() -> None:
    result = CliRunner().invoke(
        app,
        ["discover", "--subscription", "00000000-0000-0000-0000-000000000000"],
    )

    assert result.exit_code == 2
    assert "all-zero UUID" in result.output


def test_discover_renders_machine_readable_json(monkeypatch: pytest.MonkeyPatch) -> None:
    selected: list[str] = []

    def discover_fake(subscription_id: str) -> Inventory:
        selected.append(subscription_id)
        return make_inventory(subscription_id)

    monkeypatch.setattr(cli_module, "_discover_inventory", discover_fake)

    result = CliRunner().invoke(
        app,
        ["discover", "--subscription", SUBSCRIPTION_ID, "--json"],
    )

    assert result.exit_code == 0
    assert selected == [SUBSCRIPTION_ID]
    payload = json.loads(result.stdout)
    assert payload["subscription_id"] == SUBSCRIPTION_ID
    assert payload["resources"][0]["key_authentication"] == "enabled"
    assert "coverage" not in payload["resources"][0]
    assert payload["resources"][0]["kind"] == "StorageV2"
    assert payload["resources"][0]["key_slots"][0]["name"] == "key1"
    assert "key_value" not in result.stdout


def test_discover_writes_private_json_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli_module, "_discover_inventory", make_inventory)
    destination = tmp_path / "inventory.json"

    result = CliRunner().invoke(
        app,
        [
            "discover",
            "--subscription",
            SUBSCRIPTION_ID,
            "--out",
            str(destination),
        ],
    )

    assert result.exit_code == 0
    assert json.loads(destination.read_text(encoding="utf-8"))["subscription_id"] == SUBSCRIPTION_ID
    if os.name != "nt":
        assert destination.stat().st_mode & 0o777 == 0o600


def test_discover_table_is_a_concise_human_summary(monkeypatch: pytest.MonkeyPatch) -> None:
    def resolve_subscription(value: str | None) -> SubscriptionSelection:
        assert value is None
        return SubscriptionSelection(SUBSCRIPTION_ID, SUBSCRIPTION_NAME)

    monkeypatch.setattr(cli_module, "_discover_inventory", make_inventory)
    monkeypatch.setattr(cli_module, "_resolve_subscription", resolve_subscription)

    result = CliRunner().invoke(app, ["discover"])

    assert result.exit_code == 0
    assert "Azure key resources" in result.stdout
    assert "Azure key resources · 1" in result.stdout
    assert f"Subscription {SUBSCRIPTION_NAME} ({SUBSCRIPTION_ID})" in result.stdout
    assert "account-a" in result.stdout
    assert "Storage Account" in result.stdout
    assert "westeurope" in result.stdout
    assert "Key authentication" in result.stdout
    assert "enabled" in result.stdout
    assert "Notes" in result.stdout
    assert "Coverage is limited to supported key-resource types" in result.stdout

    assert "StorageV2" not in result.stdout
    assert "Azure resource IDs" not in result.stdout
    assert "/resourceGroups/rg" not in result.stdout
    assert "metadata supported" not in result.stdout
    assert "No secret values were retrieved" not in result.stdout
    assert "Declared" not in result.stdout
    assert "provider-coverage-limited" not in result.stdout


def test_discover_table_includes_resources_with_key_authentication_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inventory = make_inventory()
    enabled = inventory.resources[0]
    disabled = enabled.model_copy(
        update={
            "resource_id": f"{enabled.resource_id.rsplit('/', 1)[0]}/disabled",
            "name": "account-disabled",
            "key_authentication": KeyAuthentication.disabled,
            "key_slots": tuple(
                slot.model_copy(update={"values_retrievable": False, "rotatable": False}) for slot in enabled.key_slots
            ),
        }
    )

    def discover_fake(subscription_id: str) -> Inventory:
        assert subscription_id == SUBSCRIPTION_ID
        return inventory.model_copy(update={"resources": (enabled, disabled)})

    def resolve_subscription(value: str | None) -> SubscriptionSelection:
        assert value is None
        return SubscriptionSelection(SUBSCRIPTION_ID, SUBSCRIPTION_NAME)

    monkeypatch.setattr(cli_module, "_discover_inventory", discover_fake)
    monkeypatch.setattr(cli_module, "_resolve_subscription", resolve_subscription)

    result = CliRunner().invoke(app, ["discover"])

    assert result.exit_code == 0
    assert "Azure key resources · 2" in result.stdout
    assert "account-a" in result.stdout
    assert "enabled" in result.stdout
    assert "account-disabled" in result.stdout
    assert "disabled" in result.stdout
    assert "Key slots" not in result.stdout


def test_discover_table_collapses_equivalent_provider_limitations(monkeypatch: pytest.MonkeyPatch) -> None:
    warnings = (
        DiscoveryWarning(
            code="provider-coverage-limited",
            message="Coverage is limited.",
            impact=WarningImpact.advisory,
            category=WarningCategory.coverage,
        ),
        DiscoveryWarning(
            code="storage-bindings-not-inspected",
            message="Storage bindings not inspected.",
            impact=WarningImpact.confirmation,
            category=WarningCategory.credential_binding,
        ),
        DiscoveryWarning(
            code="storage-key-permissions-not-tested",
            message="Storage permissions not tested.",
            impact=WarningImpact.advisory,
            category=WarningCategory.permission,
        ),
        DiscoveryWarning(
            code="cognitive-services-bindings-not-inspected",
            message="AI bindings not inspected.",
            impact=WarningImpact.confirmation,
            category=WarningCategory.credential_binding,
        ),
        DiscoveryWarning(
            code="cognitive-services-key-permissions-not-tested",
            message="AI permissions not tested.",
            impact=WarningImpact.advisory,
            category=WarningCategory.permission,
        ),
    )
    inventory = make_inventory().model_copy(update={"warnings": warnings})

    def discover_fake(subscription_id: str) -> Inventory:
        del subscription_id
        return inventory

    monkeypatch.setattr(cli_module, "_discover_inventory", discover_fake)

    result = CliRunner().invoke(
        app,
        ["discover", "--subscription", SUBSCRIPTION_ID],
        terminal_width=180,
    )

    assert result.exit_code == 0
    assert result.stdout.count("Credential bindings and key-operation permissions are not checked by discover") == 1
    assert "Storage bindings not inspected" not in result.stdout
    assert "AI bindings not inspected" not in result.stdout
    assert "storage-bindings-not-inspected" not in result.stdout
    assert "cognitive-services-bindings-not-inspected" not in result.stdout


def test_discover_table_keeps_actionable_provider_warnings(monkeypatch: pytest.MonkeyPatch) -> None:
    warning = DiscoveryWarning(
        code="storage-discovery-forbidden",
        message="Storage Account discovery failed with HTTP 403.",
        impact=WarningImpact.blocking,
        category=WarningCategory.contract,
    )
    inventory = make_inventory().model_copy(update={"warnings": (warning,)})

    def discover_fake(subscription_id: str) -> Inventory:
        del subscription_id
        return inventory

    monkeypatch.setattr(cli_module, "_discover_inventory", discover_fake)

    result = CliRunner().invoke(app, ["discover", "--subscription", SUBSCRIPTION_ID])

    assert result.exit_code == 0
    assert "Storage discovery permission" in result.stdout
    assert "Storage Account discovery failed with HTTP 403" in result.stdout
    assert "storage-discovery-forbidden" not in result.stdout


def test_native_login_failure_is_helpful_and_secret_free(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AZURATOR_CLIENT_ID", raising=False)

    result = CliRunner().invoke(app, ["login", "--method", "device-code"])

    assert result.exit_code == 1
    assert "registered public client" in result.output
    assert "Traceback" not in result.output


class FakeAuthenticator:
    def login(self, method: AuthMethod, **kwargs: object) -> LoginResult:
        del kwargs
        return LoginResult(
            method=method,
            tenant_id="tenant-id",
            subscription_id=SUBSCRIPTION_ID,
            subscription_name=SUBSCRIPTION_NAME,
        )

    def resolve_subscription(self, subscription_id: str | None = None) -> SubscriptionSelection:
        assert subscription_id is None
        return SubscriptionSelection(SUBSCRIPTION_ID, SUBSCRIPTION_NAME)

    def verify(self, subscription_id: str) -> AuthMethod:
        assert subscription_id == SUBSCRIPTION_ID
        return AuthMethod.device_code


def test_login_and_auth_status_render_safe_success(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeAuthenticator()
    monkeypatch.setattr(cli_module, "_authenticator", lambda: fake)
    runner = CliRunner()

    login_result = runner.invoke(app, ["login", "--method", "browser"])
    status_result = runner.invoke(app, ["auth", "status"])

    assert login_result.exit_code == 0
    assert "Authenticated with browser in tenant tenant-id" in login_result.stdout
    assert SUBSCRIPTION_NAME in login_result.stdout
    assert SUBSCRIPTION_ID in login_result.stdout
    assert status_result.exit_code == 0
    assert "ready via device-code" in status_result.stdout
    assert f"{SUBSCRIPTION_NAME} ({SUBSCRIPTION_ID})" in status_result.stdout

    json_result = runner.invoke(app, ["auth", "status", "--json"])
    assert json_result.exit_code == 0
    assert json.loads(json_result.stdout) == {
        "schema_version": "1",
        "method": "device-code",
        "subscription_id": SUBSCRIPTION_ID,
        "subscription_name": SUBSCRIPTION_NAME,
        "tenant_id": None,
        "ready": True,
    }


def test_auth_clear_only_removes_the_azurator_record(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = AuthStore(tmp_path / "auth.json")
    store.save(AuthConfig(method=AuthMethod.azure_cli, subscription_id=SUBSCRIPTION_ID))
    monkeypatch.setattr(cli_module, "_auth_store", lambda: store)

    removed = CliRunner().invoke(app, ["auth", "clear"])
    absent = CliRunner().invoke(app, ["auth", "clear"])

    assert removed.exit_code == 0
    assert "Cleared Azurator's saved authentication selection" in removed.stdout
    assert "Azure CLI sign-in was not changed" in removed.stdout
    assert absent.exit_code == 0
    assert "No saved" in absent.stdout


def test_discover_uses_subscription_pinned_at_login(monkeypatch: pytest.MonkeyPatch) -> None:
    selected: list[str] = []

    def discover_fake(subscription_id: str) -> Inventory:
        selected.append(subscription_id)
        return make_inventory(subscription_id)

    monkeypatch.setattr(cli_module, "_authenticator", lambda: FakeAuthenticator())
    monkeypatch.setattr(cli_module, "_discover_inventory", discover_fake)

    result = CliRunner().invoke(app, ["discover", "--json"])

    assert result.exit_code == 0
    assert selected == [SUBSCRIPTION_ID]
    payload = json.loads(result.stdout)
    assert payload["subscription_id"] == SUBSCRIPTION_ID
    assert payload["subscription_name"] == SUBSCRIPTION_NAME


def test_discover_reports_when_login_has_no_subscription(monkeypatch: pytest.MonkeyPatch) -> None:
    class MissingSubscriptionAuthenticator:
        def resolve_subscription(self, subscription_id: str | None = None) -> SubscriptionSelection:
            del subscription_id
            raise AuthConfigurationError("no Azure subscription is selected")

    monkeypatch.setattr(cli_module, "_authenticator", lambda: MissingSubscriptionAuthenticator())

    result = CliRunner().invoke(app, ["discover"])

    assert result.exit_code == 1
    assert "no Azure subscription is selected" in result.output
    assert "Traceback" not in result.output


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (AuthenticationRequiredError(scopes=("scope",)), "requires interaction"),
        (CredentialUnavailableError("sensitive-detail"), "method is unavailable"),
        (ClientAuthenticationError("sensitive-detail"), "authentication failed"),
        (AuthConfigurationError("safe configuration message"), "safe configuration message"),
        (RuntimeError("sensitive-detail"), "response details were suppressed"),
    ],
)
def test_authentication_errors_are_mapped_without_provider_details(
    error: BaseException,
    expected: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(typer.Exit):
        cli_module._authentication_failure(error)  # pyright: ignore[reportPrivateUsage]

    output = capsys.readouterr().err
    assert expected in output
    if not isinstance(error, AuthConfigurationError):
        assert "sensitive-detail" not in output


def test_discovery_http_failure_is_redacted(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_discovery(subscription_id: str) -> Inventory:
        del subscription_id
        raise HttpResponseError(message="do-not-render")

    monkeypatch.setattr(cli_module, "_discover_inventory", fail_discovery)

    result = CliRunner().invoke(app, ["discover", "--subscription", SUBSCRIPTION_ID])

    assert result.exit_code == 1
    assert "response details were suppressed" in result.output
    assert "do-not-render" not in result.output


def test_discover_refuses_symlink_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli_module, "_discover_inventory", make_inventory)
    target = tmp_path / "target"
    target.write_text("unchanged", encoding="utf-8")
    link = tmp_path / "inventory.json"
    link.symlink_to(target)

    result = CliRunner().invoke(
        app,
        ["discover", "--subscription", SUBSCRIPTION_ID, "--out", str(link)],
    )

    assert result.exit_code == 1
    assert "could not safely write" in result.output
    assert target.read_text(encoding="utf-8") == "unchanged"


def test_list_groups_supported_key_resources_and_bindings_without_authentication(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_if_called() -> None:
        raise AssertionError("support listing must not construct an authenticator")

    monkeypatch.setattr(cli_module, "_authenticator", fail_if_called)

    result = CliRunner().invoke(app, ["list"])

    assert result.exit_code == 0
    assert "Supported key resources" in result.stdout
    assert "Supported key resources · 2" in result.stdout
    assert "Supported credential bindings" in result.stdout
    assert "Supported credential bindings · 4" in result.stdout
    assert "provider" not in result.stdout.casefold()
    assert "contract version" not in result.stdout.casefold()
    assert "Azure AI, Cognitive Services, and Azure OpenAI" in result.stdout
    assert "Microsoft.CognitiveServices/accounts" in result.stdout
    assert "Storage Account" in result.stdout
    assert "Microsoft.Storage/storageAccounts" in result.stdout
    assert "Foundry project connections" in result.stdout
    assert "App Service application settings" in result.stdout
    assert "Plaintext dotenv assignments" in result.stdout
    assert "--env-file" in result.stdout
    assert "SOPS-encrypted dotenv assignments" in result.stdout
    assert "--sops-file" in result.stdout


@pytest.mark.parametrize(
    ("options", "shows_key_resources", "shows_bindings"),
    (
        (("--key-resources",), True, False),
        (("--bindings",), False, True),
        (("--key-resources", "--bindings"), True, True),
    ),
)
def test_list_filters_domain_sections(
    options: tuple[str, ...],
    shows_key_resources: bool,
    shows_bindings: bool,
) -> None:
    result = CliRunner().invoke(app, ["list", *options])

    assert result.exit_code == 0
    assert ("Supported key resources" in result.stdout) is shows_key_resources
    assert ("Supported credential bindings" in result.stdout) is shows_bindings


def test_list_supports_structured_domain_output() -> None:
    result = CliRunner().invoke(app, ["list", "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == "1"
    assert [resource["name"] for resource in payload["key_resources"]] == [
        "Storage Account",
        "Azure AI, Cognitive Services, and Azure OpenAI",
    ]
    assert payload["key_resources"][0] == {
        "name": "Storage Account",
        "resource_type": "Microsoft.Storage/storageAccounts",
        "key_slots": ["key1", "key2"],
        "operations": ["discover", "match", "export", "rotate"],
        "contract_id": "azure-storage",
        "contract_version": "1",
    }
    assert [binding["name"] for binding in payload["credential_bindings"]] == [
        "Foundry project connections",
        "App Service application settings",
        "Plaintext dotenv assignments",
        "SOPS-encrypted dotenv assignments",
    ]
    assert payload["credential_bindings"][0]["included_by"] == "automatic"
    assert payload["credential_bindings"][0]["location"] == "azure"
    assert (
        payload["credential_bindings"][0]["binding_type"] == "Microsoft.CognitiveServices/accounts/projects/connections"
    )
    assert payload["credential_bindings"][0]["management"] == "update-and-verify"
    assert payload["credential_bindings"][2]["included_by"] == "--env-file"
    assert payload["credential_bindings"][2]["contract_id"] == "local-dotenv-file"


def test_list_json_filters_keep_one_stable_object_shape() -> None:
    resources = CliRunner().invoke(app, ["list", "--key-resources", "--json"])
    bindings = CliRunner().invoke(app, ["list", "--bindings", "--json"])

    assert resources.exit_code == 0
    assert bindings.exit_code == 0
    resource_payload = json.loads(resources.stdout)
    binding_payload = json.loads(bindings.stdout)
    assert len(resource_payload["key_resources"]) == 2
    assert resource_payload["credential_bindings"] == []
    assert binding_payload["key_resources"] == []
    assert len(binding_payload["credential_bindings"]) == 4


def test_obsolete_providers_command_is_not_retained() -> None:
    result = CliRunner().invoke(app, ["providers"])

    assert result.exit_code == 2
    assert "No such command 'providers'" in result.output

"""Tests for authentication selection and private session metadata."""

from __future__ import annotations

import os
from collections.abc import Sequence
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest
from azure.core.credentials import AccessToken, TokenCredential
from azure.identity import AuthenticationRecord

import azurator.auth as auth_module
from azurator.auth import (
    ARM_SCOPE,
    AuthConfig,
    AuthConfigurationError,
    Authenticator,
    AuthLoginError,
    AuthMetadataRefreshError,
    AuthMethod,
    AuthStore,
    CredentialFactory,
    SubscriptionSelection,
)

SUBSCRIPTION_ID = "11111111-1111-1111-1111-111111111111"
OTHER_SUBSCRIPTION_ID = "22222222-2222-2222-2222-222222222222"
TENANT_ID = "33333333-3333-3333-3333-333333333333"
OTHER_TENANT_ID = "44444444-4444-4444-4444-444444444444"
TENANT_DOMAIN = "example.onmicrosoft.com"
SUBSCRIPTION_NAME = "Example Production"


class FakeTokenCredential(TokenCredential):
    def __init__(self) -> None:
        self.scopes: list[tuple[str, ...]] = []

    def get_token(
        self,
        *scopes: str,
        claims: str | None = None,
        tenant_id: str | None = None,
        enable_cae: bool = False,
        **kwargs: Any,
    ) -> AccessToken:
        del claims, tenant_id, enable_cae, kwargs
        self.scopes.append(scopes)
        return AccessToken("not-a-real-token", 4_102_444_800)


class FakeInteractiveCredential(FakeTokenCredential):
    def __init__(self, record: AuthenticationRecord) -> None:
        super().__init__()
        self.record = record
        self.authenticate_scopes: tuple[str, ...] = ()
        self.closed = False

    def authenticate(self, *, scopes: tuple[str, ...]) -> AuthenticationRecord:
        self.authenticate_scopes = scopes
        return self.record

    def close(self) -> None:
        self.closed = True


def _record() -> AuthenticationRecord:
    return AuthenticationRecord(
        tenant_id="tenant-id",
        client_id="client-id",
        authority="login.microsoftonline.com",
        home_account_id="home-account-id",
        username="operator@example.invalid",
    )


def test_auth_store_round_trip_uses_private_permissions(tmp_path: Path) -> None:
    store = AuthStore(tmp_path / "auth.json")
    config = AuthConfig(
        method=AuthMethod.azure_cli,
        tenant_id=TENANT_ID,
        subscription_id=SUBSCRIPTION_ID,
        subscription_name=SUBSCRIPTION_NAME,
    )

    store.save(config)

    assert store.load() == config
    if os.name != "nt":
        assert store.path.stat().st_mode & 0o777 == 0o600


def test_auth_store_clear_removes_only_an_existing_private_record(tmp_path: Path) -> None:
    store = AuthStore(tmp_path / "auth.json")
    store.save(AuthConfig(method=AuthMethod.azure_cli, subscription_id=SUBSCRIPTION_ID))

    assert store.clear()
    assert not store.path.exists()
    assert not store.clear()


def test_auth_store_clear_rejects_an_unsafe_record(tmp_path: Path) -> None:
    store = AuthStore(tmp_path / "auth.json")
    target = tmp_path / "target.json"
    target.write_text("unchanged", encoding="utf-8")
    store.path.symlink_to(target)

    with pytest.raises(AuthConfigurationError, match="removed safely"):
        store.clear()

    assert target.read_text(encoding="utf-8") == "unchanged"


def test_auth_store_rejects_overly_permissive_metadata(tmp_path: Path) -> None:
    store = AuthStore(tmp_path / "auth.json")
    store.path.write_text(AuthConfig(method=AuthMethod.azure_cli).model_dump_json(), encoding="utf-8")
    store.path.chmod(0o644)

    if os.name == "nt":
        assert store.load() is not None
    else:
        with pytest.raises(AuthConfigurationError):
            store.load()


def test_auth_store_rejects_symlink_and_malformed_json(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    target.chmod(0o600)
    link_store = AuthStore(tmp_path / "auth.json")
    link_store.path.symlink_to(target)

    with pytest.raises(AuthConfigurationError, match="unsafe or unreadable"):
        link_store.load()

    malformed_store = AuthStore(tmp_path / "malformed.json")
    malformed_store.path.write_text("not-json", encoding="utf-8")
    malformed_store.path.chmod(0o600)
    with pytest.raises(AuthConfigurationError, match="malformed"):
        malformed_store.load()


def test_auth_store_rejects_an_unsupported_schema_version(tmp_path: Path) -> None:
    store = AuthStore(tmp_path / "auth.json")
    store.path.write_text('{"schema_version": 2, "method": "azure-cli"}', encoding="utf-8")
    store.path.chmod(0o600)

    with pytest.raises(AuthConfigurationError, match="malformed"):
        store.load()


def test_auth_store_wraps_unsafe_save(tmp_path: Path) -> None:
    store = AuthStore(tmp_path)

    with pytest.raises(AuthConfigurationError, match="safely persist"):
        store.save(AuthConfig(method=AuthMethod.azure_cli))


def test_default_credential_reuses_azure_cli_for_selected_subscription(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created: list[dict[str, object]] = []
    credential = FakeTokenCredential()

    def build_cli_credential(**kwargs: object) -> FakeTokenCredential:
        created.append(kwargs)
        return credential

    monkeypatch.setattr(auth_module, "AzureCliCredential", build_cli_credential)

    selected = CredentialFactory(AuthStore(tmp_path / "missing.json")).create(SUBSCRIPTION_ID)

    assert selected is credential
    assert created == [{"subscription": SUBSCRIPTION_ID, "process_timeout": 30}]
    assert CredentialFactory(AuthStore(tmp_path / "missing.json")).active_method() is AuthMethod.azure_cli


def test_azure_cli_credential_uses_subscription_instead_of_saved_tenant(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created: list[dict[str, object]] = []
    credential = FakeTokenCredential()

    def build_cli_credential(**kwargs: object) -> FakeTokenCredential:
        created.append(kwargs)
        return credential

    monkeypatch.setattr(auth_module, "AzureCliCredential", build_cli_credential)
    store = AuthStore(tmp_path / "auth.json")
    store.save(
        AuthConfig(
            method=AuthMethod.azure_cli,
            tenant_id=TENANT_ID,
            subscription_id=SUBSCRIPTION_ID,
        )
    )

    assert CredentialFactory(store).create() is credential
    assert created == [{"subscription": SUBSCRIPTION_ID, "process_timeout": 30}]


def test_factory_recreates_environment_and_native_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = FakeTokenCredential()
    native = FakeTokenCredential()
    native_arguments: list[dict[str, object]] = []

    def build_environment() -> FakeTokenCredential:
        return environment

    def build_native(**kwargs: object) -> FakeTokenCredential:
        native_arguments.append(kwargs)
        return native

    monkeypatch.setattr(auth_module, "EnvironmentCredential", build_environment)
    monkeypatch.setattr(auth_module, "InteractiveBrowserCredential", build_native)
    store = AuthStore(tmp_path / "auth.json")
    factory = CredentialFactory(store)

    assert factory.create_from_config(AuthConfig(method=AuthMethod.environment)) is environment
    browser_config = AuthConfig(
        method=AuthMethod.browser,
        client_id="client-id",
        authentication_record=_record().serialize(),
    )
    assert factory.create_from_config(browser_config) is native
    assert native_arguments[0]["disable_automatic_authentication"] is True
    assert native_arguments[0]["tenant_id"] == "tenant-id"


def test_factory_rejects_incomplete_and_malformed_native_metadata(tmp_path: Path) -> None:
    factory = CredentialFactory(AuthStore(tmp_path / "auth.json"))

    with pytest.raises(AuthConfigurationError, match="incomplete"):
        factory.create_from_config(AuthConfig(method=AuthMethod.browser))
    with pytest.raises(AuthConfigurationError, match="malformed"):
        factory.create_from_config(
            AuthConfig(method=AuthMethod.device_code, client_id="client-id", authentication_record="not-json")
        )


@pytest.mark.parametrize(
    "config",
    (
        AuthConfig(
            method=AuthMethod.browser,
            client_id="different-client-id",
            authentication_record=_record().serialize(),
        ),
        AuthConfig(
            method=AuthMethod.browser,
            tenant_id="different-tenant-id",
            client_id="client-id",
            authentication_record=_record().serialize(),
        ),
    ),
)
def test_factory_rejects_native_metadata_that_disagrees_with_the_account_record(
    tmp_path: Path,
    config: AuthConfig,
) -> None:
    with pytest.raises(AuthConfigurationError, match="disagrees"):
        CredentialFactory(AuthStore(tmp_path / "auth.json")).create_from_config(config)


def test_azure_cli_login_supports_device_code_and_saves_selection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commands: list[tuple[str, ...]] = []
    credential = FakeTokenCredential()

    def run_cli(arguments: Sequence[str]) -> int:
        commands.append(tuple(arguments))
        return 0

    def build_cli_credential(**kwargs: object) -> FakeTokenCredential:
        assert kwargs["subscription"] == SUBSCRIPTION_ID
        return credential

    def resolve_subscription(subscription_id: str | None) -> SubscriptionSelection:
        assert subscription_id == SUBSCRIPTION_ID
        return SubscriptionSelection(SUBSCRIPTION_ID, SUBSCRIPTION_NAME, TENANT_ID)

    monkeypatch.setattr(auth_module, "AzureCliCredential", build_cli_credential)
    store = AuthStore(tmp_path / "auth.json")
    authenticator = Authenticator(
        store,
        cli_runner=run_cli,
        cli_subscription_resolver=resolve_subscription,
    )

    result = authenticator.login(
        AuthMethod.azure_cli,
        tenant_id=TENANT_DOMAIN,
        subscription_id=SUBSCRIPTION_ID,
        use_device_code=True,
    )

    assert result.method is AuthMethod.azure_cli
    assert result.subscription_id == SUBSCRIPTION_ID
    assert result.subscription_name == SUBSCRIPTION_NAME
    assert commands == [("az", "login", "--output", "none", "--tenant", TENANT_DOMAIN, "--use-device-code")]
    assert credential.scopes == [(ARM_SCOPE,)]
    assert store.load() == AuthConfig(
        method=AuthMethod.azure_cli,
        tenant_id=TENANT_ID,
        subscription_id=SUBSCRIPTION_ID,
        subscription_name=SUBSCRIPTION_NAME,
    )


def test_azure_cli_login_captures_selected_default_subscription(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    credential = FakeTokenCredential()

    def build_cli_credential(**kwargs: object) -> FakeTokenCredential:
        del kwargs
        return credential

    monkeypatch.setattr(auth_module, "AzureCliCredential", build_cli_credential)
    store = AuthStore(tmp_path / "auth.json")
    authenticator = Authenticator(
        store,
        cli_runner=lambda arguments: 0,
        cli_subscription_resolver=lambda subscription_id: SubscriptionSelection(
            SUBSCRIPTION_ID,
            SUBSCRIPTION_NAME,
            TENANT_ID,
        ),
    )

    result = authenticator.login(AuthMethod.azure_cli)

    assert result.subscription_id == SUBSCRIPTION_ID
    assert result.subscription_name == SUBSCRIPTION_NAME
    assert result.tenant_id == TENANT_ID
    assert store.load() == AuthConfig(
        method=AuthMethod.azure_cli,
        tenant_id=TENANT_ID,
        subscription_id=SUBSCRIPTION_ID,
        subscription_name=SUBSCRIPTION_NAME,
    )
    assert credential.scopes == [(ARM_SCOPE,)]


def test_azure_cli_login_rejects_a_subscription_from_another_explicit_tenant(tmp_path: Path) -> None:
    store = AuthStore(tmp_path / "auth.json")
    authenticator = Authenticator(
        store,
        cli_runner=lambda arguments: 0,
        cli_subscription_resolver=lambda subscription_id: SubscriptionSelection(
            SUBSCRIPTION_ID,
            SUBSCRIPTION_NAME,
            TENANT_ID,
        ),
    )

    with pytest.raises(AuthConfigurationError, match="different Azure tenant"):
        authenticator.login(
            AuthMethod.azure_cli,
            tenant_id=OTHER_TENANT_ID,
            subscription_id=SUBSCRIPTION_ID,
        )

    assert store.load() is None


def test_selected_subscription_adds_name_to_an_existing_azure_cli_record(tmp_path: Path) -> None:
    store = AuthStore(tmp_path / "auth.json")
    store.save(
        AuthConfig(
            method=AuthMethod.azure_cli,
            tenant_id=TENANT_ID,
            subscription_id=SUBSCRIPTION_ID,
        )
    )

    def resolve_subscription(subscription_id: str | None) -> SubscriptionSelection:
        assert subscription_id == SUBSCRIPTION_ID
        return SubscriptionSelection(SUBSCRIPTION_ID, SUBSCRIPTION_NAME, TENANT_ID)

    authenticator = Authenticator(store, cli_subscription_resolver=resolve_subscription)

    assert authenticator.selected_subscription() == SubscriptionSelection(
        SUBSCRIPTION_ID,
        SUBSCRIPTION_NAME,
        TENANT_ID,
    )
    assert store.load() == AuthConfig(
        method=AuthMethod.azure_cli,
        tenant_id=TENANT_ID,
        subscription_id=SUBSCRIPTION_ID,
        subscription_name=SUBSCRIPTION_NAME,
    )


def test_selected_subscription_keeps_validated_scope_when_name_refresh_is_unavailable(tmp_path: Path) -> None:
    config = AuthConfig(method=AuthMethod.azure_cli, tenant_id=TENANT_ID, subscription_id=SUBSCRIPTION_ID)
    store = AuthStore(tmp_path / "auth.json")
    store.save(config)

    def unavailable_name_refresh(subscription_id: str | None) -> SubscriptionSelection:
        assert subscription_id == SUBSCRIPTION_ID
        raise AuthMetadataRefreshError("Azure CLI metadata unavailable")

    selection = Authenticator(store, cli_subscription_resolver=unavailable_name_refresh).selected_subscription()

    assert selection == SubscriptionSelection(SUBSCRIPTION_ID, tenant_id=TENANT_ID)
    assert store.load() == config


def test_selected_subscription_requires_tenant_when_metadata_refresh_is_unavailable(tmp_path: Path) -> None:
    store = AuthStore(tmp_path / "auth.json")
    store.save(AuthConfig(method=AuthMethod.azure_cli, subscription_id=SUBSCRIPTION_ID))

    def unavailable_metadata(subscription_id: str | None) -> SubscriptionSelection:
        assert subscription_id == SUBSCRIPTION_ID
        raise AuthMetadataRefreshError("Azure CLI metadata unavailable")

    with pytest.raises(AuthConfigurationError, match="tenant metadata is unavailable"):
        Authenticator(store, cli_subscription_resolver=unavailable_metadata).selected_subscription()


def test_selected_subscription_does_not_hide_invalid_refreshed_metadata(tmp_path: Path) -> None:
    store = AuthStore(tmp_path / "auth.json")
    store.save(AuthConfig(method=AuthMethod.azure_cli, tenant_id=TENANT_ID, subscription_id=SUBSCRIPTION_ID))

    def invalid_metadata(subscription_id: str | None) -> SubscriptionSelection:
        assert subscription_id == SUBSCRIPTION_ID
        raise AuthConfigurationError("Azure CLI returned invalid subscription metadata")

    with pytest.raises(AuthConfigurationError, match="invalid subscription metadata"):
        Authenticator(store, cli_subscription_resolver=invalid_metadata).selected_subscription()


def test_resolve_subscription_uses_complete_pinned_cli_scope_without_refresh(tmp_path: Path) -> None:
    store = AuthStore(tmp_path / "auth.json")
    store.save(
        AuthConfig(
            method=AuthMethod.azure_cli,
            tenant_id=TENANT_ID,
            subscription_id=SUBSCRIPTION_ID,
            subscription_name=SUBSCRIPTION_NAME,
        )
    )

    def unexpected_refresh(subscription_id: str | None) -> SubscriptionSelection:
        pytest.fail(f"unexpected Azure CLI refresh for {subscription_id}")

    selection = Authenticator(store, cli_subscription_resolver=unexpected_refresh).resolve_subscription(SUBSCRIPTION_ID)

    assert selection == SubscriptionSelection(SUBSCRIPTION_ID, SUBSCRIPTION_NAME, TENANT_ID)


def test_resolve_subscription_refreshes_and_persists_incomplete_cli_metadata(tmp_path: Path) -> None:
    store = AuthStore(tmp_path / "auth.json")
    store.save(AuthConfig(method=AuthMethod.azure_cli, subscription_id=SUBSCRIPTION_ID))

    def refresh(subscription_id: str | None) -> SubscriptionSelection:
        assert subscription_id == SUBSCRIPTION_ID
        return SubscriptionSelection(SUBSCRIPTION_ID.upper(), f"  {SUBSCRIPTION_NAME}  ", TENANT_ID.upper())

    selection = Authenticator(store, cli_subscription_resolver=refresh).resolve_subscription(SUBSCRIPTION_ID)

    assert selection == SubscriptionSelection(SUBSCRIPTION_ID, SUBSCRIPTION_NAME, TENANT_ID)
    saved = store.load()
    assert saved is not None
    assert saved.subscription_name == SUBSCRIPTION_NAME
    assert saved.tenant_id == TENANT_ID


def test_resolve_subscription_uses_cli_for_an_unpinned_cli_override(tmp_path: Path) -> None:
    requested: list[str | None] = []

    def resolve(subscription_id: str | None) -> SubscriptionSelection:
        requested.append(subscription_id)
        return SubscriptionSelection(OTHER_SUBSCRIPTION_ID, "Other Subscription", TENANT_ID)

    selection = Authenticator(
        AuthStore(tmp_path / "missing.json"),
        cli_subscription_resolver=resolve,
    ).resolve_subscription(OTHER_SUBSCRIPTION_ID)

    assert requested == [OTHER_SUBSCRIPTION_ID]
    assert selection == SubscriptionSelection(OTHER_SUBSCRIPTION_ID, "Other Subscription", TENANT_ID)


def test_resolve_subscription_keeps_native_tenant_for_an_explicit_override(tmp_path: Path) -> None:
    store = AuthStore(tmp_path / "auth.json")
    store.save(AuthConfig(method=AuthMethod.browser, tenant_id=TENANT_ID, subscription_id=SUBSCRIPTION_ID))

    selection = Authenticator(store).resolve_subscription(OTHER_SUBSCRIPTION_ID)

    assert selection == SubscriptionSelection(OTHER_SUBSCRIPTION_ID, tenant_id=TENANT_ID)


def test_selected_subscription_imports_and_pins_the_cli_default(tmp_path: Path) -> None:
    store = AuthStore(tmp_path / "auth.json")
    authenticator = Authenticator(
        store,
        cli_subscription_resolver=lambda subscription_id: SubscriptionSelection(
            SUBSCRIPTION_ID,
            SUBSCRIPTION_NAME,
            TENANT_ID,
        ),
    )

    selection = authenticator.selected_subscription()

    assert selection == SubscriptionSelection(SUBSCRIPTION_ID, SUBSCRIPTION_NAME, TENANT_ID)
    assert store.load() == AuthConfig(
        method=AuthMethod.azure_cli,
        tenant_id=TENANT_ID,
        subscription_id=SUBSCRIPTION_ID,
        subscription_name=SUBSCRIPTION_NAME,
    )


def test_selected_subscription_imports_environment_scope(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", SUBSCRIPTION_ID)
    store = AuthStore(tmp_path / "auth.json")
    store.save(AuthConfig(method=AuthMethod.environment, tenant_id=TENANT_ID))

    selection = Authenticator(store).selected_subscription()

    assert selection == SubscriptionSelection(SUBSCRIPTION_ID, tenant_id=TENANT_ID)
    saved = store.load()
    assert saved is not None
    assert saved.subscription_id == SUBSCRIPTION_ID


def test_cli_subscription_resolver_rejects_scope_and_tenant_contract_violations(tmp_path: Path) -> None:
    mismatched_scope = Authenticator(
        AuthStore(tmp_path / "missing.json"),
        cli_subscription_resolver=lambda subscription_id: SubscriptionSelection(
            OTHER_SUBSCRIPTION_ID,
            SUBSCRIPTION_NAME,
            TENANT_ID,
        ),
    )
    with pytest.raises(AuthConfigurationError, match="different subscription"):
        mismatched_scope.resolve_subscription(SUBSCRIPTION_ID)

    missing_tenant = Authenticator(
        AuthStore(tmp_path / "missing.json"),
        cli_subscription_resolver=lambda subscription_id: SubscriptionSelection(
            SUBSCRIPTION_ID,
            SUBSCRIPTION_NAME,
        ),
    )
    with pytest.raises(AuthConfigurationError, match="without a tenant ID"):
        missing_tenant.resolve_subscription(SUBSCRIPTION_ID)


@pytest.mark.parametrize(
    ("subscription_id", "message"),
    (
        ("not-a-uuid", "not a valid UUID"),
        ("00000000-0000-0000-0000-000000000000", "must not be the all-zero UUID"),
    ),
)
def test_resolve_subscription_rejects_invalid_scope_identifiers(
    tmp_path: Path,
    subscription_id: str,
    message: str,
) -> None:
    with pytest.raises(AuthConfigurationError, match=message):
        Authenticator(AuthStore(tmp_path / "missing.json")).resolve_subscription(subscription_id)


@pytest.mark.parametrize(
    ("expected_tenant", "message"),
    (
        ("   ", "must not be empty"),
        ("00000000-0000-0000-0000-000000000000", "must not be the all-zero UUID"),
    ),
)
def test_tenant_binding_rejects_invalid_explicit_tenant_hints(expected_tenant: str, message: str) -> None:
    selection = SubscriptionSelection(SUBSCRIPTION_ID, SUBSCRIPTION_NAME, TENANT_ID)

    with pytest.raises(AuthConfigurationError, match=message):
        auth_module._merge_tenant(selection, expected_tenant)  # pyright: ignore[reportPrivateUsage]


def test_selected_subscription_requires_scope_for_native_login(tmp_path: Path) -> None:
    store = AuthStore(tmp_path / "auth.json")
    store.save(AuthConfig(method=AuthMethod.browser))

    with pytest.raises(AuthConfigurationError, match="no Azure subscription is selected"):
        Authenticator(store).selected_subscription()


@pytest.mark.parametrize("return_code", [1, 42])
def test_azure_cli_login_rejects_failed_process(tmp_path: Path, return_code: int) -> None:
    def run_cli(arguments: Sequence[str]) -> int:
        del arguments
        return return_code

    with pytest.raises(AuthLoginError, match="did not complete"):
        Authenticator(AuthStore(tmp_path / "auth.json"), cli_runner=run_cli).login(AuthMethod.azure_cli)


def test_azure_cli_login_reports_missing_executable(tmp_path: Path) -> None:
    def run_cli(arguments: Sequence[str]) -> int:
        del arguments
        raise FileNotFoundError

    with pytest.raises(AuthLoginError, match="not installed"):
        Authenticator(AuthStore(tmp_path / "auth.json"), cli_runner=run_cli).login(AuthMethod.azure_cli)


def test_device_code_flag_is_rejected_for_native_login(tmp_path: Path) -> None:
    with pytest.raises(AuthConfigurationError, match="applies only"):
        Authenticator(AuthStore(tmp_path / "auth.json")).login(AuthMethod.browser, use_device_code=True)


@pytest.mark.parametrize("method", [AuthMethod.browser, AuthMethod.device_code])
def test_native_login_uses_encrypted_cache_and_serialized_record(
    method: AuthMethod,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AZURATOR_CLIENT_ID", "environment-client-id")
    fake = FakeInteractiveCredential(_record())
    constructor_arguments: list[dict[str, object]] = []

    def build_interactive(**kwargs: object) -> FakeInteractiveCredential:
        constructor_arguments.append(kwargs)
        return fake

    target = "InteractiveBrowserCredential" if method is AuthMethod.browser else "DeviceCodeCredential"
    monkeypatch.setattr(auth_module, target, build_interactive)
    store = AuthStore(tmp_path / "auth.json")

    result = Authenticator(store).login(method, client_id="client-id", tenant_id="organizations")

    assert result.tenant_id == "tenant-id"
    assert result.username == "operator@example.invalid"
    assert fake.authenticate_scopes == (ARM_SCOPE,)
    assert fake.closed
    assert constructor_arguments[0]["client_id"] == "client-id"
    cache = constructor_arguments[0]["cache_persistence_options"]
    assert cache is not None
    saved = store.load()
    assert saved is not None
    assert saved.method is method
    assert saved.authentication_record == _record().serialize()


def test_native_login_requires_an_application_registration(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AZURATOR_CLIENT_ID", raising=False)

    with pytest.raises(AuthConfigurationError, match="registered public client"):
        Authenticator(AuthStore(tmp_path / "auth.json")).login(AuthMethod.device_code)


def test_environment_login_stores_no_service_principal_secret(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    credential = FakeTokenCredential()

    def build_environment() -> FakeTokenCredential:
        return credential

    monkeypatch.setattr(auth_module, "EnvironmentCredential", build_environment)
    monkeypatch.setenv("AZURE_TENANT_ID", "tenant-id")
    monkeypatch.setenv("AZURE_CLIENT_SECRET", "must-not-be-persisted")
    store = AuthStore(tmp_path / "auth.json")

    Authenticator(store).login(AuthMethod.environment)

    persisted = store.path.read_text(encoding="utf-8")
    assert "must-not-be-persisted" not in persisted
    assert credential.scopes == [(ARM_SCOPE,)]


def test_environment_login_explicit_subscription_precedes_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    credential = FakeTokenCredential()
    monkeypatch.setattr(auth_module, "EnvironmentCredential", lambda: credential)
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", OTHER_SUBSCRIPTION_ID)
    store = AuthStore(tmp_path / "auth.json")

    result = Authenticator(store).login(AuthMethod.environment, subscription_id=SUBSCRIPTION_ID)

    assert result.subscription_id == SUBSCRIPTION_ID
    saved = store.load()
    assert saved is not None
    assert saved.subscription_id == SUBSCRIPTION_ID


def test_verify_uses_saved_method(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    credential = FakeTokenCredential()

    def build_environment() -> FakeTokenCredential:
        return credential

    monkeypatch.setattr(auth_module, "EnvironmentCredential", build_environment)
    store = AuthStore(tmp_path / "auth.json")
    store.save(AuthConfig(method=AuthMethod.environment, tenant_id="tenant-id"))

    method = Authenticator(store).verify(SUBSCRIPTION_ID)

    assert method is AuthMethod.environment
    assert credential.scopes == [(ARM_SCOPE,)]


def test_default_cli_runner_uses_argument_array(monkeypatch: pytest.MonkeyPatch) -> None:
    completed = Mock(returncode=7)
    run = Mock(return_value=completed)
    monkeypatch.setattr(auth_module.subprocess, "run", run)

    assert auth_module._run_cli(("az", "login")) == 7  # pyright: ignore[reportPrivateUsage]
    run.assert_called_once_with(["az", "login"], check=False)


def test_current_cli_subscription_uses_machine_readable_account_selection(monkeypatch: pytest.MonkeyPatch) -> None:
    completed = Mock(
        returncode=0,
        stdout=(f'{{"id":"{SUBSCRIPTION_ID}","name":"{SUBSCRIPTION_NAME}","tenantId":"{TENANT_ID}"}}\n'),
    )
    run = Mock(return_value=completed)
    monkeypatch.setattr(auth_module.subprocess, "run", run)

    assert auth_module._current_azure_cli_subscription() == SubscriptionSelection(  # pyright: ignore[reportPrivateUsage]
        SUBSCRIPTION_ID,
        SUBSCRIPTION_NAME,
        TENANT_ID,
    )
    run.assert_called_once_with(
        [
            "az",
            "account",
            "show",
            "--query",
            "{id:id,name:name,tenantId:tenantId}",
            "--output",
            "json",
            "--only-show-errors",
        ],
        check=False,
        capture_output=True,
        text=True,
    )


def test_current_cli_subscription_rejects_an_unexpected_response_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    completed = Mock(
        returncode=0,
        stdout=(
            f'{{"id":"{SUBSCRIPTION_ID}","name":"{SUBSCRIPTION_NAME}","tenantId":"{TENANT_ID}","unexpected":"field"}}\n'
        ),
    )
    monkeypatch.setattr(auth_module.subprocess, "run", Mock(return_value=completed))

    with pytest.raises(AuthConfigurationError, match="invalid subscription metadata"):
        auth_module._current_azure_cli_subscription()  # pyright: ignore[reportPrivateUsage]


def test_current_cli_subscription_requires_tenant_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    completed = Mock(
        returncode=0,
        stdout=f'{{"id":"{SUBSCRIPTION_ID}","name":"{SUBSCRIPTION_NAME}"}}\n',
    )
    monkeypatch.setattr(auth_module.subprocess, "run", Mock(return_value=completed))

    with pytest.raises(AuthConfigurationError, match="invalid subscription metadata"):
        auth_module._current_azure_cli_subscription()  # pyright: ignore[reportPrivateUsage]


def test_current_cli_subscription_rejects_noncanonical_tenant_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    completed = Mock(
        returncode=0,
        stdout=f'{{"id":"{SUBSCRIPTION_ID}","name":"{SUBSCRIPTION_NAME}","tenantId":"tenant-domain"}}\n',
    )
    monkeypatch.setattr(auth_module.subprocess, "run", Mock(return_value=completed))

    with pytest.raises(AuthConfigurationError, match="tenant metadata is not a valid UUID"):
        auth_module._current_azure_cli_subscription()  # pyright: ignore[reportPrivateUsage]


@pytest.mark.parametrize(
    "failure",
    (
        Mock(returncode=1, stdout=""),
        FileNotFoundError(),
        OSError("synthetic failure"),
    ),
)
def test_current_cli_subscription_reports_metadata_refresh_failures(
    monkeypatch: pytest.MonkeyPatch,
    failure: Mock | OSError,
) -> None:
    if isinstance(failure, OSError):
        monkeypatch.setattr(auth_module.subprocess, "run", Mock(side_effect=failure))
    else:
        monkeypatch.setattr(auth_module.subprocess, "run", Mock(return_value=failure))

    with pytest.raises(AuthMetadataRefreshError):
        auth_module._current_azure_cli_subscription()  # pyright: ignore[reportPrivateUsage]

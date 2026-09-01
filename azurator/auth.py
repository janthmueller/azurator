"""Authentication adapters for the standalone command.

Azure credentials are created at the application edge and injected into SDK
client factories. Native browser and device-code sessions use Azure Identity's
encrypted persistent cache; the serialized authentication record contains
account metadata, not access or refresh tokens.
"""

from __future__ import annotations

import os
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Literal
from uuid import UUID

from azure.core.credentials import TokenCredential
from azure.identity import (
    AuthenticationRecord,
    AzureCliCredential,
    DeviceCodeCredential,
    EnvironmentCredential,
    InteractiveBrowserCredential,
    TokenCachePersistenceOptions,
)
from platformdirs import user_config_path
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from azurator.files import (
    UnsafeInputPathError,
    UnsafeOutputPathError,
    read_private_text,
    remove_private_text,
    write_private_text,
)

ARM_SCOPE = "https://management.azure.com/.default"
_CACHE_NAME = "azurator"
_AZURE_CLI_PROCESS_TIMEOUT_SECONDS = 30


class AuthMethod(str, Enum):
    """Supported authentication hosts for the standalone CLI."""

    azure_cli = "azure-cli"
    browser = "browser"
    device_code = "device-code"
    environment = "environment"


class AuthError(RuntimeError):
    """Base class for safe, user-facing authentication errors."""


class AuthConfigurationError(AuthError):
    """Authentication configuration is missing, malformed, or unsafe."""


class AuthLoginError(AuthError):
    """An external login adapter could not complete."""


class AuthMetadataRefreshError(AuthError):
    """Azure CLI could not refresh non-secret metadata for a known scope."""


class AuthConfig(BaseModel):
    """Non-secret selection and account metadata persisted by Azurator."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = 1
    method: AuthMethod
    tenant_id: str | None = None
    subscription_id: str | None = None
    subscription_name: str | None = None
    client_id: str | None = None
    authentication_record: str | None = None


class _AzureCliSubscription(BaseModel):
    """The small, explicitly queried subset of ``az account show`` output."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    name: str | None = None
    tenant_id: str = Field(alias="tenantId", min_length=1)


@dataclass(frozen=True)
class LoginResult:
    """Safe summary of a completed login."""

    method: AuthMethod
    tenant_id: str | None = None
    subscription_id: str | None = None
    subscription_name: str | None = None
    username: str | None = None


@dataclass(frozen=True)
class SubscriptionSelection:
    """Validated non-secret subscription scope metadata."""

    subscription_id: str
    name: str | None = None
    tenant_id: str | None = None


CliRunner = Callable[[Sequence[str]], int]
SubscriptionResolver = Callable[[str | None], SubscriptionSelection]


def _run_cli(arguments: Sequence[str]) -> int:
    completed = subprocess.run(list(arguments), check=False)  # noqa: S603
    return completed.returncode


def _normalize_subscription_id(value: str) -> str:
    try:
        parsed = UUID(value.strip())
    except ValueError as error:
        raise AuthConfigurationError("the selected Azure subscription is not a valid UUID") from error
    if parsed.int == 0:
        raise AuthConfigurationError("the selected Azure subscription must not be the all-zero UUID")
    return str(parsed)


def _normalize_tenant_id(value: str) -> str:
    try:
        parsed = UUID(value.strip())
    except ValueError as error:
        raise AuthConfigurationError("Azure tenant metadata is not a valid UUID") from error
    if parsed.int == 0:
        raise AuthConfigurationError("the selected Azure tenant must not be the all-zero UUID")
    return str(parsed)


def _current_azure_cli_subscription(subscription_id: str | None = None) -> SubscriptionSelection:
    command = ["az", "account", "show"]
    if subscription_id:
        command.extend(("--subscription", _normalize_subscription_id(subscription_id)))
    command.extend(("--query", "{id:id,name:name,tenantId:tenantId}", "--output", "json", "--only-show-errors"))
    try:
        completed = subprocess.run(  # noqa: S603
            command,
            check=False,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as error:
        raise AuthMetadataRefreshError("Azure CLI is not installed or is not available on PATH") from error
    except OSError as error:
        raise AuthMetadataRefreshError("Azure CLI subscription metadata could not be read") from error
    if completed.returncode != 0 or not completed.stdout.strip():
        raise AuthMetadataRefreshError(
            "Azure CLI has no active subscription; run 'azurator login' or pass --subscription"
        )
    try:
        account = _AzureCliSubscription.model_validate_json(completed.stdout)
    except ValidationError as error:
        raise AuthConfigurationError("Azure CLI returned invalid subscription metadata") from error
    name = " ".join(account.name.split()) if account.name else None
    return SubscriptionSelection(
        subscription_id=_normalize_subscription_id(account.id),
        name=name or None,
        tenant_id=_normalize_tenant_id(account.tenant_id),
    )


def _default_auth_path() -> Path:
    return user_config_path("azurator", appauthor=False) / "auth.json"


def _merge_tenant(
    selection: SubscriptionSelection,
    expected_tenant_id: str | None,
) -> SubscriptionSelection:
    if selection.tenant_id is None:
        raise AuthConfigurationError("Azure CLI returned subscription metadata without a tenant ID")
    selected_tenant_id = _normalize_tenant_id(selection.tenant_id)
    if expected_tenant_id is not None:
        try:
            expected_uuid = UUID(expected_tenant_id.strip())
        except ValueError:
            # Azure CLI also accepts tenant domains and aliases. A successful
            # tenant-scoped login is bound to the canonical tenant ID returned
            # for the selected subscription.
            if not expected_tenant_id.strip():
                raise AuthConfigurationError("the selected Azure tenant must not be empty") from None
        else:
            if expected_uuid.int == 0:
                raise AuthConfigurationError("the selected Azure tenant must not be the all-zero UUID")
            if expected_uuid != UUID(selected_tenant_id):
                raise AuthConfigurationError("the selected subscription belongs to a different Azure tenant")
    return SubscriptionSelection(
        selection.subscription_id,
        selection.name,
        selected_tenant_id,
    )


class AuthStore:
    """Store non-secret login metadata in a user-private file."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or _default_auth_path()

    def load(self) -> AuthConfig | None:
        try:
            payload = read_private_text(self.path)
        except FileNotFoundError:
            return None
        except (OSError, UnicodeError, UnsafeInputPathError) as error:
            raise AuthConfigurationError("the Azurator authentication record is unsafe or unreadable") from error
        try:
            return AuthConfig.model_validate_json(payload)
        except ValidationError as error:
            raise AuthConfigurationError("the Azurator authentication record is malformed") from error

    def save(self, config: AuthConfig) -> None:
        try:
            write_private_text(self.path, config.model_dump_json(indent=2) + "\n")
        except (OSError, UnsafeOutputPathError) as error:
            raise AuthConfigurationError("could not safely persist the Azurator authentication record") from error

    def clear(self) -> bool:
        """Remove Azurator's saved adapter and scope record if it exists."""

        try:
            remove_private_text(self.path)
        except FileNotFoundError:
            return False
        except (OSError, UnsafeOutputPathError) as error:
            raise AuthConfigurationError("the Azurator authentication record could not be removed safely") from error
        return True


class CredentialFactory:
    """Build credentials without leaking a concrete auth mechanism into providers."""

    def __init__(self, store: AuthStore) -> None:
        self._store = store

    def active_method(self) -> AuthMethod:
        config = self._store.load()
        return config.method if config is not None else AuthMethod.azure_cli

    def create(self, subscription_id: str | None = None) -> TokenCredential:
        config = self._store.load() or AuthConfig(method=AuthMethod.azure_cli)
        return self.create_from_config(config, subscription_id or config.subscription_id)

    def create_from_config(self, config: AuthConfig, subscription_id: str | None = None) -> TokenCredential:
        if config.method is AuthMethod.azure_cli:
            if subscription_id is not None:
                return AzureCliCredential(
                    subscription=subscription_id,
                    process_timeout=_AZURE_CLI_PROCESS_TIMEOUT_SECONDS,
                )
            if config.tenant_id is not None:
                return AzureCliCredential(
                    tenant_id=config.tenant_id,
                    process_timeout=_AZURE_CLI_PROCESS_TIMEOUT_SECONDS,
                )
            return AzureCliCredential(process_timeout=_AZURE_CLI_PROCESS_TIMEOUT_SECONDS)
        if config.method is AuthMethod.environment:
            return EnvironmentCredential()

        if not config.client_id or not config.authentication_record:
            raise AuthConfigurationError(
                "native login metadata is incomplete; run 'azurator login' again for the selected method"
            )

        try:
            record = AuthenticationRecord.deserialize(config.authentication_record)
        except ValueError as error:
            raise AuthConfigurationError("the saved native authentication record is malformed") from error
        if config.client_id != record.client_id or (
            config.tenant_id is not None and config.tenant_id != record.tenant_id
        ):
            raise AuthConfigurationError("saved native authentication metadata disagrees with its account record")

        cache = TokenCachePersistenceOptions(name=_CACHE_NAME, allow_unencrypted_storage=False)
        if config.method is AuthMethod.browser:
            return InteractiveBrowserCredential(
                tenant_id=record.tenant_id,
                client_id=record.client_id,
                authentication_record=record,
                disable_automatic_authentication=True,
                cache_persistence_options=cache,
            )
        return DeviceCodeCredential(
            tenant_id=record.tenant_id,
            client_id=record.client_id,
            authentication_record=record,
            disable_automatic_authentication=True,
            cache_persistence_options=cache,
        )


class Authenticator:
    """Perform explicit login and persist only the chosen adapter and account record."""

    def __init__(
        self,
        store: AuthStore,
        *,
        cli_runner: CliRunner = _run_cli,
        cli_subscription_resolver: SubscriptionResolver = _current_azure_cli_subscription,
    ) -> None:
        self._store = store
        self._credentials = CredentialFactory(store)
        self._cli_runner = cli_runner
        self._cli_subscription_resolver = cli_subscription_resolver

    def login(
        self,
        method: AuthMethod,
        *,
        tenant_id: str | None = None,
        subscription_id: str | None = None,
        client_id: str | None = None,
        use_device_code: bool = False,
        redirect_uri: str = "http://localhost",
    ) -> LoginResult:
        if method is AuthMethod.azure_cli:
            return self._login_with_azure_cli(
                tenant_id=tenant_id,
                subscription_id=subscription_id,
                use_device_code=use_device_code,
            )
        if use_device_code:
            raise AuthConfigurationError("--use-device-code applies only to the azure-cli login method")
        if method is AuthMethod.environment:
            return self._login_with_environment(subscription_id=subscription_id)
        return self._login_natively(
            method,
            tenant_id=tenant_id,
            subscription_id=subscription_id,
            client_id=client_id,
            redirect_uri=redirect_uri,
        )

    def resolve_subscription(self, subscription_id: str | None = None) -> SubscriptionSelection:
        """Resolve an optional command override or return the pinned login scope."""

        if subscription_id is None:
            return self.selected_subscription()

        requested_id = _normalize_subscription_id(subscription_id)
        config = self._store.load()
        if config is not None and config.subscription_id == requested_id:
            if config.method is not AuthMethod.azure_cli:
                return SubscriptionSelection(requested_id, config.subscription_name, config.tenant_id)
            cached_tenant_id = _normalize_tenant_id(config.tenant_id) if config.tenant_id else None
            if config.subscription_name and cached_tenant_id:
                return SubscriptionSelection(requested_id, config.subscription_name, cached_tenant_id)
            selection = _merge_tenant(self._resolve_cli_subscription(requested_id), cached_tenant_id)
            self._store.save(
                config.model_copy(
                    update={
                        "subscription_id": selection.subscription_id,
                        "subscription_name": selection.name,
                        "tenant_id": selection.tenant_id,
                    }
                )
            )
            return selection

        if config is None or config.method is AuthMethod.azure_cli:
            return self._resolve_cli_subscription(requested_id)
        return SubscriptionSelection(requested_id, tenant_id=config.tenant_id)

    def selected_subscription(self) -> SubscriptionSelection:
        """Return the pinned scope, migrating existing Azure CLI metadata when needed."""

        config = self._store.load()
        if config is not None and config.subscription_id:
            subscription_id = _normalize_subscription_id(config.subscription_id)
            if config.method is not AuthMethod.azure_cli:
                return SubscriptionSelection(subscription_id, config.subscription_name, config.tenant_id)
            cached_tenant_id = _normalize_tenant_id(config.tenant_id) if config.tenant_id else None
            if config.subscription_name and cached_tenant_id:
                return SubscriptionSelection(subscription_id, config.subscription_name, cached_tenant_id)
            try:
                selection = _merge_tenant(
                    self._resolve_cli_subscription(subscription_id),
                    cached_tenant_id,
                )
            except AuthMetadataRefreshError:
                if cached_tenant_id is None:
                    raise AuthConfigurationError(
                        "Azure CLI tenant metadata is unavailable; run 'azurator login' again"
                    ) from None
                return SubscriptionSelection(subscription_id, config.subscription_name, cached_tenant_id)
            self._store.save(
                config.model_copy(
                    update={
                        "subscription_id": selection.subscription_id,
                        "subscription_name": selection.name,
                        "tenant_id": selection.tenant_id,
                    }
                )
            )
            return selection

        if config is None or config.method is AuthMethod.azure_cli:
            selection = self._resolve_cli_subscription()
            migrated = (config or AuthConfig(method=AuthMethod.azure_cli)).model_copy(
                update={
                    "subscription_id": selection.subscription_id,
                    "subscription_name": selection.name,
                    "tenant_id": selection.tenant_id,
                }
            )
            self._store.save(migrated)
            return selection

        if config.method is AuthMethod.environment and (subscription_id := os.environ.get("AZURE_SUBSCRIPTION_ID")):
            subscription_id = _normalize_subscription_id(subscription_id)
            self._store.save(config.model_copy(update={"subscription_id": subscription_id}))
            return SubscriptionSelection(subscription_id, tenant_id=config.tenant_id)

        raise AuthConfigurationError(
            "no Azure subscription is selected; run 'azurator login --subscription <id>' or pass --subscription"
        )

    def _resolve_cli_subscription(self, subscription_id: str | None = None) -> SubscriptionSelection:
        requested_id = _normalize_subscription_id(subscription_id) if subscription_id else None
        selection = self._cli_subscription_resolver(requested_id)
        resolved_id = _normalize_subscription_id(selection.subscription_id)
        if requested_id is not None and resolved_id != requested_id:
            raise AuthConfigurationError("Azure CLI resolved a different subscription than requested")
        name = " ".join(selection.name.split()) if selection.name else None
        if selection.tenant_id is None:
            raise AuthConfigurationError("Azure CLI returned subscription metadata without a tenant ID")
        tenant_id = _normalize_tenant_id(selection.tenant_id)
        return SubscriptionSelection(resolved_id, name or None, tenant_id)

    def verify(self, subscription_id: str | None = None) -> AuthMethod:
        credential = self._credentials.create(subscription_id)
        _ = credential.get_token(ARM_SCOPE)
        return self._credentials.active_method()

    def _login_with_azure_cli(
        self,
        *,
        tenant_id: str | None,
        subscription_id: str | None,
        use_device_code: bool,
    ) -> LoginResult:
        command = ["az", "login", "--output", "none"]
        if tenant_id:
            command.extend(("--tenant", tenant_id))
        if use_device_code:
            command.append("--use-device-code")
        try:
            return_code = self._cli_runner(command)
        except FileNotFoundError as error:
            raise AuthLoginError("Azure CLI is not installed or is not available on PATH") from error
        if return_code != 0:
            raise AuthLoginError("Azure CLI login did not complete successfully")

        selected_subscription = self._resolve_cli_subscription(subscription_id)
        selected_subscription = _merge_tenant(selected_subscription, tenant_id)
        selected_tenant = selected_subscription.tenant_id
        config = AuthConfig(
            method=AuthMethod.azure_cli,
            tenant_id=selected_tenant,
            subscription_id=selected_subscription.subscription_id,
            subscription_name=selected_subscription.name,
        )
        credential = self._credentials.create_from_config(config, selected_subscription.subscription_id)
        _ = credential.get_token(ARM_SCOPE)
        self._store.save(config)
        return LoginResult(
            method=AuthMethod.azure_cli,
            tenant_id=selected_tenant,
            subscription_id=selected_subscription.subscription_id,
            subscription_name=selected_subscription.name,
        )

    def _login_with_environment(self, *, subscription_id: str | None) -> LoginResult:
        selected_subscription = subscription_id or os.environ.get("AZURE_SUBSCRIPTION_ID")
        if selected_subscription:
            selected_subscription = _normalize_subscription_id(selected_subscription)
        config = AuthConfig(
            method=AuthMethod.environment,
            tenant_id=os.environ.get("AZURE_TENANT_ID"),
            subscription_id=selected_subscription,
        )
        credential = self._credentials.create_from_config(config)
        _ = credential.get_token(ARM_SCOPE)
        self._store.save(config)
        return LoginResult(
            method=AuthMethod.environment,
            tenant_id=config.tenant_id,
            subscription_id=selected_subscription,
        )

    def _login_natively(
        self,
        method: AuthMethod,
        *,
        tenant_id: str | None,
        subscription_id: str | None,
        client_id: str | None,
        redirect_uri: str,
    ) -> LoginResult:
        resolved_client_id = client_id or os.environ.get("AZURATOR_CLIENT_ID")
        if not resolved_client_id:
            raise AuthConfigurationError(
                "browser and device-code login require --client-id or AZURATOR_CLIENT_ID for a registered public client"
            )

        cache = TokenCachePersistenceOptions(name=_CACHE_NAME, allow_unencrypted_storage=False)
        resolved_tenant = tenant_id or "organizations"
        if method is AuthMethod.browser:
            credential = InteractiveBrowserCredential(
                tenant_id=resolved_tenant,
                client_id=resolved_client_id,
                redirect_uri=redirect_uri,
                cache_persistence_options=cache,
            )
        else:
            credential = DeviceCodeCredential(
                tenant_id=resolved_tenant,
                client_id=resolved_client_id,
                cache_persistence_options=cache,
            )

        try:
            record = credential.authenticate(scopes=(ARM_SCOPE,))
        finally:
            credential.close()

        config = AuthConfig(
            method=method,
            tenant_id=record.tenant_id,
            subscription_id=_normalize_subscription_id(subscription_id) if subscription_id else None,
            client_id=record.client_id,
            authentication_record=record.serialize(),
        )
        self._store.save(config)
        return LoginResult(
            method=method,
            tenant_id=record.tenant_id,
            subscription_id=config.subscription_id,
            username=record.username,
        )

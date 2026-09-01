"""Shared fakes for the reviewed App Service application-settings contract."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import cast

from azure.mgmt.web.models import StringDictionary

from azurator.clients import (
    AppSettingsLike,
    AzureClientFactory,
    WebAppLike,
    WebAppOperations,
    WebSiteManagementClientLike,
)
from azurator.models import (
    DiscoveredResource,
    KeyAuthentication,
    KeySlot,
    ProviderBindingResult,
)
from azurator.providers.app_service_settings import AppServiceSettingsProvider

SUBSCRIPTION_ID = "11111111-2222-3333-4444-555555555555"
SITE_ID = f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/app-rg/providers/Microsoft.Web/sites/example-app"
STORAGE_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/key-rg/providers/Microsoft.Storage/storageAccounts/storageone"
)
COGNITIVE_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/key-rg/providers/Microsoft.CognitiveServices/accounts/aione"
)


@dataclass
class FakeSite:
    id: object = SITE_ID
    name: object = "example-app"
    type: object = "Microsoft.Web/sites"


@dataclass
class FakeSettings:
    properties: object


class FakeWebAppOperations:
    def __init__(
        self,
        sites: Iterable[FakeSite] = (),
        settings: dict[str, object] | None = None,
        *,
        list_error: Exception | None = None,
        read_errors: dict[str, Exception] | None = None,
        update_error: Exception | None = None,
    ) -> None:
        self.sites = tuple(sites)
        self.settings = dict(settings or {})
        self.list_error = list_error
        self.read_errors = dict(read_errors or {})
        self.update_error = update_error
        self.list_calls: list[bool] = []
        self.read_calls: list[tuple[str, str, bool]] = []
        self.update_calls: list[tuple[str, str, dict[str, str], bool]] = []
        self.last_request: StringDictionary | None = None

    def list(self, *, logging_enable: bool = False) -> Iterable[WebAppLike]:
        self.list_calls.append(logging_enable)
        if self.list_error is not None:
            raise self.list_error
        return tuple(cast(WebAppLike, site) for site in self.sites)

    def list_application_settings(
        self,
        resource_group_name: str,
        name: str,
        *,
        logging_enable: bool = False,
    ) -> AppSettingsLike:
        self.read_calls.append((resource_group_name, name, logging_enable))
        error = self.read_errors.get(name)
        if error is not None:
            raise error
        raw = self.settings.get(name)
        properties: object = dict(cast(dict[object, object], raw)) if isinstance(raw, dict) else raw
        return cast(AppSettingsLike, FakeSettings(properties))

    def update_application_settings(
        self,
        resource_group_name: str,
        name: str,
        app_settings: StringDictionary,
        *,
        logging_enable: bool = False,
    ) -> AppSettingsLike:
        self.last_request = app_settings
        properties = app_settings.properties
        snapshot = dict(properties) if isinstance(properties, dict) else {}
        self.update_calls.append((resource_group_name, name, snapshot, logging_enable))
        if self.update_error is not None:
            raise self.update_error
        self.settings[name] = snapshot
        return cast(AppSettingsLike, FakeSettings(dict(snapshot)))


class FakeWebSiteManagementClient:
    def __init__(self, operations: FakeWebAppOperations) -> None:
        self._operations = operations
        self.closed = False

    @property
    def web_apps(self) -> WebAppOperations:
        return cast(WebAppOperations, self._operations)

    def close(self) -> None:
        self.closed = True


class FakeClientFactory:
    def __init__(self, client: FakeWebSiteManagementClient) -> None:
        self.client = client
        self.subscription_calls: list[str] = []

    def web_site_management(self, subscription_id: str) -> WebSiteManagementClientLike:
        self.subscription_calls.append(subscription_id)
        return cast(WebSiteManagementClientLike, self.client)


def make_storage_resource() -> DiscoveredResource:
    return DiscoveredResource(
        resource_id=STORAGE_ID,
        name="storageone",
        resource_type="Microsoft.Storage/storageAccounts",
        location="westeurope",
        kind="StorageV2",
        provider="azure-storage",
        key_authentication=KeyAuthentication.enabled,
        key_slots=(
            KeySlot(name="key1", values_retrievable=True, rotatable=True),
            KeySlot(name="key2", values_retrievable=True, rotatable=True),
        ),
    )


def make_cognitive_resource() -> DiscoveredResource:
    return DiscoveredResource(
        resource_id=COGNITIVE_ID,
        name="aione",
        resource_type="Microsoft.CognitiveServices/accounts",
        location="westeurope",
        kind="OpenAI",
        endpoint="https://aione.openai.azure.com/",
        provider="azure-cognitive-services",
        key_authentication=KeyAuthentication.enabled,
        key_slots=(
            KeySlot(name="Key1", values_retrievable=True, rotatable=True),
            KeySlot(name="Key2", values_retrievable=True, rotatable=True),
        ),
    )


def make_provider(
    operations: FakeWebAppOperations,
) -> tuple[AppServiceSettingsProvider, FakeWebSiteManagementClient, FakeClientFactory]:
    client = FakeWebSiteManagementClient(operations)
    factory = FakeClientFactory(client)
    provider = AppServiceSettingsProvider(cast(AzureClientFactory, factory))
    return provider, client, factory


def inspect_bindings(
    provider: AppServiceSettingsProvider,
    *,
    storage_key: str = "storage-current-key",
    cognitive_key: str = "cognitive-current-key",
    include_cognitive: bool = True,
) -> ProviderBindingResult:
    resources = (
        (make_storage_resource(), make_cognitive_resource()) if include_cognitive else (make_storage_resource(),)
    )
    selected = frozenset(resource.resource_id for resource in resources)

    def identify(resource_id: str, value: str) -> str | None:
        if not value or resource_id not in selected:
            raise AssertionError("provider called the candidate identifier outside its contract")
        if resource_id == STORAGE_ID and value == storage_key:
            return "key1"
        if resource_id == COGNITIVE_ID and value == cognitive_key:
            return "Key1"
        return None

    return provider.inspect_bindings(SUBSCRIPTION_ID, resources, selected, identify)

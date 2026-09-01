"""Injectable Azure SDK client boundaries.

The core and providers depend on these protocols rather than constructing an
``AzureCliCredential`` or importing ``azure-cli-core`` themselves.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol, cast

from azure.ai.projects import AIProjectClient
from azure.core.credentials import TokenCredential
from azure.mgmt.cognitiveservices import CognitiveServicesManagementClient
from azure.mgmt.cognitiveservices.models import ConnectionPropertiesV2BasicResource, ConnectionUpdateContent
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.storage.models import StorageAccountRegenerateKeyParameters
from azure.mgmt.web import WebSiteManagementClient
from azure.mgmt.web.models import StringDictionary


class CognitiveAccountPropertiesLike(Protocol):
    """Cognitive Services account properties used for safe classification."""

    @property
    def disable_local_auth(self) -> bool | None: ...

    @property
    def endpoint(self) -> str | None: ...


class CognitiveAccountLike(Protocol):
    """Metadata fields consumed from an SDK Cognitive Services account."""

    @property
    def id(self) -> str | None: ...

    @property
    def name(self) -> str | None: ...

    @property
    def type(self) -> str | None: ...

    @property
    def location(self) -> str | None: ...

    @property
    def kind(self) -> str | None: ...

    @property
    def properties(self) -> CognitiveAccountPropertiesLike | None: ...


class CognitiveAccountOperations(Protocol):
    """Reviewed Cognitive account discovery and key-operation surface."""

    def list(self) -> Iterable[CognitiveAccountLike]: ...

    def list_keys(
        self,
        resource_group_name: str,
        account_name: str,
        *,
        logging_enable: bool = False,
    ) -> CognitiveApiKeysLike: ...

    def regenerate_key(
        self,
        resource_group_name: str,
        account_name: str,
        key_name: str,
        *,
        logging_enable: bool = False,
    ) -> CognitiveApiKeysLike: ...


class CognitiveApiKeysLike(Protocol):
    """Cognitive account key-pair response consumed only inside supported boundaries."""

    @property
    def key1(self) -> str | None: ...

    @property
    def key2(self) -> str | None: ...


class FoundryProjectLike(Protocol):
    """Project identity fields returned by the supported management operation."""

    @property
    def id(self) -> str | None: ...

    @property
    def type(self) -> str | None: ...


class FoundryProjectOperations(Protocol):
    """Reviewed management-plane project enumeration operation."""

    def list(
        self,
        resource_group_name: str,
        account_name: str,
        *,
        api_version: str,
        logging_enable: bool = False,
    ) -> Iterable[FoundryProjectLike]: ...


class FoundryProjectConnectionOperations(Protocol):
    """Reviewed management-plane mutation surface for project connections."""

    def update(
        self,
        resource_group_name: str,
        account_name: str,
        project_name: str,
        connection_name: str,
        connection: ConnectionUpdateContent,
        *,
        logging_enable: bool = False,
    ) -> ConnectionPropertiesV2BasicResource: ...


class CognitiveServicesManagementClientLike(Protocol):
    """Minimal client surface required by the Cognitive Services provider."""

    @property
    def accounts(self) -> CognitiveAccountOperations: ...

    def close(self) -> None: ...


class FoundryManagementClientLike(Protocol):
    """Minimal management client surface for supported Foundry operations."""

    @property
    def projects(self) -> FoundryProjectOperations: ...

    @property
    def project_connections(self) -> FoundryProjectConnectionOperations: ...

    def close(self) -> None: ...


class FoundryConnectionLike(Protocol):
    """Connection fields consumed from the Foundry project data plane."""

    @property
    def name(self) -> object: ...

    @property
    def type(self) -> object: ...

    @property
    def target(self) -> object: ...

    @property
    def credentials(self) -> object: ...


class FoundryConnectionOperations(Protocol):
    """Reviewed data-plane connection reads, split at the credential boundary."""

    def list(
        self,
        *,
        connection_type: str,
        logging_enable: bool = False,
    ) -> Iterable[FoundryConnectionLike]: ...

    def get(
        self,
        name: str,
        *,
        include_credentials: bool = False,
        logging_enable: bool = False,
    ) -> FoundryConnectionLike: ...


class AIProjectClientLike(Protocol):
    """Minimal Foundry project data-plane client surface."""

    @property
    def connections(self) -> FoundryConnectionOperations: ...

    def close(self) -> None: ...


class StorageAccountLike(Protocol):
    """The metadata fields consumed from an SDK StorageAccount model."""

    @property
    def id(self) -> str | None: ...

    @property
    def name(self) -> str | None: ...

    @property
    def type(self) -> str | None: ...

    @property
    def location(self) -> str | None: ...

    @property
    def kind(self) -> str | None: ...

    @property
    def allow_shared_key_access(self) -> bool | None: ...


class StorageAccountOperations(Protocol):
    """Reviewed discovery, key-read, and one-slot regeneration surface."""

    def list(self) -> Iterable[StorageAccountLike]: ...

    def list_keys(
        self,
        resource_group_name: str,
        account_name: str,
        *,
        expand: str | None = None,
        logging_enable: bool = False,
    ) -> StorageAccountListKeysResultLike: ...

    def regenerate_key(
        self,
        resource_group_name: str,
        account_name: str,
        regenerate_key: StorageAccountRegenerateKeyParameters,
        *,
        logging_enable: bool = False,
    ) -> StorageAccountListKeysResultLike: ...


class StorageAccountKeyLike(Protocol):
    """One Storage key response item consumed only inside supported secret boundaries."""

    @property
    def key_name(self) -> str | None: ...

    @property
    def value(self) -> str | None: ...


class StorageAccountListKeysResultLike(Protocol):
    """Storage SDK 25.1 key-list response used by the supported provider."""

    @property
    def keys_property(self) -> Iterable[StorageAccountKeyLike] | None: ...


class StorageManagementClientLike(Protocol):
    """Minimal client surface required by the Storage provider."""

    @property
    def storage_accounts(self) -> StorageAccountOperations: ...

    def close(self) -> None: ...


class WebAppLike(Protocol):
    """Top-level App Service site metadata used to scope settings operations."""

    @property
    def id(self) -> str | None: ...

    @property
    def name(self) -> str | None: ...

    @property
    def type(self) -> str | None: ...


class AppSettingsLike(Protocol):
    """App Service application-settings dictionary returned by the supported API."""

    @property
    def properties(self) -> object: ...


class WebAppOperations(Protocol):
    """Reviewed top-level App Service enumeration and application-settings surface."""

    def list(self, *, logging_enable: bool = False) -> Iterable[WebAppLike]: ...

    def list_application_settings(
        self,
        resource_group_name: str,
        name: str,
        *,
        logging_enable: bool = False,
    ) -> AppSettingsLike: ...

    def update_application_settings(
        self,
        resource_group_name: str,
        name: str,
        app_settings: StringDictionary,
        *,
        logging_enable: bool = False,
    ) -> AppSettingsLike: ...


class WebSiteManagementClientLike(Protocol):
    """Minimal App Service management client used by the settings-binding provider."""

    @property
    def web_apps(self) -> WebAppOperations: ...

    def close(self) -> None: ...


class AzureClientFactory(Protocol):
    """Factory that can be supplied by a standalone or Azure CLI adapter."""

    def cognitive_services_management(self, subscription_id: str) -> CognitiveServicesManagementClientLike: ...

    def foundry_management(self, subscription_id: str) -> FoundryManagementClientLike: ...

    def storage_management(self, subscription_id: str) -> StorageManagementClientLike: ...

    def web_site_management(self, subscription_id: str) -> WebSiteManagementClientLike: ...

    def ai_project(self, endpoint: str) -> AIProjectClientLike: ...


class SdkAzureClientFactory:
    """Construct official Azure management clients from an injected credential."""

    def __init__(self, credential: TokenCredential) -> None:
        self._credential = credential

    def cognitive_services_management(self, subscription_id: str) -> CognitiveServicesManagementClientLike:
        client = CognitiveServicesManagementClient(
            credential=self._credential,
            subscription_id=subscription_id,
            api_version="2025-06-01",
        )
        return cast(CognitiveServicesManagementClientLike, client)

    def foundry_management(self, subscription_id: str) -> FoundryManagementClientLike:
        client = CognitiveServicesManagementClient(
            credential=self._credential,
            subscription_id=subscription_id,
            api_version="2025-06-01",
        )
        return cast(FoundryManagementClientLike, client)

    def storage_management(self, subscription_id: str) -> StorageManagementClientLike:
        client = StorageManagementClient(
            credential=self._credential,
            subscription_id=subscription_id,
            api_version="2025-08-01",
        )
        return cast(StorageManagementClientLike, client)

    def web_site_management(self, subscription_id: str) -> WebSiteManagementClientLike:
        client = WebSiteManagementClient(
            credential=self._credential,
            subscription_id=subscription_id,
            api_version="2025-05-01",
        )
        return cast(WebSiteManagementClientLike, client)

    def ai_project(self, endpoint: str) -> AIProjectClientLike:
        client = AIProjectClient(
            endpoint=endpoint,
            credential=self._credential,
            api_version="v1",
            logging_enable=False,
        )
        return cast(AIProjectClientLike, client)

"""Shared fakes and builders for reviewed Foundry connection tests."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import cast

from azure.mgmt.cognitiveservices.models import (
    AccountKeyAuthTypeConnectionProperties,
    ApiKeyAuthConnectionProperties,
    ConnectionCategory,
    ConnectionPropertiesV2BasicResource,
    ConnectionUpdateContent,
)

from azurator.clients import (
    AIProjectClientLike,
    AzureClientFactory,
    FoundryConnectionLike,
    FoundryConnectionOperations,
    FoundryManagementClientLike,
    FoundryProjectConnectionOperations,
    FoundryProjectLike,
    FoundryProjectOperations,
)
from azurator.models import (
    DiscoveredResource,
    KeyAuthentication,
    KeySlot,
)
from azurator.providers.foundry_connections import FoundryConnectionsProvider

SUBSCRIPTION_ID = "11111111-1111-1111-1111-111111111111"
ACCOUNT_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/foundryone"
)
PROJECT_ID = f"{ACCOUNT_ID}/projects/projectone"


@dataclass(frozen=True)
class FakeProject:
    id: str | None = PROJECT_ID
    name: str | None = "foundryone/projectone"
    type: str | None = "Microsoft.CognitiveServices/accounts/projects"


class FakeCredentials(dict[str, object]):
    def __init__(self, account_key: str | None, *, credential_type: str = "AccountKey") -> None:
        super().__init__(type=credential_type, key=account_key)


def _empty_metadata() -> dict[str, str]:
    return {}


@dataclass(frozen=True)
class FakeConnection:
    id: str
    name: str
    type: str = "AzureStorageAccount"
    target: str = "https://accountone.blob.core.windows.net/"
    credentials: FakeCredentials = field(default_factory=lambda: FakeCredentials(None))
    metadata: dict[str, str] = field(default_factory=_empty_metadata)


class FakeProjectOperations:
    def __init__(
        self,
        projects: tuple[FakeProject, ...] = (),
        *,
        error: Exception | None = None,
    ) -> None:
        self.projects = projects
        self.error = error
        self.calls: list[tuple[str, str, str, bool]] = []

    def list(
        self,
        resource_group_name: str,
        account_name: str,
        *,
        api_version: str,
        logging_enable: bool = False,
    ) -> Iterable[FoundryProjectLike]:
        self.calls.append((resource_group_name, account_name, api_version, logging_enable))
        if self.error is not None:
            raise self.error
        return tuple(cast(FoundryProjectLike, project) for project in self.projects)


class FakeProjectConnectionOperations:
    def __init__(
        self,
        *,
        expected_key: str = "managed-storage-secret",
        error: Exception | None = None,
    ) -> None:
        self.expected_key = expected_key
        self.error = error
        self.calls: list[tuple[str, str, str, str, str | None, str | None, bool, bool]] = []
        self.request: ConnectionUpdateContent | None = None

    def update(
        self,
        resource_group_name: str,
        account_name: str,
        project_name: str,
        connection_name: str,
        connection: ConnectionUpdateContent,
        *,
        logging_enable: bool = False,
    ) -> ConnectionPropertiesV2BasicResource:
        properties = cast(
            AccountKeyAuthTypeConnectionProperties | ApiKeyAuthConnectionProperties | None,
            connection.properties,
        )
        credentials = properties.credentials if properties is not None else None
        key = credentials.key if credentials is not None else None
        category = properties.category if properties is not None else None
        category_value = category.value if isinstance(category, ConnectionCategory) else category
        self.calls.append(
            (
                resource_group_name,
                account_name,
                project_name,
                connection_name,
                category_value,
                properties.target if properties is not None else None,
                key == self.expected_key,
                logging_enable,
            )
        )
        self.request = connection
        key = ""
        if self.error is not None:
            raise self.error
        return cast(ConnectionPropertiesV2BasicResource, object())


class FakeManagementClient:
    def __init__(
        self,
        operations: FakeProjectOperations,
        connection_operations: FakeProjectConnectionOperations | None = None,
    ) -> None:
        self.operations = operations
        self.connection_operations = connection_operations or FakeProjectConnectionOperations()
        self.closed = False

    @property
    def projects(self) -> FoundryProjectOperations:
        return self.operations

    @property
    def project_connections(self) -> FoundryProjectConnectionOperations:
        return self.connection_operations

    def close(self) -> None:
        self.closed = True


class FakeConnectionOperations:
    def __init__(
        self,
        connections: tuple[FakeConnection, ...],
        details: dict[str, FakeConnection],
        *,
        list_error: Exception | None = None,
        get_error: Exception | None = None,
    ) -> None:
        self.connections = connections
        self.details = details
        self.list_error = list_error
        self.get_error = get_error
        self.list_calls: list[tuple[str, bool]] = []
        self.get_calls: list[tuple[str, bool, bool]] = []

    def list(
        self,
        *,
        connection_type: str,
        logging_enable: bool = False,
    ) -> Iterable[FoundryConnectionLike]:
        self.list_calls.append((connection_type, logging_enable))
        if self.list_error is not None:
            raise self.list_error
        return tuple(cast(FoundryConnectionLike, connection) for connection in self.connections)

    def get(
        self,
        name: str,
        *,
        include_credentials: bool = False,
        logging_enable: bool = False,
    ) -> FoundryConnectionLike:
        self.get_calls.append((name, include_credentials, logging_enable))
        if self.get_error is not None:
            raise self.get_error
        return cast(FoundryConnectionLike, self.details[name])


class FakeProjectClient:
    def __init__(self, operations: FakeConnectionOperations) -> None:
        self._operations = operations
        self.closed = False

    @property
    def connections(self) -> FoundryConnectionOperations:
        return self._operations

    def close(self) -> None:
        self.closed = True


class FakeClientFactory:
    def __init__(
        self,
        management_client: FakeManagementClient,
        project_clients: dict[str, FakeProjectClient],
    ) -> None:
        self.management_client = management_client
        self.project_clients = project_clients
        self.subscription_ids: list[str] = []
        self.project_endpoints: list[str] = []

    def foundry_management(self, subscription_id: str) -> FoundryManagementClientLike:
        self.subscription_ids.append(subscription_id)
        return cast(FoundryManagementClientLike, self.management_client)

    def ai_project(self, endpoint: str) -> AIProjectClientLike:
        self.project_endpoints.append(endpoint)
        return self.project_clients[endpoint]


def make_storage_resource(name: str) -> DiscoveredResource:
    return DiscoveredResource(
        resource_id=(
            f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/{name}"
        ),
        name=name,
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


def make_cognitive_resource(name: str = "openai-one") -> DiscoveredResource:
    return DiscoveredResource(
        resource_id=(
            f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/{name}"
        ),
        name=name,
        resource_type="Microsoft.CognitiveServices/accounts",
        location="westeurope",
        kind="OpenAI",
        endpoint=f"https://{name}.openai.azure.com/",
        provider="azure-cognitive-services",
        key_authentication=KeyAuthentication.enabled,
        key_slots=(
            KeySlot(name="Key1", values_retrievable=True, rotatable=True),
            KeySlot(name="Key2", values_retrievable=True, rotatable=True),
        ),
    )


def make_account() -> DiscoveredResource:
    return DiscoveredResource(
        resource_id=ACCOUNT_ID,
        name="foundryone",
        resource_type="Microsoft.CognitiveServices/accounts",
        location="westeurope",
        kind="AIServices",
        endpoint="https://foundryone.services.ai.azure.com",
        provider="azure-cognitive-services",
        key_authentication=KeyAuthentication.enabled,
        key_slots=(),
    )


def make_provider(
    project: FakeProject,
    connection_operations: FakeConnectionOperations,
    management_connection_operations: FakeProjectConnectionOperations | None = None,
) -> tuple[FoundryConnectionsProvider, FakeManagementClient, FakeProjectClient, FakeClientFactory]:
    management_client = FakeManagementClient(
        FakeProjectOperations((project,)),
        management_connection_operations,
    )
    project_client = FakeProjectClient(connection_operations)
    endpoint = "https://foundryone.services.ai.azure.com/api/projects/projectone"
    factory = FakeClientFactory(management_client, {endpoint: project_client})
    provider = FoundryConnectionsProvider(cast(AzureClientFactory, factory))
    return provider, management_client, project_client, factory

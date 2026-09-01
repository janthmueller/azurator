"""Static registration of providers shipped with Azurator."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal, Protocol

from azurator.clients import AzureClientFactory
from azurator.models import (
    BindingLocation,
    BindingManagement,
    ProviderInfo,
    SupportCatalog,
    SupportedCredentialBinding,
    SupportedKeyResource,
)
from azurator.providers.app_service_settings import (
    APP_SERVICE_SETTINGS_PROVIDER_INFO,
    AppServiceSettingsProvider,
)
from azurator.providers.base import (
    BindingProvider,
    DiscoveryProvider,
    KeyReadingProvider,
    ManagedBindingProvider,
    MatchingProvider,
    RotationProvider,
)
from azurator.providers.cognitive_services import (
    COGNITIVE_SERVICES_KEY_SLOTS,
    COGNITIVE_SERVICES_PROVIDER_INFO,
    CognitiveServicesProvider,
)
from azurator.providers.dotenv_file import DOTENV_FILE_PROVIDER_INFO, DotenvFileProvider
from azurator.providers.foundry_connections import FOUNDRY_CONNECTIONS_PROVIDER_INFO, FoundryConnectionsProvider
from azurator.providers.sops_dotenv_file import SOPS_DOTENV_FILE_PROVIDER_INFO, SopsDotenvFileProvider
from azurator.providers.storage import STORAGE_KEY_SLOTS, STORAGE_PROVIDER_INFO, StorageProvider

_KEY_RESOURCE_OPERATIONS = ("discover", "match", "export", "rotate")
_BINDING_OPERATIONS = ("inspect", "update", "verify")


class _KeyResourceProvider(MatchingProvider, RotationProvider, Protocol):
    """The complete capability set required from a built-in key-resource provider."""


KeyResourceFactory = Callable[[AzureClientFactory], _KeyResourceProvider]
BindingFactory = Callable[[AzureClientFactory], ManagedBindingProvider]


@dataclass(frozen=True)
class _KeyResourceRegistration:
    name: str
    info: ProviderInfo
    key_slots: tuple[str, ...]
    factory: KeyResourceFactory


@dataclass(frozen=True)
class _BindingRegistration:
    name: str
    info: ProviderInfo
    location: BindingLocation
    included_by: Literal["automatic", "--env-file", "--sops-file"]
    management: BindingManagement
    factory: BindingFactory


def _dotenv_factory(_clients: AzureClientFactory) -> ManagedBindingProvider:
    return DotenvFileProvider()


def _sops_dotenv_factory(_clients: AzureClientFactory) -> ManagedBindingProvider:
    return SopsDotenvFileProvider()


_KEY_RESOURCES = (
    _KeyResourceRegistration(
        name="Storage Account",
        info=STORAGE_PROVIDER_INFO,
        key_slots=STORAGE_KEY_SLOTS,
        factory=StorageProvider,
    ),
    _KeyResourceRegistration(
        name="Azure AI, Cognitive Services, and Azure OpenAI",
        info=COGNITIVE_SERVICES_PROVIDER_INFO,
        key_slots=COGNITIVE_SERVICES_KEY_SLOTS,
        factory=CognitiveServicesProvider,
    ),
)
_SUPPORTED_KEY_RESOURCE_TYPES = tuple(
    resource_type for registration in _KEY_RESOURCES for resource_type in registration.info.resource_types
)

_BINDINGS = (
    _BindingRegistration(
        name="Foundry project connections",
        info=FOUNDRY_CONNECTIONS_PROVIDER_INFO,
        location=BindingLocation.azure,
        included_by="automatic",
        management=BindingManagement.update_and_verify,
        factory=FoundryConnectionsProvider,
    ),
    _BindingRegistration(
        name="App Service application settings",
        info=APP_SERVICE_SETTINGS_PROVIDER_INFO,
        location=BindingLocation.azure,
        included_by="automatic",
        management=BindingManagement.update_and_verify,
        factory=AppServiceSettingsProvider,
    ),
    _BindingRegistration(
        name="Plaintext dotenv assignments",
        info=DOTENV_FILE_PROVIDER_INFO,
        location=BindingLocation.local,
        included_by="--env-file",
        management=BindingManagement.update_and_verify,
        factory=_dotenv_factory,
    ),
    _BindingRegistration(
        name="SOPS-encrypted dotenv assignments",
        info=SOPS_DOTENV_FILE_PROVIDER_INFO,
        location=BindingLocation.local,
        included_by="--sops-file",
        management=BindingManagement.update_and_verify,
        factory=_sops_dotenv_factory,
    ),
)


def builtin_support_catalog() -> SupportCatalog:
    """Describe supported key resources and bindings without constructing clients."""

    return SupportCatalog(
        key_resources=tuple(
            SupportedKeyResource(
                name=registration.name,
                resource_type=registration.info.resource_types[0],
                key_slots=registration.key_slots,
                operations=_KEY_RESOURCE_OPERATIONS,
                contract_id=registration.info.name,
                contract_version=registration.info.contract_version,
            )
            for registration in _KEY_RESOURCES
        ),
        credential_bindings=tuple(
            SupportedCredentialBinding(
                name=registration.name,
                binding_type=registration.info.resource_types[0],
                location=registration.location,
                included_by=registration.included_by,
                key_resource_types=_SUPPORTED_KEY_RESOURCE_TYPES,
                management=registration.management,
                operations=_BINDING_OPERATIONS,
                contract_id=registration.info.name,
                contract_version=registration.info.contract_version,
            )
            for registration in _BINDINGS
        ),
    )


def builtin_provider_info() -> tuple[ProviderInfo, ...]:
    """Return metadata for providers included in this build without creating Azure clients."""

    return tuple(registration.info for registration in (*_KEY_RESOURCES, *_BINDINGS))


def _key_resource_providers(clients: AzureClientFactory) -> tuple[_KeyResourceProvider, ...]:
    return tuple(registration.factory(clients) for registration in _KEY_RESOURCES)


def builtin_discovery_providers(clients: AzureClientFactory) -> tuple[DiscoveryProvider, ...]:
    """Construct every supported metadata provider included in this build."""

    return _key_resource_providers(clients)


def builtin_matching_providers(clients: AzureClientFactory) -> tuple[MatchingProvider, ...]:
    """Construct supported providers permitted to retrieve candidates for matching."""

    return _key_resource_providers(clients)


def builtin_azure_binding_providers(clients: AzureClientFactory) -> tuple[BindingProvider, ...]:
    """Construct supported Azure providers permitted to inspect selected-key bindings."""

    return tuple(
        registration.factory(clients) for registration in _BINDINGS if registration.location is BindingLocation.azure
    )


def builtin_rotation_providers(clients: AzureClientFactory) -> tuple[RotationProvider, ...]:
    """Construct supported providers permitted to regenerate key slots."""

    return _key_resource_providers(clients)


def builtin_key_reading_providers(clients: AzureClientFactory) -> tuple[KeyReadingProvider, ...]:
    """Construct supported providers permitted to stream exact key states."""

    return _key_resource_providers(clients)


def builtin_managed_binding_providers(
    clients: AzureClientFactory,
    *,
    include_dotenv_file: bool = False,
    include_sops_dotenv_file: bool = False,
) -> tuple[ManagedBindingProvider, ...]:
    """Construct supported providers permitted to update and verify bindings."""

    included_local_options = {
        "--env-file": include_dotenv_file,
        "--sops-file": include_sops_dotenv_file,
    }
    return tuple(
        registration.factory(clients)
        for registration in _BINDINGS
        if registration.location is BindingLocation.azure or included_local_options.get(registration.included_by, False)
    )

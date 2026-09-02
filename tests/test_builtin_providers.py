"""Tests for the provider set shipped with Azurator."""

from __future__ import annotations

from typing import cast

from azurator.clients import AzureClientFactory
from azurator.providers.app_service_settings import AppServiceSettingsProvider
from azurator.providers.builtin import (
    builtin_azure_binding_providers,
    builtin_discovery_providers,
    builtin_key_reading_providers,
    builtin_managed_binding_providers,
    builtin_matching_providers,
    builtin_provider_info,
    builtin_rotation_providers,
    builtin_support_catalog,
)
from azurator.providers.cognitive_services import CognitiveServicesProvider
from azurator.providers.dotenv_file import DotenvFileProvider
from azurator.providers.foundry_connections import FoundryConnectionsProvider
from azurator.providers.sops_dotenv_file import SopsDotenvFileProvider
from azurator.providers.storage import StorageProvider


def test_builtin_registry_contains_each_reviewed_resource_provider_once() -> None:
    clients = cast(AzureClientFactory, object())

    providers = builtin_discovery_providers(clients)

    assert [type(provider) for provider in providers] == [StorageProvider, CognitiveServicesProvider]
    assert [provider.info.name for provider in providers] == ["azure-storage", "azure-cognitive-services"]
    assert {resource_type for provider in providers for resource_type in provider.info.resource_types} == {
        "Microsoft.Storage/storageAccounts",
        "Microsoft.CognitiveServices/accounts",
    }
    matching_providers = builtin_matching_providers(clients)
    assert [type(provider) for provider in matching_providers] == [StorageProvider, CognitiveServicesProvider]
    assert tuple(provider.info for provider in matching_providers) == tuple(provider.info for provider in providers)

    binding_providers = builtin_azure_binding_providers(clients)
    assert [type(provider) for provider in binding_providers] == [
        FoundryConnectionsProvider,
        AppServiceSettingsProvider,
    ]
    rotation_providers = builtin_rotation_providers(clients)
    assert [type(provider) for provider in rotation_providers] == [StorageProvider, CognitiveServicesProvider]
    key_reading_providers = builtin_key_reading_providers(clients)
    assert [type(provider) for provider in key_reading_providers] == [
        StorageProvider,
        CognitiveServicesProvider,
    ]
    assert tuple(provider.info for provider in key_reading_providers) == tuple(
        provider.info for provider in rotation_providers
    )
    managed_binding_providers = builtin_managed_binding_providers(clients)
    assert [type(provider) for provider in managed_binding_providers] == [
        FoundryConnectionsProvider,
        AppServiceSettingsProvider,
    ]
    managed_with_dotenv = builtin_managed_binding_providers(clients, include_dotenv_file=True)
    assert [type(provider) for provider in managed_with_dotenv] == [
        FoundryConnectionsProvider,
        AppServiceSettingsProvider,
        DotenvFileProvider,
    ]
    managed_with_local_files = builtin_managed_binding_providers(
        clients,
        include_dotenv_file=True,
        include_sops_dotenv_file=True,
    )
    assert [type(provider) for provider in managed_with_local_files] == [
        FoundryConnectionsProvider,
        AppServiceSettingsProvider,
        DotenvFileProvider,
        SopsDotenvFileProvider,
    ]
    assert builtin_provider_info() == (
        *(provider.info for provider in providers),
        *(provider.info for provider in binding_providers),
        *(provider.info for provider in managed_with_local_files[-2:]),
    )


def test_builtin_support_catalog_projects_domain_roles_without_clients() -> None:
    catalog = builtin_support_catalog()

    assert [resource.contract_id for resource in catalog.key_resources] == [
        "azure-storage",
        "azure-cognitive-services",
    ]
    assert [resource.key_slots for resource in catalog.key_resources] == [
        ("key1", "key2"),
        ("Key1", "Key2"),
    ]
    assert all(
        resource.operations == ("discover", "match", "export", "refresh", "rotate")
        for resource in catalog.key_resources
    )
    assert [binding.contract_id for binding in catalog.credential_bindings] == [
        "azure-foundry-connections",
        "azure-app-service-settings",
        "local-dotenv-file",
        "local-sops-dotenv-file",
    ]
    assert [binding.included_by for binding in catalog.credential_bindings] == [
        "automatic",
        "automatic",
        "--env-file",
        "--sops-file",
    ]

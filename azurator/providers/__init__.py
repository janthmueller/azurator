"""Reviewed Azure resource providers."""

from azurator.providers.app_service_settings import AppServiceSettingsProvider
from azurator.providers.base import BindingProvider, DiscoveryProvider, MatchingProvider
from azurator.providers.builtin import (
    builtin_azure_binding_providers,
    builtin_discovery_providers,
    builtin_matching_providers,
    builtin_provider_info,
)
from azurator.providers.cognitive_services import CognitiveServicesProvider
from azurator.providers.dotenv_file import DotenvFileProvider
from azurator.providers.foundry_connections import FoundryConnectionsProvider
from azurator.providers.sops_dotenv_file import SopsDotenvFileProvider
from azurator.providers.storage import StorageProvider

__all__ = [
    "CognitiveServicesProvider",
    "AppServiceSettingsProvider",
    "BindingProvider",
    "DiscoveryProvider",
    "DotenvFileProvider",
    "FoundryConnectionsProvider",
    "MatchingProvider",
    "SopsDotenvFileProvider",
    "StorageProvider",
    "builtin_azure_binding_providers",
    "builtin_discovery_providers",
    "builtin_matching_providers",
    "builtin_provider_info",
]

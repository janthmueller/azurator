"""Construction of authenticated application services at the command boundary."""

from __future__ import annotations

from typing import TextIO

from azurator.auth import AuthStore, CredentialFactory
from azurator.clients import SdkAzureClientFactory
from azurator.discovery import DiscoveryService
from azurator.execution import ExecutionService
from azurator.exporting import DotenvExportService
from azurator.matching import MatchingService
from azurator.models import AzureBindingInspection, Inventory, KeySlotSelection, MatchReport, SelectionReport
from azurator.providers.builtin import (
    builtin_azure_binding_providers,
    builtin_discovery_providers,
    builtin_key_reading_providers,
    builtin_managed_binding_providers,
    builtin_matching_providers,
    builtin_rotation_providers,
)


def _clients(subscription_id: str, auth_store: AuthStore) -> SdkAzureClientFactory:
    credential = CredentialFactory(auth_store).create(subscription_id)
    return SdkAzureClientFactory(credential)


def discover_inventory(subscription_id: str, auth_store: AuthStore) -> Inventory:
    clients = _clients(subscription_id, auth_store)
    return DiscoveryService(builtin_discovery_providers(clients)).discover(subscription_id)


def match_dotenv(
    subscription_id: str,
    stream: TextIO,
    auth_store: AuthStore,
    *,
    skip_azure_bindings: bool = False,
) -> MatchReport:
    clients = _clients(subscription_id, auth_store)
    inspection = AzureBindingInspection.skipped if skip_azure_bindings else AzureBindingInspection.enabled
    return MatchingService(
        builtin_matching_providers(clients),
        binding_providers=() if skip_azure_bindings else builtin_azure_binding_providers(clients),
        azure_binding_inspection=inspection,
    ).match_dotenv(subscription_id, stream)


def inspect_selection(
    subscription_id: str,
    inventory: Inventory,
    selections: tuple[KeySlotSelection, ...],
    auth_store: AuthStore,
    *,
    skip_azure_bindings: bool = False,
) -> SelectionReport:
    clients = _clients(subscription_id, auth_store)
    inspection = AzureBindingInspection.skipped if skip_azure_bindings else AzureBindingInspection.enabled
    return MatchingService(
        builtin_matching_providers(clients),
        binding_providers=() if skip_azure_bindings else builtin_azure_binding_providers(clients),
        azure_binding_inspection=inspection,
    ).inspect_selection(subscription_id, inventory, selections)


def execution_service(subscription_id: str, auth_store: AuthStore) -> ExecutionService:
    clients = _clients(subscription_id, auth_store)
    return ExecutionService(
        builtin_rotation_providers(clients),
        builtin_managed_binding_providers(
            clients,
            include_dotenv_file=True,
            include_sops_dotenv_file=True,
        ),
    )


def export_service(subscription_id: str, auth_store: AuthStore) -> DotenvExportService:
    clients = _clients(subscription_id, auth_store)
    return DotenvExportService(builtin_key_reading_providers(clients))

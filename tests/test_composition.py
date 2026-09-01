"""Tests for command-boundary service composition."""

from __future__ import annotations

from io import StringIO
from pathlib import Path
from unittest.mock import Mock, call

import pytest

import azurator.composition as composition
from azurator.auth import AuthStore
from azurator.models import (
    AzureBindingInspection,
    KeySlotSelection,
    SelectionReport,
)
from tests.cli_test_support import SUBSCRIPTION_ID, make_inventory, make_match_report


def _patch_client_construction(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Mock, Mock, Mock]:
    credential = Mock(name="credential")
    clients = Mock(name="clients")
    credential_factory_instance = Mock(name="credential-factory-instance")
    credential_factory_instance.create.return_value = credential
    credential_factory = Mock(return_value=credential_factory_instance)
    client_factory = Mock(return_value=clients)
    monkeypatch.setattr(composition, "CredentialFactory", credential_factory)
    monkeypatch.setattr(composition, "SdkAzureClientFactory", client_factory)
    return clients, credential_factory, client_factory


def test_discovery_composition_constructs_clients_and_supported_providers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = AuthStore(tmp_path / "auth.json")
    clients, credential_factory, client_factory = _patch_client_construction(monkeypatch)
    inventory = make_inventory()
    providers = (Mock(name="storage-provider"),)
    provider_factory = Mock(return_value=providers)
    service = Mock(name="discovery-service")
    service.discover.return_value = inventory
    service_factory = Mock(return_value=service)
    monkeypatch.setattr(composition, "builtin_discovery_providers", provider_factory)
    monkeypatch.setattr(composition, "DiscoveryService", service_factory)

    assert composition.discover_inventory(SUBSCRIPTION_ID, store) is inventory
    credential_factory.assert_called_once_with(store)
    credential_factory.return_value.create.assert_called_once_with(SUBSCRIPTION_ID)
    client_factory.assert_called_once_with(credential_factory.return_value.create.return_value)
    provider_factory.assert_called_once_with(clients)
    service_factory.assert_called_once_with(providers)
    service.discover.assert_called_once_with(SUBSCRIPTION_ID)


def test_match_composition_includes_azure_bindings_by_default(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = AuthStore(tmp_path / "auth.json")
    clients, _, _ = _patch_client_construction(monkeypatch)
    report = make_match_report()
    key_providers = (Mock(name="key-provider"),)
    binding_providers = (Mock(name="binding-provider"),)
    key_provider_factory = Mock(return_value=key_providers)
    binding_provider_factory = Mock(return_value=binding_providers)
    service = Mock(name="matching-service")
    service.match_dotenv.return_value = report
    service_factory = Mock(return_value=service)
    monkeypatch.setattr(composition, "builtin_matching_providers", key_provider_factory)
    monkeypatch.setattr(composition, "builtin_azure_binding_providers", binding_provider_factory)
    monkeypatch.setattr(composition, "MatchingService", service_factory)
    stream = StringIO("TOKEN=must-not-render\n")

    assert composition.match_dotenv(SUBSCRIPTION_ID, stream, store) is report
    key_provider_factory.assert_called_once_with(clients)
    binding_provider_factory.assert_called_once_with(clients)
    service_factory.assert_called_once_with(
        key_providers,
        binding_providers=binding_providers,
        azure_binding_inspection=AzureBindingInspection.enabled,
    )
    service.match_dotenv.assert_called_once_with(SUBSCRIPTION_ID, stream)


def test_selection_composition_omits_all_azure_bindings_when_requested(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = AuthStore(tmp_path / "auth.json")
    clients, _, _ = _patch_client_construction(monkeypatch)
    inventory = make_inventory()
    selection = KeySlotSelection(
        resource_id=inventory.resources[0].resource_id,
        key_slot="key1",
    )
    report = SelectionReport(
        subscription_id=SUBSCRIPTION_ID,
        generated_at=inventory.generated_at,
        azure_binding_inspection=AzureBindingInspection.skipped,
        providers=inventory.providers,
        resources=(),
        inspections=(),
        selected_slots=(selection,),
        warnings=(),
    )
    key_providers = (Mock(name="key-provider"),)
    key_provider_factory = Mock(return_value=key_providers)
    binding_provider_factory = Mock()
    service = Mock(name="matching-service")
    service.inspect_selection.return_value = report
    service_factory = Mock(return_value=service)
    monkeypatch.setattr(composition, "builtin_matching_providers", key_provider_factory)
    monkeypatch.setattr(composition, "builtin_azure_binding_providers", binding_provider_factory)
    monkeypatch.setattr(composition, "MatchingService", service_factory)

    assert (
        composition.inspect_selection(
            SUBSCRIPTION_ID,
            inventory,
            (selection,),
            store,
            skip_azure_bindings=True,
        )
        is report
    )
    key_provider_factory.assert_called_once_with(clients)
    binding_provider_factory.assert_not_called()
    service_factory.assert_called_once_with(
        key_providers,
        binding_providers=(),
        azure_binding_inspection=AzureBindingInspection.skipped,
    )
    service.inspect_selection.assert_called_once_with(
        SUBSCRIPTION_ID,
        inventory,
        (selection,),
    )


def test_mutation_and_export_composition_use_the_exact_provider_sets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = AuthStore(tmp_path / "auth.json")
    clients, _, _ = _patch_client_construction(monkeypatch)
    rotation_providers = (Mock(name="rotation-provider"),)
    binding_providers = (Mock(name="managed-binding-provider"),)
    key_reading_providers = (Mock(name="key-reading-provider"),)
    rotation_factory = Mock(return_value=rotation_providers)
    binding_factory = Mock(return_value=binding_providers)
    key_reading_factory = Mock(return_value=key_reading_providers)
    execution = Mock(name="execution-service")
    exporter = Mock(name="export-service")
    execution_factory = Mock(return_value=execution)
    export_factory = Mock(return_value=exporter)
    monkeypatch.setattr(composition, "builtin_rotation_providers", rotation_factory)
    monkeypatch.setattr(composition, "builtin_managed_binding_providers", binding_factory)
    monkeypatch.setattr(composition, "builtin_key_reading_providers", key_reading_factory)
    monkeypatch.setattr(composition, "ExecutionService", execution_factory)
    monkeypatch.setattr(composition, "DotenvExportService", export_factory)

    assert composition.execution_service(SUBSCRIPTION_ID, store) is execution
    assert composition.export_service(SUBSCRIPTION_ID, store) is exporter
    assert rotation_factory.call_args_list == [call(clients)]
    binding_factory.assert_called_once_with(
        clients,
        include_dotenv_file=True,
        include_sops_dotenv_file=True,
    )
    execution_factory.assert_called_once_with(rotation_providers, binding_providers)
    key_reading_factory.assert_called_once_with(clients)
    export_factory.assert_called_once_with(key_reading_providers)

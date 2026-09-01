"""Read-only Foundry Storage and Azure OpenAI connection inspection tests."""

from __future__ import annotations

from typing import cast

import pytest
from azure.core.exceptions import HttpResponseError, ServiceRequestError, ServiceResponseError

from azurator.clients import (
    AIProjectClientLike,
    AzureClientFactory,
)
from azurator.models import (
    BindingInspectionStatus,
    BindingManagement,
)
from azurator.providers.foundry_connections import FoundryConnectionsProvider
from tests.foundry_test_support import (
    PROJECT_ID,
    SUBSCRIPTION_ID,
    FakeClientFactory,
    FakeConnection,
    FakeConnectionOperations,
    FakeCredentials,
    FakeManagementClient,
    FakeProject,
    FakeProjectOperations,
    make_account,
    make_cognitive_resource,
    make_provider,
    make_storage_resource,
)


def test_foundry_provider_contract_and_empty_selection_do_not_construct_clients() -> None:
    management_client = FakeManagementClient(FakeProjectOperations())
    factory = FakeClientFactory(management_client, {})
    provider = FoundryConnectionsProvider(cast(AzureClientFactory, factory))

    result = provider.inspect_bindings(
        SUBSCRIPTION_ID,
        (make_account(),),
        frozenset({"/not/a/discovered/storage/resource"}),
        lambda resource_id, value: None,
    )

    assert provider.info.name == "azure-foundry-connections"
    assert provider.key_resource_types == (
        "Microsoft.Storage/storageAccounts",
        "Microsoft.CognitiveServices/accounts",
    )
    assert result.inspections == ()
    assert result.bindings == ()
    assert result.warnings == ()
    assert factory.subscription_ids == []


def test_foundry_rejects_invalid_account_scope_before_project_enumeration() -> None:
    selected = make_storage_resource("accountone")
    invalid_account = make_account().model_copy(update={"resource_id": "/invalid/foundry/account"})
    management_client = FakeManagementClient(FakeProjectOperations())
    factory = FakeClientFactory(management_client, {})
    provider = FoundryConnectionsProvider(cast(AzureClientFactory, factory))

    result = provider.inspect_bindings(
        SUBSCRIPTION_ID,
        (invalid_account, selected),
        frozenset({selected.resource_id}),
        lambda resource_id, value: None,
    )

    assert result.inspections[0].status is BindingInspectionStatus.unavailable
    assert result.warnings[-1].code == "foundry-account-scope-invalid"
    assert management_client.operations.calls == []
    assert management_client.closed


def test_foundry_inspection_requests_credentials_only_for_selected_storage_targets() -> None:
    selected = make_storage_resource("accountone")
    unselected = make_storage_resource("accounttwo")
    listed_selected = FakeConnection(
        id="selected-id",
        name="selected-connection",
        credentials=FakeCredentials(None),
        metadata={"ResourceId": unselected.resource_id},
    )
    listed_unselected = FakeConnection(
        id="unselected-id",
        name="unselected-connection",
        target="https://accounttwo.blob.core.windows.net/",
        credentials=FakeCredentials(None),
        metadata={"ResourceId": selected.resource_id},
    )
    detailed_credentials = FakeCredentials("selected-storage-secret")
    detailed = FakeConnection(
        id="selected-id",
        name="selected-connection",
        credentials=detailed_credentials,
        metadata={"resourceId": unselected.resource_id},
    )
    operations = FakeConnectionOperations(
        (listed_selected, listed_unselected),
        {"selected-connection": detailed},
    )
    project = FakeProject()
    provider, management_client, project_client, factory = make_provider(project, operations)
    identified: list[tuple[str, str]] = []

    def identify(resource_id: str, value: str) -> str | None:
        identified.append((resource_id, value))
        return "key1" if value == "selected-storage-secret" else None

    result = provider.inspect_bindings(
        SUBSCRIPTION_ID,
        (make_account(), selected, unselected),
        frozenset({selected.resource_id}),
        identify,
    )

    assert factory.subscription_ids == [SUBSCRIPTION_ID]
    assert factory.project_endpoints == ["https://foundryone.services.ai.azure.com/api/projects/projectone"]
    assert management_client.operations.calls == [("rg", "foundryone", "2025-06-01", False)]
    assert operations.list_calls == [("AzureStorageAccount", False)]
    assert operations.get_calls == [("selected-connection", True, False)]
    assert identified == [(selected.resource_id, "selected-storage-secret")]
    assert result.inspections[0].status is BindingInspectionStatus.inspected
    assert result.inspections[0].scopes_inspected == 1
    assert len(result.bindings) == 1
    binding = result.bindings[0]
    assert binding.binding_id == f"{PROJECT_ID}/connections/selected-connection"
    assert binding.scope_name == "projectone"
    assert binding.key_resource_id == selected.resource_id
    assert binding.key_slot == "key1"
    assert binding.target == "https://accountone.blob.core.windows.net/"
    assert binding.management is BindingManagement.update_and_verify
    assert [warning.code for warning in result.warnings] == ["foundry-binding-coverage-limited"]
    assert "AzureStorageAccount/AccountKey" in result.warnings[0].message
    assert "AzureOpenAI/ApiKey" not in result.warnings[0].message
    assert "selected-storage-secret" not in result.model_dump_json()
    assert "key" not in detailed_credentials
    assert management_client.closed
    assert project_client.closed


def test_foundry_inspection_resolves_storage_target_url_and_constructs_project_endpoint() -> None:
    selected = make_storage_resource("accountone")
    listed = FakeConnection(
        id="connection-id",
        name="storage-connection",
        credentials=FakeCredentials(None),
        metadata={},
    )
    detailed = FakeConnection(
        id="connection-id",
        name="storage-connection",
        credentials=FakeCredentials("storage-secret-two"),
        metadata={},
    )
    operations = FakeConnectionOperations((listed,), {"storage-connection": detailed})
    provider, _, _, factory = make_provider(FakeProject(), operations)

    result = provider.inspect_bindings(
        SUBSCRIPTION_ID,
        (make_account(), selected),
        frozenset({selected.resource_id}),
        lambda resource_id, value: "key2",
    )

    assert factory.project_endpoints == ["https://foundryone.services.ai.azure.com/api/projects/projectone"]
    assert result.bindings[0].key_slot == "key2"


def test_foundry_inspection_attributes_an_exact_azure_openai_api_key_connection() -> None:
    selected = make_cognitive_resource()
    listed = FakeConnection(
        id="openai-connection-id",
        name="openai-connection",
        type="AzureOpenAI",
        target="https://openai-one.openai.azure.com/",
        credentials=FakeCredentials(None, credential_type="ApiKey"),
    )
    detailed_credentials = FakeCredentials("selected-ai-secret", credential_type="ApiKey")
    detailed = FakeConnection(
        id="openai-connection-id",
        name="openai-connection",
        type="AzureOpenAI",
        target="https://openai-one.openai.azure.com/",
        credentials=detailed_credentials,
    )
    operations = FakeConnectionOperations((listed,), {"openai-connection": detailed})
    provider, management_client, project_client, _ = make_provider(FakeProject(), operations)
    identified: list[tuple[str, str]] = []

    result = provider.inspect_bindings(
        SUBSCRIPTION_ID,
        (make_account(), selected),
        frozenset({selected.resource_id}),
        lambda resource_id, value: identified.append((resource_id, value)) or "Key2",
    )

    assert operations.list_calls == [("AzureOpenAI", False)]
    assert operations.get_calls == [("openai-connection", True, False)]
    assert identified == [(selected.resource_id, "selected-ai-secret")]
    assert result.inspections[0].status is BindingInspectionStatus.inspected
    assert len(result.bindings) == 1
    assert result.bindings[0].key_resource_id == selected.resource_id
    assert result.bindings[0].key_slot == "Key2"
    assert result.bindings[0].management is BindingManagement.update_and_verify
    assert result.warnings[0].code == "foundry-binding-coverage-limited"
    assert "AzureOpenAI/ApiKey" in result.warnings[0].message
    assert "AzureStorageAccount/AccountKey" not in result.warnings[0].message
    assert "selected-ai-secret" not in result.model_dump_json()
    assert "key" not in detailed_credentials
    assert management_client.closed
    assert project_client.closed


def test_foundry_azure_openai_connection_does_not_probe_account_key_credentials() -> None:
    selected = make_cognitive_resource()
    listed = FakeConnection(
        id="openai-connection-id",
        name="openai-connection",
        type="AzureOpenAI",
        target="https://openai-one.openai.azure.com/",
    )
    detailed_credentials = FakeCredentials("must-not-be-compared", credential_type="AccountKey")
    detailed = FakeConnection(
        id="openai-connection-id",
        name="openai-connection",
        type="AzureOpenAI",
        target="https://openai-one.openai.azure.com/",
        credentials=detailed_credentials,
    )
    operations = FakeConnectionOperations((listed,), {"openai-connection": detailed})
    provider, _, _, _ = make_provider(FakeProject(), operations)
    identified: list[str] = []

    result = provider.inspect_bindings(
        SUBSCRIPTION_ID,
        (make_account(), selected),
        frozenset({selected.resource_id}),
        lambda resource_id, value: identified.append(value) or None,
    )

    assert identified == []
    assert result.bindings[0].management is BindingManagement.observed_only
    assert result.warnings[-1].code == "foundry-connection-credential-unavailable"
    assert "must-not-be-compared" not in result.model_dump_json()
    assert "key" not in detailed_credentials


def test_foundry_inspection_rejects_target_drift_between_list_and_credential_read() -> None:
    selected = make_cognitive_resource()
    listed = FakeConnection(
        id="openai-connection-id",
        name="openai-connection",
        type="AzureOpenAI",
        target="https://openai-one.openai.azure.com/",
        credentials=FakeCredentials(None, credential_type="ApiKey"),
    )
    detailed_credentials = FakeCredentials("must-not-be-attributed", credential_type="ApiKey")
    detailed = FakeConnection(
        id="openai-connection-id",
        name="openai-connection",
        type="AzureOpenAI",
        target="https://openai-one.openai.azure.com",
        credentials=detailed_credentials,
    )
    operations = FakeConnectionOperations((listed,), {"openai-connection": detailed})
    provider, _, _, _ = make_provider(FakeProject(), operations)
    identified: list[str] = []

    result = provider.inspect_bindings(
        SUBSCRIPTION_ID,
        (make_account(), selected),
        frozenset({selected.resource_id}),
        lambda resource_id, value: identified.append(value) or None,
    )

    assert identified == []
    assert result.bindings[0].management is BindingManagement.observed_only
    assert result.warnings[-1].code == "foundry-connection-credential-unavailable"
    assert "must-not-be-attributed" not in result.model_dump_json()
    assert "key" not in detailed_credentials


def test_foundry_project_permission_failure_is_scoped_and_redacted() -> None:
    sensitive_value = "foundry-error-must-not-render"
    error = HttpResponseError(message=sensitive_value)
    error.status_code = 403
    management_client = FakeManagementClient(FakeProjectOperations(error=error))
    factory = FakeClientFactory(management_client, {})
    provider = FoundryConnectionsProvider(cast(AzureClientFactory, factory))
    selected = make_storage_resource("accountone")

    result = provider.inspect_bindings(
        SUBSCRIPTION_ID,
        (make_account(), selected),
        frozenset({selected.resource_id}),
        lambda resource_id, value: None,
    )

    assert result.inspections[0].status is BindingInspectionStatus.unavailable
    assert result.inspections[0].scopes_inspected == 0
    assert [warning.code for warning in result.warnings] == [
        "foundry-binding-coverage-limited",
        "foundry-project-list-forbidden",
    ]
    assert sensitive_value not in result.model_dump_json()
    assert factory.project_endpoints == []
    assert management_client.closed


@pytest.mark.parametrize(
    ("error_type", "phase"),
    ((ServiceRequestError, "request"), (ServiceResponseError, "response")),
)
def test_foundry_project_transport_failure_is_scoped_and_redacted(
    error_type: type[Exception],
    phase: str,
) -> None:
    sensitive_value = "foundry-transport-error-must-not-render"
    management_client = FakeManagementClient(FakeProjectOperations(error=error_type(sensitive_value)))
    factory = FakeClientFactory(management_client, {})
    provider = FoundryConnectionsProvider(cast(AzureClientFactory, factory))
    selected = make_storage_resource("accountone")

    result = provider.inspect_bindings(
        SUBSCRIPTION_ID,
        (make_account(), selected),
        frozenset({selected.resource_id}),
        lambda resource_id, value: None,
    )

    assert result.inspections[0].status is BindingInspectionStatus.unavailable
    assert result.warnings[-1].code == f"foundry-project-list-{phase}-failed"
    assert sensitive_value not in result.model_dump_json()
    assert management_client.closed


def test_foundry_connection_list_failure_is_scoped_and_redacted() -> None:
    sensitive_value = "connection-list-error-must-not-render"
    error = HttpResponseError(message=sensitive_value)
    error.status_code = 500
    selected = make_storage_resource("accountone")
    operations = FakeConnectionOperations((), {}, list_error=error)
    provider, _, project_client, _ = make_provider(FakeProject(), operations)

    result = provider.inspect_bindings(
        SUBSCRIPTION_ID,
        (make_account(), selected),
        frozenset({selected.resource_id}),
        lambda resource_id, value: None,
    )

    assert result.inspections[0].status is BindingInspectionStatus.unavailable
    assert result.warnings[-1].code == "foundry-connection-list-failed"
    assert sensitive_value not in result.model_dump_json()
    assert project_client.closed


@pytest.mark.parametrize(
    ("error_type", "phase"),
    ((ServiceRequestError, "request"), (ServiceResponseError, "response")),
)
def test_foundry_connection_list_transport_failure_is_scoped_and_redacted(
    error_type: type[Exception],
    phase: str,
) -> None:
    sensitive_value = "connection-list-transport-secret"
    selected = make_storage_resource("accountone")
    operations = FakeConnectionOperations((), {}, list_error=error_type(sensitive_value))
    provider, _, project_client, _ = make_provider(FakeProject(), operations)

    result = provider.inspect_bindings(
        SUBSCRIPTION_ID,
        (make_account(), selected),
        frozenset({selected.resource_id}),
        lambda resource_id, value: None,
    )

    assert result.inspections[0].status is BindingInspectionStatus.unavailable
    assert result.warnings[-1].code == f"foundry-connection-list-{phase}-failed"
    assert sensitive_value not in result.model_dump_json()
    assert project_client.closed


def test_foundry_credential_failure_keeps_binding_without_slot_and_is_redacted() -> None:
    sensitive_value = "credential-error-must-not-render"
    error = HttpResponseError(message=sensitive_value)
    error.status_code = 403
    selected = make_storage_resource("accountone")
    listed = FakeConnection(
        id="connection-id",
        name="storage-connection",
        credentials=FakeCredentials(None),
        metadata={"ResourceId": selected.resource_id},
    )
    operations = FakeConnectionOperations((listed,), {}, get_error=error)
    provider, _, project_client, _ = make_provider(FakeProject(), operations)

    result = provider.inspect_bindings(
        SUBSCRIPTION_ID,
        (make_account(), selected),
        frozenset({selected.resource_id}),
        lambda resource_id, value: None,
    )

    assert result.inspections[0].status is BindingInspectionStatus.partial
    assert result.bindings[0].key_slot is None
    assert result.bindings[0].management is BindingManagement.observed_only
    assert result.warnings[-1].code == "foundry-connection-credential-forbidden"
    assert sensitive_value not in result.model_dump_json()
    assert project_client.closed


@pytest.mark.parametrize(
    ("error_type", "phase"),
    ((ServiceRequestError, "request"), (ServiceResponseError, "response")),
)
def test_foundry_credential_transport_failure_is_observed_only_and_redacted(
    error_type: type[Exception],
    phase: str,
) -> None:
    sensitive_value = "credential-transport-secret"
    selected = make_storage_resource("accountone")
    listed = FakeConnection(
        id="connection-id",
        name="storage-connection",
        credentials=FakeCredentials(None),
    )
    operations = FakeConnectionOperations((listed,), {}, get_error=error_type(sensitive_value))
    provider, _, project_client, _ = make_provider(FakeProject(), operations)

    result = provider.inspect_bindings(
        SUBSCRIPTION_ID,
        (make_account(), selected),
        frozenset({selected.resource_id}),
        lambda resource_id, value: None,
    )

    assert result.inspections[0].status is BindingInspectionStatus.partial
    assert result.bindings[0].management is BindingManagement.observed_only
    assert result.warnings[-1].code == f"foundry-connection-credential-{phase}-failed"
    assert sensitive_value not in result.model_dump_json()
    assert project_client.closed


def test_foundry_translates_project_client_endpoint_rejection() -> None:
    class RejectingProjectFactory(FakeClientFactory):
        def ai_project(self, endpoint: str) -> AIProjectClientLike:
            self.project_endpoints.append(endpoint)
            raise ValueError("sensitive SDK validation detail")

    selected = make_storage_resource("accountone")
    management_client = FakeManagementClient(FakeProjectOperations((FakeProject(),)))
    factory = RejectingProjectFactory(management_client, {})
    provider = FoundryConnectionsProvider(cast(AzureClientFactory, factory))

    result = provider.inspect_bindings(
        SUBSCRIPTION_ID,
        (make_account(), selected),
        frozenset({selected.resource_id}),
        lambda resource_id, value: None,
    )

    assert result.inspections[0].status is BindingInspectionStatus.unavailable
    assert result.warnings[-1].code == "foundry-project-endpoint-invalid"
    assert "sensitive SDK validation detail" not in result.model_dump_json()


def test_foundry_rejects_duplicate_connection_records_without_fetching_credentials() -> None:
    selected = make_storage_resource("accountone")
    duplicate = FakeConnection(
        id="connection-id",
        name="duplicate-connection",
        credentials=FakeCredentials(None),
        metadata={},
    )
    detailed = FakeConnection(
        id="connection-id",
        name="duplicate-connection",
        credentials=FakeCredentials("selected-storage-secret"),
        metadata={},
    )
    operations = FakeConnectionOperations((duplicate, duplicate), {"duplicate-connection": detailed})
    provider, _, _, _ = make_provider(FakeProject(), operations)

    result = provider.inspect_bindings(
        SUBSCRIPTION_ID,
        (make_account(), selected),
        frozenset({selected.resource_id}),
        lambda resource_id, value: None,
    )

    assert result.inspections[0].status is BindingInspectionStatus.partial
    assert result.warnings[-1].code == "foundry-connection-metadata-invalid"
    assert operations.get_calls == [("duplicate-connection", True, False)]


def test_foundry_rejects_unexpected_connection_type_from_filtered_list() -> None:
    selected = make_storage_resource("accountone")
    malformed = FakeConnection(
        id="connection-id",
        name="wrong-type",
        type="AzureBlob",
        credentials=FakeCredentials(None),
        metadata={"ResourceId": selected.resource_id},
    )
    operations = FakeConnectionOperations((malformed,), {})
    provider, _, _, _ = make_provider(FakeProject(), operations)

    result = provider.inspect_bindings(
        SUBSCRIPTION_ID,
        (make_account(), selected),
        frozenset({selected.resource_id}),
        lambda resource_id, value: None,
    )

    assert result.inspections[0].status is BindingInspectionStatus.partial
    assert result.bindings == ()
    assert result.warnings[-1].code == "foundry-connection-metadata-invalid"
    assert operations.get_calls == []


@pytest.mark.parametrize(
    ("credential", "expected_code"),
    (
        (None, "foundry-connection-credential-unavailable"),
        ("current-but-unmatched-key", "foundry-connection-key-unmatched"),
    ),
)
def test_foundry_reports_unusable_or_unmatched_connection_credentials(
    credential: str | None,
    expected_code: str,
) -> None:
    selected = make_storage_resource("accountone")
    listed = FakeConnection(
        id="connection-id",
        name="storage-connection",
        target="https://accountone.blob.core.windows.net/",
        credentials=FakeCredentials(None),
        metadata={},
    )
    detailed_credentials = FakeCredentials(credential)
    detailed = FakeConnection(
        id="connection-id",
        name="storage-connection",
        target="https://accountone.blob.core.windows.net/",
        credentials=detailed_credentials,
        metadata={},
    )
    operations = FakeConnectionOperations((listed,), {"storage-connection": detailed})
    provider, _, _, _ = make_provider(FakeProject(), operations)

    result = provider.inspect_bindings(
        SUBSCRIPTION_ID,
        (make_account(), selected),
        frozenset({selected.resource_id}),
        lambda resource_id, value: None,
    )

    assert result.inspections[0].status is BindingInspectionStatus.partial
    assert result.bindings[0].key_slot is None
    assert result.bindings[0].management is BindingManagement.observed_only
    assert result.warnings[-1].code == expected_code
    assert credential is None or credential not in result.model_dump_json()
    assert "key" not in detailed_credentials


def test_foundry_inspection_rejects_extra_credential_fields_without_comparing_the_key() -> None:
    selected = make_storage_resource("accountone")
    listed = FakeConnection(id="connection-id", name="storage-connection")
    detailed_credentials = FakeCredentials("must-not-be-compared")
    detailed_credentials["unexpected"] = "contract-drift"
    detailed = FakeConnection(
        id="connection-id",
        name="storage-connection",
        credentials=detailed_credentials,
    )
    operations = FakeConnectionOperations((listed,), {"storage-connection": detailed})
    provider, _, _, _ = make_provider(FakeProject(), operations)
    identified: list[str] = []

    result = provider.inspect_bindings(
        SUBSCRIPTION_ID,
        (make_account(), selected),
        frozenset({selected.resource_id}),
        lambda resource_id, value: identified.append(value) or "key1",
    )

    assert identified == []
    assert result.inspections[0].status is BindingInspectionStatus.partial
    assert result.bindings[0].management is BindingManagement.observed_only
    assert result.warnings[-1].code == "foundry-connection-credential-unavailable"
    assert "must-not-be-compared" not in result.model_dump_json()
    assert detailed_credentials == {}


def test_foundry_does_not_probe_an_api_key_credential_as_an_account_key() -> None:
    selected = make_storage_resource("accountone")
    listed = FakeConnection(id="connection-id", name="storage-connection")
    detailed_credentials = FakeCredentials("must-not-be-compared", credential_type="ApiKey")
    detailed = FakeConnection(
        id="connection-id",
        name="storage-connection",
        credentials=detailed_credentials,
    )
    operations = FakeConnectionOperations((listed,), {"storage-connection": detailed})
    provider, _, _, _ = make_provider(FakeProject(), operations)
    identified: list[str] = []

    result = provider.inspect_bindings(
        SUBSCRIPTION_ID,
        (make_account(), selected),
        frozenset({selected.resource_id}),
        lambda resource_id, value: identified.append(value) or None,
    )

    assert identified == []
    assert result.bindings[0].key_slot is None
    assert result.bindings[0].management is BindingManagement.observed_only
    assert result.warnings[-1].code == "foundry-connection-credential-unavailable"
    assert "must-not-be-compared" not in result.model_dump_json()
    assert "key" not in detailed_credentials


def test_foundry_rejects_wrong_project_resource_type() -> None:
    selected = make_storage_resource("accountone")
    project = FakeProject(type="Microsoft.CognitiveServices/accounts/deployments")
    management_client = FakeManagementClient(FakeProjectOperations((project,)))
    factory = FakeClientFactory(management_client, {})
    provider = FoundryConnectionsProvider(cast(AzureClientFactory, factory))

    result = provider.inspect_bindings(
        SUBSCRIPTION_ID,
        (make_account(), selected),
        frozenset({selected.resource_id}),
        lambda resource_id, value: None,
    )

    assert result.inspections[0].status is BindingInspectionStatus.unavailable
    assert result.warnings[-1].code == "foundry-project-metadata-invalid"
    assert factory.project_endpoints == []


@pytest.mark.parametrize(
    "project",
    (
        FakeProject(id="/subscriptions/other/projects/projectone"),
        FakeProject(id=f"{PROJECT_ID}/nested", name="foundryone/projectone/nested"),
    ),
)
def test_foundry_rejects_project_identity_disagreement(project: FakeProject) -> None:
    selected = make_storage_resource("accountone")
    management_client = FakeManagementClient(FakeProjectOperations((project,)))
    factory = FakeClientFactory(management_client, {})
    provider = FoundryConnectionsProvider(cast(AzureClientFactory, factory))

    result = provider.inspect_bindings(
        SUBSCRIPTION_ID,
        (make_account(), selected),
        frozenset({selected.resource_id}),
        lambda resource_id, value: None,
    )

    assert result.inspections[0].status is BindingInspectionStatus.unavailable
    assert result.warnings[-1].code == "foundry-project-metadata-invalid"
    assert factory.project_endpoints == []


@pytest.mark.parametrize(
    "target",
    (
        "https://accountone.blob.core.windows.net.attacker.example/",
        "https://accountone.file.core.windows.net/",
        "https://accountone.blob.core.windows.net:443/",
        "https://accountone.blob.core.usgovcloudapi.net/",
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/accountone",
    ),
)
def test_foundry_rejects_unreviewed_storage_target_shapes(target: str) -> None:
    selected = make_storage_resource("accountone")
    listed = FakeConnection(
        id="connection-id",
        name="storage-connection",
        target=target,
        credentials=FakeCredentials(None),
        metadata={},
    )
    operations = FakeConnectionOperations((listed,), {})
    provider, _, _, _ = make_provider(FakeProject(), operations)

    result = provider.inspect_bindings(
        SUBSCRIPTION_ID,
        (make_account(), selected),
        frozenset({selected.resource_id}),
        lambda resource_id, value: None,
    )

    assert result.inspections[0].status is BindingInspectionStatus.partial
    assert result.bindings == ()
    assert result.warnings[-1].code == "foundry-storage-target-unresolved"
    assert operations.get_calls == []


def test_foundry_ignores_a_valid_storage_target_that_cannot_identify_a_selected_resource() -> None:
    selected = make_storage_resource("accountone")
    unrelated = FakeConnection(
        id="connection-id",
        name="storage-connection",
        target="https://accounttwo.blob.core.windows.net/",
        credentials=FakeCredentials(None),
        metadata={},
    )
    operations = FakeConnectionOperations((unrelated,), {})
    provider, _, _, _ = make_provider(FakeProject(), operations)

    result = provider.inspect_bindings(
        SUBSCRIPTION_ID,
        (make_account(), selected),
        frozenset({selected.resource_id}),
        lambda resource_id, value: None,
    )

    assert result.inspections[0].status is BindingInspectionStatus.inspected
    assert result.bindings == ()
    assert [warning.code for warning in result.warnings] == ["foundry-binding-coverage-limited"]
    assert operations.get_calls == []


def test_foundry_blocks_an_ambiguous_selected_target_without_fetching_credentials() -> None:
    selected = make_storage_resource("accountone")
    duplicate_identity = selected.model_copy(
        update={"resource_id": selected.resource_id.replace("/resourceGroups/rg/", "/resourceGroups/other/")}
    )
    listed = FakeConnection(
        id="connection-id",
        name="storage-connection",
        credentials=FakeCredentials(None),
        metadata={},
    )
    operations = FakeConnectionOperations((listed,), {})
    provider, _, _, _ = make_provider(FakeProject(), operations)

    result = provider.inspect_bindings(
        SUBSCRIPTION_ID,
        (make_account(), selected, duplicate_identity),
        frozenset({selected.resource_id, duplicate_identity.resource_id}),
        lambda resource_id, value: None,
    )

    assert all(inspection.status is BindingInspectionStatus.partial for inspection in result.inspections)
    assert result.bindings == ()
    assert result.warnings[-1].code == "foundry-storage-target-unresolved"
    assert operations.get_calls == []


@pytest.mark.parametrize(
    "target",
    (
        "https://openai-one.openai.azure.com:443/",
        "https://openai-one.openai.azure.com/openai",
        "https://openai-one.openai.azure.com/?api-version=v1",
        "http://openai-one.openai.azure.com/",
    ),
)
def test_foundry_rejects_unreviewed_or_unmatched_cognitive_target_shapes(target: str) -> None:
    selected = make_cognitive_resource()
    listed = FakeConnection(
        id="openai-connection-id",
        name="openai-connection",
        type="AzureOpenAI",
        target=target,
        credentials=FakeCredentials(None, credential_type="ApiKey"),
    )
    operations = FakeConnectionOperations((listed,), {})
    provider, _, _, _ = make_provider(FakeProject(), operations)

    result = provider.inspect_bindings(
        SUBSCRIPTION_ID,
        (make_account(), selected),
        frozenset({selected.resource_id}),
        lambda resource_id, value: None,
    )

    assert result.inspections[0].status is BindingInspectionStatus.partial
    assert result.bindings == ()
    assert result.warnings[-1].code == "foundry-cognitive-target-unresolved"
    assert operations.get_calls == []


def test_foundry_ignores_a_valid_cognitive_target_that_cannot_identify_a_selected_resource() -> None:
    selected = make_cognitive_resource()
    unrelated = FakeConnection(
        id="openai-connection-id",
        name="openai-connection",
        type="AzureOpenAI",
        target="https://different.openai.azure.com/",
        credentials=FakeCredentials(None, credential_type="ApiKey"),
    )
    operations = FakeConnectionOperations((unrelated,), {})
    provider, _, _, _ = make_provider(FakeProject(), operations)

    result = provider.inspect_bindings(
        SUBSCRIPTION_ID,
        (make_account(), selected),
        frozenset({selected.resource_id}),
        lambda resource_id, value: None,
    )

    assert result.inspections[0].status is BindingInspectionStatus.inspected
    assert result.bindings == ()
    assert [warning.code for warning in result.warnings] == ["foundry-binding-coverage-limited"]
    assert operations.get_calls == []

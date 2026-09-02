"""Foundry Storage and Azure OpenAI connection mutation tests."""

from __future__ import annotations

import pytest
from azure.core.exceptions import HttpResponseError, ServiceRequestError, ServiceResponseError

from azurator.models import (
    BindingLocation,
    BindingManagement,
    CredentialBinding,
)
from azurator.providers.base import BINDING_VERIFICATION_MISMATCH_CODE, ProviderOperationError
from tests.foundry_test_support import (
    PROJECT_ID,
    SUBSCRIPTION_ID,
    FakeConnection,
    FakeConnectionOperations,
    FakeCredentials,
    FakeProject,
    FakeProjectConnectionOperations,
    make_cognitive_resource,
    make_provider,
    make_storage_resource,
)


def _managed_binding(*, target: str = "https://accountone.blob.core.windows.net/") -> CredentialBinding:
    return CredentialBinding(
        binding_id=f"{PROJECT_ID}/connections/storage-connection",
        name="storage-connection",
        binding_type="Microsoft.CognitiveServices/accounts/projects/connections",
        provider="azure-foundry-connections",
        location=BindingLocation.azure,
        scope_id=PROJECT_ID,
        scope_name="projectone",
        key_resource_id=make_storage_resource("accountone").resource_id,
        key_slot="key1",
        target=target,
        selectors=(),
        management=BindingManagement.update_and_verify,
    )


def _managed_connection_operations(*, key: str | None = "current-storage-secret") -> FakeConnectionOperations:
    current = FakeConnection(
        id="connection-id",
        name="storage-connection",
        credentials=FakeCredentials(key),
    )
    return FakeConnectionOperations((), {"storage-connection": current})


def _managed_cognitive_binding() -> CredentialBinding:
    return CredentialBinding(
        binding_id=f"{PROJECT_ID}/connections/openai-connection",
        name="openai-connection",
        binding_type="Microsoft.CognitiveServices/accounts/projects/connections",
        provider="azure-foundry-connections",
        location=BindingLocation.azure,
        scope_id=PROJECT_ID,
        scope_name="projectone",
        key_resource_id=make_cognitive_resource().resource_id,
        key_slot="Key1",
        target="https://openai-one.openai.azure.com/",
        selectors=(),
        management=BindingManagement.update_and_verify,
    )


def _managed_cognitive_connection_operations(*, key: str | None = "current-ai-secret") -> FakeConnectionOperations:
    current = FakeConnection(
        id="openai-connection-id",
        name="openai-connection",
        type="AzureOpenAI",
        target="https://openai-one.openai.azure.com/",
        credentials=FakeCredentials(key, credential_type="ApiKey"),
    )
    return FakeConnectionOperations((), {"openai-connection": current})


def test_foundry_updates_one_managed_account_key_with_the_pinned_arm_contract() -> None:
    managed_secret = "managed-storage-secret"
    update_operations = FakeProjectConnectionOperations(expected_key=managed_secret)
    data_operations = _managed_connection_operations()
    provider, management_client, _, _ = make_provider(
        FakeProject(),
        data_operations,
        update_operations,
    )

    provider.update_binding(
        SUBSCRIPTION_ID,
        _managed_binding(),
        make_storage_resource("accountone"),
        "current-storage-secret",
        managed_secret,
    )

    assert update_operations.calls == [
        (
            "rg",
            "foundryone",
            "projectone",
            "storage-connection",
            "AzureStorageAccount",
            "https://accountone.blob.core.windows.net/",
            True,
            False,
        )
    ]
    assert update_operations.request is not None
    assert update_operations.request.properties is None
    assert managed_secret not in repr(update_operations.request)
    assert data_operations.get_calls == [("storage-connection", True, False)]
    assert management_client.closed


def test_foundry_update_is_a_noop_when_the_replacement_is_already_present() -> None:
    replacement = "managed-storage-secret"
    update_operations = FakeProjectConnectionOperations()
    data_operations = _managed_connection_operations(key=replacement)
    provider, management_client, project_client, _ = make_provider(
        FakeProject(),
        data_operations,
        update_operations,
    )

    provider.update_binding(
        SUBSCRIPTION_ID,
        _managed_binding(),
        make_storage_resource("accountone"),
        "current-storage-secret",
        replacement,
    )

    assert data_operations.get_calls == [("storage-connection", True, False)]
    assert update_operations.calls == []
    assert project_client.closed
    assert not management_client.closed


def test_foundry_update_blocks_a_third_credential_without_overwriting_it() -> None:
    third = "dritter-storage-schlüssel"
    update_operations = FakeProjectConnectionOperations()
    data_operations = _managed_connection_operations(key=third)
    provider, management_client, project_client, _ = make_provider(
        FakeProject(),
        data_operations,
        update_operations,
    )

    with pytest.raises(ProviderOperationError) as caught:
        provider.update_binding(
            SUBSCRIPTION_ID,
            _managed_binding(),
            make_storage_resource("accountone"),
            "current-storage-secret",
            "managed-storage-secret",
        )

    assert caught.value.code == "foundry-connection-drift-detected"
    assert third not in str(caught.value)
    assert update_operations.calls == []
    assert project_client.closed
    assert not management_client.closed


def test_foundry_updates_one_managed_api_key_with_the_pinned_arm_contract() -> None:
    managed_secret = "managed-ai-secret"
    update_operations = FakeProjectConnectionOperations(expected_key=managed_secret)
    data_operations = _managed_cognitive_connection_operations()
    provider, management_client, _, _ = make_provider(
        FakeProject(),
        data_operations,
        update_operations,
    )

    provider.update_binding(
        SUBSCRIPTION_ID,
        _managed_cognitive_binding(),
        make_cognitive_resource(),
        "current-ai-secret",
        managed_secret,
    )

    assert update_operations.calls == [
        (
            "rg",
            "foundryone",
            "projectone",
            "openai-connection",
            "AzureOpenAI",
            "https://openai-one.openai.azure.com/",
            True,
            False,
        )
    ]
    assert update_operations.request is not None
    assert update_operations.request.properties is None
    assert managed_secret not in repr(update_operations.request)
    assert data_operations.get_calls == [("openai-connection", True, False)]
    assert management_client.closed


def test_foundry_verifies_a_managed_connection_credential_and_discards_it() -> None:
    managed_secret = "managed-storage-secret"
    detailed_credentials = FakeCredentials(managed_secret)
    detailed = FakeConnection(
        id="connection-id",
        name="storage-connection",
        credentials=detailed_credentials,
    )
    data_operations = FakeConnectionOperations((), {"storage-connection": detailed})
    provider, _, project_client, factory = make_provider(FakeProject(), data_operations)

    provider.verify_binding(
        SUBSCRIPTION_ID,
        _managed_binding(),
        make_storage_resource("accountone"),
        managed_secret,
    )

    assert factory.project_endpoints == ["https://foundryone.services.ai.azure.com/api/projects/projectone"]
    assert data_operations.get_calls == [("storage-connection", True, False)]
    assert "key" not in detailed_credentials
    assert project_client.closed


def test_foundry_verifies_a_managed_azure_openai_api_key_and_discards_it() -> None:
    managed_secret = "managed-ai-secret"
    data_operations = _managed_cognitive_connection_operations(key=managed_secret)
    detailed = data_operations.details["openai-connection"]
    detailed_credentials = detailed.credentials
    provider, _, project_client, _ = make_provider(FakeProject(), data_operations)

    provider.verify_binding(
        SUBSCRIPTION_ID,
        _managed_cognitive_binding(),
        make_cognitive_resource(),
        managed_secret,
    )

    assert data_operations.get_calls == [("openai-connection", True, False)]
    assert "key" not in detailed_credentials
    assert project_client.closed


def test_foundry_verification_rejects_target_drift_even_when_it_resolves_to_the_same_resource() -> None:
    managed_secret = "managed-ai-secret"
    detailed_credentials = FakeCredentials(managed_secret, credential_type="ApiKey")
    detailed = FakeConnection(
        id="openai-connection-id",
        name="openai-connection",
        type="AzureOpenAI",
        target="https://openai-one.openai.azure.com",
        credentials=detailed_credentials,
    )
    data_operations = FakeConnectionOperations((), {"openai-connection": detailed})
    provider, _, project_client, _ = make_provider(FakeProject(), data_operations)

    with pytest.raises(ProviderOperationError) as caught:
        provider.verify_binding(
            SUBSCRIPTION_ID,
            _managed_cognitive_binding(),
            make_cognitive_resource(),
            managed_secret,
        )

    assert caught.value.code == "foundry-connection-drift-detected"
    assert managed_secret not in str(caught.value)
    assert "key" not in detailed_credentials
    assert project_client.closed


def test_foundry_verification_rejects_noncanonical_credentials_without_reclassifying_them_as_a_mismatch() -> None:
    managed_secret = "managed-storage-secret"
    detailed_credentials = FakeCredentials(managed_secret)
    detailed_credentials["unexpected"] = "contract-drift"
    detailed = FakeConnection(
        id="connection-id",
        name="storage-connection",
        credentials=detailed_credentials,
    )
    data_operations = FakeConnectionOperations((), {"storage-connection": detailed})
    provider, _, project_client, _ = make_provider(FakeProject(), data_operations)

    with pytest.raises(ProviderOperationError) as caught:
        provider.verify_binding(
            SUBSCRIPTION_ID,
            _managed_binding(),
            make_storage_resource("accountone"),
            managed_secret,
        )

    assert caught.value.code == "foundry-verification-contract-invalid"
    assert managed_secret not in str(caught.value)
    assert detailed_credentials == {}
    assert project_client.closed


def test_foundry_verification_mismatch_is_secret_free_and_fails_closed() -> None:
    stored_secret = "gespeicherter-storage-schlüssel"
    expected_secret = "expected-storage-secret"
    detailed_credentials = FakeCredentials(stored_secret)
    detailed = FakeConnection(
        id="connection-id",
        name="storage-connection",
        credentials=detailed_credentials,
    )
    data_operations = FakeConnectionOperations((), {"storage-connection": detailed})
    provider, _, project_client, _ = make_provider(FakeProject(), data_operations)

    with pytest.raises(ProviderOperationError) as caught:
        provider.verify_binding(
            SUBSCRIPTION_ID,
            _managed_binding(),
            make_storage_resource("accountone"),
            expected_secret,
        )

    assert caught.value.code == BINDING_VERIFICATION_MISMATCH_CODE
    assert stored_secret not in str(caught.value)
    assert expected_secret not in str(caught.value)
    assert "key" not in detailed_credentials
    assert project_client.closed


def test_foundry_update_failure_is_status_only_and_scrubs_the_request() -> None:
    managed_secret = "managed-storage-secret"
    response_secret = "foundry-response-secret"
    error = HttpResponseError(message=response_secret)
    error.status_code = 403
    update_operations = FakeProjectConnectionOperations(expected_key=managed_secret, error=error)
    provider, management_client, _, _ = make_provider(
        FakeProject(),
        _managed_connection_operations(),
        update_operations,
    )

    with pytest.raises(ProviderOperationError) as caught:
        provider.update_binding(
            SUBSCRIPTION_ID,
            _managed_binding(),
            make_storage_resource("accountone"),
            "current-storage-secret",
            managed_secret,
        )

    assert caught.value.code == "foundry-connection-update-forbidden"
    assert managed_secret not in str(caught.value)
    assert response_secret not in str(caught.value)
    assert update_operations.request is not None
    assert update_operations.request.properties is None
    assert management_client.closed


@pytest.mark.parametrize(
    ("error_type", "phase"),
    ((ServiceRequestError, "request"), (ServiceResponseError, "response")),
)
def test_foundry_update_transport_failure_is_redacted_and_scrubs_the_request(
    error_type: type[Exception],
    phase: str,
) -> None:
    managed_secret = "managed-storage-secret"
    transport_secret = "foundry-update-transport-secret"
    update_operations = FakeProjectConnectionOperations(
        expected_key=managed_secret,
        error=error_type(transport_secret),
    )
    provider, management_client, _, _ = make_provider(
        FakeProject(),
        _managed_connection_operations(),
        update_operations,
    )

    with pytest.raises(ProviderOperationError) as caught:
        provider.update_binding(
            SUBSCRIPTION_ID,
            _managed_binding(),
            make_storage_resource("accountone"),
            "current-storage-secret",
            managed_secret,
        )

    assert caught.value.code == f"foundry-connection-update-{phase}-failed"
    assert managed_secret not in str(caught.value)
    assert transport_secret not in str(caught.value)
    assert update_operations.request is not None
    assert update_operations.request.properties is None
    assert management_client.closed


@pytest.mark.parametrize(
    ("error_type", "phase"),
    ((ServiceRequestError, "request"), (ServiceResponseError, "response")),
)
def test_foundry_verification_transport_failure_is_redacted(
    error_type: type[Exception],
    phase: str,
) -> None:
    expected_secret = "managed-storage-secret"
    transport_secret = "foundry-verification-transport-secret"
    operations = FakeConnectionOperations((), {}, get_error=error_type(transport_secret))
    provider, _, project_client, _ = make_provider(FakeProject(), operations)

    with pytest.raises(ProviderOperationError) as caught:
        provider.verify_binding(
            SUBSCRIPTION_ID,
            _managed_binding(),
            make_storage_resource("accountone"),
            expected_secret,
        )

    assert caught.value.code == f"foundry-connection-verification-{phase}-failed"
    assert expected_secret not in str(caught.value)
    assert transport_secret not in str(caught.value)
    assert project_client.closed


def test_foundry_rejects_connection_scope_drift_before_update() -> None:
    update_operations = FakeProjectConnectionOperations()
    provider, management_client, _, _ = make_provider(
        FakeProject(),
        FakeConnectionOperations((), {}),
        update_operations,
    )
    drifted = _managed_binding(target="https://accounttwo.blob.core.windows.net/")

    with pytest.raises(ProviderOperationError) as caught:
        provider.update_binding(
            SUBSCRIPTION_ID,
            drifted,
            make_storage_resource("accountone"),
            "current-storage-secret",
            "managed-storage-secret",
        )

    assert caught.value.code == "foundry-operation-contract-invalid"
    assert update_operations.calls == []
    assert not management_client.closed


def test_foundry_detects_live_connection_metadata_drift_before_update() -> None:
    update_operations = FakeProjectConnectionOperations()
    current = FakeConnection(
        id="connection-id",
        name="storage-connection",
        target="https://accounttwo.blob.core.windows.net/",
        credentials=FakeCredentials(None),
    )
    data_operations = FakeConnectionOperations((), {"storage-connection": current})
    provider, management_client, project_client, _ = make_provider(
        FakeProject(),
        data_operations,
        update_operations,
    )

    with pytest.raises(ProviderOperationError) as caught:
        provider.update_binding(
            SUBSCRIPTION_ID,
            _managed_binding(),
            make_storage_resource("accountone"),
            "current-storage-secret",
            "managed-storage-secret",
        )

    assert caught.value.code == "foundry-connection-drift-detected"
    assert update_operations.calls == []
    assert data_operations.get_calls == [("storage-connection", True, False)]
    assert project_client.closed
    assert not management_client.closed


@pytest.mark.parametrize(
    ("error_type", "phase"),
    ((ServiceRequestError, "request"), (ServiceResponseError, "response")),
)
def test_foundry_pre_update_drift_check_transport_failure_is_redacted(
    error_type: type[Exception],
    phase: str,
) -> None:
    managed_secret = "managed-storage-secret"
    transport_secret = "foundry-drift-check-transport-secret"
    operations = FakeConnectionOperations((), {}, get_error=error_type(transport_secret))
    update_operations = FakeProjectConnectionOperations()
    provider, management_client, project_client, _ = make_provider(
        FakeProject(),
        operations,
        update_operations,
    )

    with pytest.raises(ProviderOperationError) as caught:
        provider.update_binding(
            SUBSCRIPTION_ID,
            _managed_binding(),
            make_storage_resource("accountone"),
            "current-storage-secret",
            managed_secret,
        )

    assert caught.value.code == f"foundry-connection-transition-check-{phase}-failed"
    assert managed_secret not in str(caught.value)
    assert transport_secret not in str(caught.value)
    assert update_operations.calls == []
    assert project_client.closed
    assert not management_client.closed

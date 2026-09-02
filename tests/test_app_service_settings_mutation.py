"""Managed App Service application-settings transition and verification tests."""

from __future__ import annotations

import pytest
from azure.core.exceptions import HttpResponseError, ServiceRequestError, ServiceResponseError

from azurator.models import CredentialBinding
from azurator.providers.base import BINDING_VERIFICATION_MISMATCH_CODE, ProviderOperationError
from tests.app_service_test_support import (
    SITE_ID,
    SUBSCRIPTION_ID,
    FakeSite,
    FakeWebAppOperations,
    inspect_bindings,
    make_provider,
    make_storage_resource,
)


def _http_error(message: str, status: int) -> HttpResponseError:
    error = HttpResponseError(message=message)
    error.status_code = status
    return error


def _managed_binding() -> CredentialBinding:
    operations = FakeWebAppOperations(
        (FakeSite(),),
        {
            "example-app": {
                "PRIMARY": "current-storage-key",
                "ALIAS": "current-storage-key",
            }
        },
    )
    provider, _, _ = make_provider(operations)
    result = inspect_bindings(
        provider,
        storage_key="current-storage-key",
        include_cognitive=False,
    )
    assert len(result.bindings) == 1
    return result.bindings[0]


def test_app_service_update_replaces_only_selected_aliases_in_the_complete_dictionary() -> None:
    binding = _managed_binding()
    operations = FakeWebAppOperations(
        settings={
            "example-app": {
                "ALIAS": "current-storage-key",
                "PRIMARY": "current-storage-key",
                "UNRELATED": "preserve-me",
            }
        }
    )
    provider, client, factory = make_provider(operations)

    provider.update_binding(
        SUBSCRIPTION_ID,
        binding,
        make_storage_resource(),
        "current-storage-key",
        "replacement-storage-key",
    )

    assert factory.subscription_calls == [SUBSCRIPTION_ID]
    assert operations.read_calls == [("app-rg", "example-app", False)]
    assert operations.update_calls == [
        (
            "app-rg",
            "example-app",
            {
                "ALIAS": "replacement-storage-key",
                "PRIMARY": "replacement-storage-key",
                "UNRELATED": "preserve-me",
            },
            False,
        )
    ]
    assert operations.settings["example-app"] == operations.update_calls[0][2]
    assert operations.last_request is not None
    assert operations.last_request.properties is None
    assert client.closed


def test_app_service_update_is_a_noop_when_the_replacement_is_already_present() -> None:
    binding = _managed_binding()
    operations = FakeWebAppOperations(
        settings={
            "example-app": {
                "ALIAS": "replacement-storage-key",
                "PRIMARY": "replacement-storage-key",
            }
        }
    )
    provider, client, _ = make_provider(operations)

    provider.update_binding(
        SUBSCRIPTION_ID,
        binding,
        make_storage_resource(),
        "current-storage-key",
        "replacement-storage-key",
    )

    assert operations.update_calls == []
    assert client.closed


@pytest.mark.parametrize(
    "settings",
    (
        {"ALIAS": "dritter-schlüssel", "PRIMARY": "dritter-schlüssel"},
        {"ALIAS": "current-storage-key", "PRIMARY": "replacement-storage-key"},
        {"PRIMARY": "current-storage-key"},
    ),
)
def test_app_service_update_blocks_third_mixed_or_missing_values(settings: dict[str, str]) -> None:
    binding = _managed_binding()
    operations = FakeWebAppOperations(settings={"example-app": settings})
    provider, client, _ = make_provider(operations)

    with pytest.raises(ProviderOperationError) as caught:
        provider.update_binding(
            SUBSCRIPTION_ID,
            binding,
            make_storage_resource(),
            "current-storage-key",
            "replacement-storage-key",
        )

    assert caught.value.code == "app-service-settings-binding-drift-detected"
    assert "dritter-schlüssel" not in str(caught.value)
    assert "current-storage-key" not in str(caught.value)
    assert "replacement-storage-key" not in str(caught.value)
    assert operations.update_calls == []
    assert client.closed


@pytest.mark.parametrize(
    ("error", "code"),
    (
        (_http_error("response-secret", 403), "app-service-settings-read-forbidden"),
        (ServiceRequestError("request-secret"), "app-service-settings-read-request-failed"),
        (ServiceResponseError("response-secret"), "app-service-settings-read-response-failed"),
    ),
)
def test_app_service_pre_update_read_failures_are_fixed_and_redacted(
    error: Exception,
    code: str,
) -> None:
    binding = _managed_binding()
    operations = FakeWebAppOperations(read_errors={"example-app": error})
    provider, client, _ = make_provider(operations)

    with pytest.raises(ProviderOperationError) as caught:
        provider.update_binding(
            SUBSCRIPTION_ID,
            binding,
            make_storage_resource(),
            "current-storage-key",
            "replacement-storage-key",
        )

    assert caught.value.code == code
    assert "secret" not in str(caught.value)
    assert operations.update_calls == []
    assert client.closed


@pytest.mark.parametrize(
    ("error", "code"),
    (
        (_http_error("response-secret", 500), "app-service-settings-update-failed"),
        (ServiceRequestError("request-secret"), "app-service-settings-update-request-failed"),
        (ServiceResponseError("response-secret"), "app-service-settings-update-response-failed"),
    ),
)
def test_app_service_update_failures_are_fixed_and_scrub_the_request(
    error: Exception,
    code: str,
) -> None:
    binding = _managed_binding()
    operations = FakeWebAppOperations(
        settings={
            "example-app": {
                "ALIAS": "current-storage-key",
                "PRIMARY": "current-storage-key",
            }
        },
        update_error=error,
    )
    provider, client, _ = make_provider(operations)

    with pytest.raises(ProviderOperationError) as caught:
        provider.update_binding(
            SUBSCRIPTION_ID,
            binding,
            make_storage_resource(),
            "current-storage-key",
            "replacement-storage-key",
        )

    assert caught.value.code == code
    assert "secret" not in str(caught.value)
    assert operations.last_request is not None
    assert operations.last_request.properties is None
    assert client.closed


def test_app_service_verification_accepts_only_the_complete_expected_alias_group() -> None:
    binding = _managed_binding()
    operations = FakeWebAppOperations(
        settings={
            "example-app": {
                "ALIAS": "replacement-storage-key",
                "PRIMARY": "replacement-storage-key",
                "UNRELATED": "preserve-me",
            }
        }
    )
    provider, client, _ = make_provider(operations)

    provider.verify_binding(
        SUBSCRIPTION_ID,
        binding,
        make_storage_resource(),
        "replacement-storage-key",
    )

    assert operations.read_calls == [("app-rg", "example-app", False)]
    assert operations.update_calls == []
    assert client.closed


def test_app_service_verification_mismatch_is_secret_free() -> None:
    binding = _managed_binding()
    operations = FakeWebAppOperations(
        settings={
            "example-app": {
                "ALIAS": "gespeicherter-schlüssel",
                "PRIMARY": "gespeicherter-schlüssel",
            }
        }
    )
    provider, client, _ = make_provider(operations)

    with pytest.raises(ProviderOperationError) as caught:
        provider.verify_binding(
            SUBSCRIPTION_ID,
            binding,
            make_storage_resource(),
            "expected-secret",
        )

    assert caught.value.code == BINDING_VERIFICATION_MISMATCH_CODE
    assert "gespeicherter-schlüssel" not in str(caught.value)
    assert "expected-secret" not in str(caught.value)
    assert client.closed


def test_app_service_rejects_tampered_binding_metadata_before_constructing_a_client() -> None:
    binding = _managed_binding().model_copy(update={"scope_id": f"{SITE_ID}/slots/other"})
    operations = FakeWebAppOperations()
    provider, client, factory = make_provider(operations)

    with pytest.raises(ProviderOperationError) as caught:
        provider.update_binding(
            SUBSCRIPTION_ID,
            binding,
            make_storage_resource(),
            "current-storage-key",
            "replacement-storage-key",
        )

    assert caught.value.code == "app-service-settings-operation-contract-invalid"
    assert factory.subscription_calls == []
    assert not client.closed


@pytest.mark.parametrize("properties", (None, (), {"SETTING": 1}))
def test_app_service_update_rejects_noncanonical_settings_responses(properties: object) -> None:
    binding = _managed_binding()
    operations = FakeWebAppOperations(settings={"example-app": properties})
    provider, client, _ = make_provider(operations)

    with pytest.raises(ProviderOperationError) as caught:
        provider.update_binding(
            SUBSCRIPTION_ID,
            binding,
            make_storage_resource(),
            "current-storage-key",
            "replacement-storage-key",
        )

    assert caught.value.code == "app-service-settings-update-contract-invalid"
    assert operations.update_calls == []
    assert client.closed

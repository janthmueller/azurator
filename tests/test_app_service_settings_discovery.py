"""Read-only App Service application-settings binding inspection tests."""

from __future__ import annotations

import pytest
from azure.core.exceptions import HttpResponseError, ServiceRequestError, ServiceResponseError

from azurator.models import BindingInspectionStatus, BindingManagement
from tests.app_service_test_support import (
    COGNITIVE_ID,
    SITE_ID,
    STORAGE_ID,
    FakeSite,
    FakeWebAppOperations,
    inspect_bindings,
    make_provider,
)


def _http_error(message: str, status: int) -> HttpResponseError:
    error = HttpResponseError(message=message)
    error.status_code = status
    return error


def test_app_service_inspection_groups_exact_aliases_and_discards_every_value() -> None:
    storage_key = "storage-secret-sentinel"
    cognitive_key = "cognitive-secret-sentinel"
    second_site_id = SITE_ID.replace("example-app", "empty-app")
    operations = FakeWebAppOperations(
        (FakeSite(), FakeSite(id=second_site_id, name="empty-app")),
        {
            "example-app": {
                "STORAGE_KEY": storage_key,
                "STORAGE_ALIAS": storage_key,
                "AI_KEY": cognitive_key,
                "UNRELATED": "unrelated-secret-sentinel",
                "EMPTY": "",
            },
            "empty-app": {"OTHER": "no-match"},
        },
    )
    provider, client, factory = make_provider(operations)

    result = inspect_bindings(provider, storage_key=storage_key, cognitive_key=cognitive_key)

    assert factory.subscription_calls == ["11111111-2222-3333-4444-555555555555"]
    assert operations.list_calls == [False]
    assert operations.read_calls == [
        ("app-rg", "example-app", False),
        ("app-rg", "empty-app", False),
    ]
    assert client.closed
    assert {inspection.resource_id for inspection in result.inspections} == {STORAGE_ID, COGNITIVE_ID}
    assert all(inspection.status is BindingInspectionStatus.inspected for inspection in result.inspections)
    assert all(inspection.scopes_inspected == 2 for inspection in result.inspections)
    assert len(result.bindings) == 2
    storage_binding = next(binding for binding in result.bindings if binding.key_resource_id == STORAGE_ID)
    assert storage_binding.scope_id == SITE_ID
    assert storage_binding.scope_name == "example-app"
    assert storage_binding.binding_type == "Microsoft.Web/sites/config/appsettings"
    assert storage_binding.key_slot == "key1"
    assert storage_binding.selectors == ("STORAGE_ALIAS", "STORAGE_KEY")
    assert storage_binding.management is BindingManagement.update_and_verify
    cognitive_binding = next(binding for binding in result.bindings if binding.key_resource_id == COGNITIVE_ID)
    assert cognitive_binding.key_slot == "Key1"
    assert cognitive_binding.selectors == ("AI_KEY",)
    assert [warning.code for warning in result.warnings] == [
        "app-service-settings-binding-coverage-limited",
        "app-service-settings-restart-and-concurrency",
    ]
    serialized = result.model_dump_json()
    for raw_value in (storage_key, cognitive_key, "unrelated-secret-sentinel", "no-match"):
        assert raw_value not in serialized


def test_app_service_inspection_accepts_an_empty_visible_site_set() -> None:
    operations = FakeWebAppOperations()
    provider, client, _ = make_provider(operations)

    result = inspect_bindings(provider, include_cognitive=False)

    assert len(result.inspections) == 1
    assert result.inspections[0].status is BindingInspectionStatus.inspected
    assert result.inspections[0].scopes_inspected == 0
    assert result.bindings == ()
    assert [warning.code for warning in result.warnings] == ["app-service-settings-binding-coverage-limited"]
    assert client.closed


@pytest.mark.parametrize(
    "properties",
    (None, (), {"SETTING": 1}, {"": "value"}),
)
def test_app_service_inspection_rejects_noncanonical_settings_dictionaries(properties: object) -> None:
    operations = FakeWebAppOperations((FakeSite(),), {"example-app": properties})
    provider, client, _ = make_provider(operations)

    result = inspect_bindings(provider, include_cognitive=False)

    assert result.inspections[0].status is BindingInspectionStatus.unavailable
    assert result.inspections[0].scopes_inspected == 0
    assert result.bindings == ()
    assert result.warnings[-1].code == "app-service-settings-response-invalid"
    assert client.closed


def test_app_service_inspection_marks_a_partial_site_scan_incomplete() -> None:
    second_site_id = SITE_ID.replace("example-app", "broken-app")
    operations = FakeWebAppOperations(
        (FakeSite(), FakeSite(id=second_site_id, name="broken-app")),
        {"example-app": {"OTHER": "value"}, "broken-app": None},
    )
    provider, _, _ = make_provider(operations)

    result = inspect_bindings(provider, include_cognitive=False)

    assert result.inspections[0].status is BindingInspectionStatus.partial
    assert result.inspections[0].scopes_inspected == 1
    assert result.warnings[-1].resource_id == second_site_id


@pytest.mark.parametrize(
    ("error", "code"),
    (
        (_http_error("response-secret", 403), "app-service-site-list-forbidden"),
        (ServiceRequestError("request-secret"), "app-service-site-list-request-failed"),
        (ServiceResponseError("response-secret"), "app-service-site-list-response-failed"),
    ),
)
def test_app_service_site_enumeration_failures_are_fixed_and_secret_free(
    error: Exception,
    code: str,
) -> None:
    operations = FakeWebAppOperations(list_error=error)
    provider, client, _ = make_provider(operations)

    result = inspect_bindings(provider, include_cognitive=False)

    assert result.inspections[0].status is BindingInspectionStatus.unavailable
    assert result.inspections[0].scopes_inspected == 0
    assert result.warnings[-1].code == code
    assert "secret" not in result.model_dump_json()
    assert client.closed


@pytest.mark.parametrize(
    ("error", "code"),
    (
        (_http_error("response-secret", 500), "app-service-settings-list-failed"),
        (ServiceRequestError("request-secret"), "app-service-settings-list-request-failed"),
        (ServiceResponseError("response-secret"), "app-service-settings-list-response-failed"),
    ),
)
def test_app_service_settings_read_failures_are_fixed_and_secret_free(
    error: Exception,
    code: str,
) -> None:
    operations = FakeWebAppOperations((FakeSite(),), read_errors={"example-app": error})
    provider, client, _ = make_provider(operations)

    result = inspect_bindings(provider, include_cognitive=False)

    assert result.inspections[0].status is BindingInspectionStatus.unavailable
    assert result.warnings[-1].code == code
    assert "secret" not in result.model_dump_json()
    assert client.closed


def test_app_service_inspection_rejects_ambiguous_cross_resource_values() -> None:
    shared_key = "same-high-entropy-key"
    operations = FakeWebAppOperations((FakeSite(),), {"example-app": {"SHARED": shared_key}})
    provider, _, _ = make_provider(operations)

    result = inspect_bindings(provider, storage_key=shared_key, cognitive_key=shared_key)

    assert all(inspection.status is BindingInspectionStatus.partial for inspection in result.inspections)
    assert result.bindings == ()
    assert result.warnings[-1].code == "app-service-setting-key-ambiguous"
    assert shared_key not in result.model_dump_json()


def test_app_service_inspection_matches_only_complete_setting_values() -> None:
    key = "storage-secret-sentinel"
    operations = FakeWebAppOperations(
        (FakeSite(),),
        {
            "example-app": {
                "CONNECTION_STRING": f"AccountKey={key};EndpointSuffix=core.windows.net",
                "JSON": f'{{"key":"{key}"}}',
                "PREFIXED": f"prefix-{key}",
                "KEY_VAULT": "@Microsoft.KeyVault(SecretUri=https://example.vault.azure.net/secrets/key)",
            }
        },
    )
    provider, _, _ = make_provider(operations)

    result = inspect_bindings(provider, storage_key=key, include_cognitive=False)

    assert result.bindings == ()
    assert result.inspections[0].status is BindingInspectionStatus.inspected
    assert key not in result.model_dump_json()


def test_app_service_inspection_rejects_invalid_and_duplicate_site_metadata() -> None:
    operations = FakeWebAppOperations(
        (
            FakeSite(id=None),
            FakeSite(),
            FakeSite(),
        ),
        {"example-app": {"OTHER": "value"}},
    )
    provider, _, _ = make_provider(operations)

    result = inspect_bindings(provider, include_cognitive=False)

    assert result.inspections[0].status is BindingInspectionStatus.partial
    assert result.inspections[0].scopes_inspected == 1
    assert [warning.code for warning in result.warnings].count("app-service-site-metadata-invalid") == 2

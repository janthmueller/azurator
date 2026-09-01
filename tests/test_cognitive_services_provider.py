"""Tests for the reviewed Cognitive Services discovery and key contract."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import cast

import pytest
from azure.core.exceptions import HttpResponseError, ServiceRequestError, ServiceResponseError

from azurator.clients import (
    AzureClientFactory,
    CognitiveAccountLike,
    CognitiveAccountOperations,
    CognitiveApiKeysLike,
    CognitiveServicesManagementClientLike,
)
from azurator.models import CandidateInspectionStatus, DiscoveredResource, KeyAuthentication, KeySlot
from azurator.providers.base import ProviderOperationError
from azurator.providers.cognitive_services import CognitiveServicesProvider

SUBSCRIPTION_ID = "11111111-1111-1111-1111-111111111111"


@dataclass(frozen=True)
class FakeCognitiveProperties:
    disable_local_auth: bool | None = False
    endpoint: str | None = "https://example.cognitiveservices.azure.com/"


@dataclass(frozen=True)
class FakeCognitiveAccount:
    id: str | None
    name: str | None
    type: str | None = "Microsoft.CognitiveServices/accounts"
    location: str | None = "germanywestcentral"
    kind: str | None = "OpenAI"
    properties: FakeCognitiveProperties | None = FakeCognitiveProperties()


@dataclass(frozen=True)
class FakeApiKeys:
    key1: object
    key2: object


class FakeCognitiveOperations:
    def __init__(
        self,
        accounts: tuple[FakeCognitiveAccount, ...] = (),
        *,
        error: Exception | None = None,
        key_result: FakeApiKeys | None = None,
        key_error: Exception | None = None,
        regenerate_result: FakeApiKeys | None = None,
        regenerate_error: Exception | None = None,
        allow_key_calls: bool = False,
        allow_regenerate_calls: bool = False,
    ) -> None:
        self.accounts = accounts
        self.error = error
        self.key_result = key_result
        self.key_error = key_error
        self.regenerate_result = regenerate_result
        self.regenerate_error = regenerate_error
        self.allow_key_calls = allow_key_calls
        self.allow_regenerate_calls = allow_regenerate_calls
        self.list_calls = 0
        self.list_keys_calls = 0
        self.key_call_arguments: list[tuple[str, str, bool]] = []
        self.regenerate_key_calls = 0
        self.regenerate_call_arguments: list[tuple[str, str, str, bool]] = []

    def list(self) -> Iterable[CognitiveAccountLike]:
        self.list_calls += 1
        if self.error is not None:
            raise self.error
        return tuple(cast(CognitiveAccountLike, account) for account in self.accounts)

    def list_keys(
        self,
        resource_group_name: str,
        account_name: str,
        *,
        logging_enable: bool = False,
    ) -> CognitiveApiKeysLike:
        self.list_keys_calls += 1
        self.key_call_arguments.append((resource_group_name, account_name, logging_enable))
        if not self.allow_key_calls:
            raise AssertionError("metadata discovery must never retrieve Cognitive Services keys")
        if self.key_error is not None:
            raise self.key_error
        assert self.key_result is not None
        return cast(CognitiveApiKeysLike, self.key_result)

    def regenerate_key(
        self,
        resource_group_name: str,
        account_name: str,
        key_name: str,
        *,
        logging_enable: bool = False,
    ) -> CognitiveApiKeysLike:
        self.regenerate_key_calls += 1
        self.regenerate_call_arguments.append((resource_group_name, account_name, key_name, logging_enable))
        if not self.allow_regenerate_calls:
            raise AssertionError("metadata discovery must never regenerate Cognitive Services keys")
        if self.regenerate_error is not None:
            raise self.regenerate_error
        assert self.regenerate_result is not None
        return cast(CognitiveApiKeysLike, self.regenerate_result)


class FakeCognitiveClient:
    def __init__(self, operations: FakeCognitiveOperations) -> None:
        self._operations = operations
        self.closed = False

    @property
    def accounts(self) -> CognitiveAccountOperations:
        return self._operations

    def close(self) -> None:
        self.closed = True


class FakeClientFactory:
    def __init__(self, client: FakeCognitiveClient) -> None:
        self.client = client
        self.subscription_ids: list[str] = []

    def cognitive_services_management(self, subscription_id: str) -> CognitiveServicesManagementClientLike:
        self.subscription_ids.append(subscription_id)
        return self.client


def _provider(
    operations: FakeCognitiveOperations,
) -> tuple[CognitiveServicesProvider, FakeCognitiveClient, FakeClientFactory]:
    client = FakeCognitiveClient(operations)
    factory = FakeClientFactory(client)
    return CognitiveServicesProvider(cast(AzureClientFactory, factory)), client, factory


def test_cognitive_discovery_lists_metadata_without_key_operations() -> None:
    operations = FakeCognitiveOperations(
        (
            FakeCognitiveAccount(id="/subscriptions/example/providers/cognitive/keys-enabled", name="keys-enabled"),
            FakeCognitiveAccount(
                id="/subscriptions/example/providers/cognitive/keyless",
                name="keyless",
                properties=FakeCognitiveProperties(disable_local_auth=True),
            ),
            FakeCognitiveAccount(
                id="/subscriptions/example/providers/cognitive/default-local-auth",
                name="default-local-auth",
                properties=FakeCognitiveProperties(disable_local_auth=None),
            ),
        )
    )
    provider, client, factory = _provider(operations)

    result = provider.discover(SUBSCRIPTION_ID)

    assert provider.info.resource_types == ("Microsoft.CognitiveServices/accounts",)
    assert factory.subscription_ids == [SUBSCRIPTION_ID]
    assert operations.list_calls == 1
    assert operations.list_keys_calls == 0
    assert operations.regenerate_key_calls == 0
    assert client.closed
    assert [resource.key_authentication for resource in result.resources] == [
        KeyAuthentication.enabled,
        KeyAuthentication.disabled,
        KeyAuthentication.enabled,
    ]
    assert result.resources[0].kind == "OpenAI"
    assert result.resources[0].endpoint == "https://example.cognitiveservices.azure.com/"
    assert [slot.name for slot in result.resources[0].key_slots] == ["Key1", "Key2"]
    assert all(slot.values_retrievable and slot.rotatable for slot in result.resources[0].key_slots)
    assert not any(slot.values_retrievable or slot.rotatable for slot in result.resources[1].key_slots)
    assert all(slot.values_retrievable and slot.rotatable for slot in result.resources[2].key_slots)
    assert [warning.code for warning in result.warnings] == [
        "cognitive-services-bindings-not-inspected",
        "cognitive-services-key-permissions-not-tested",
    ]


def test_cognitive_discovery_reports_malformed_metadata_without_values() -> None:
    operations = FakeCognitiveOperations(
        (
            FakeCognitiveAccount(id=None, name="missing-id"),
            FakeCognitiveAccount(id="/wrong/type", name="wrong-type", type="Microsoft.Example/accounts"),
            FakeCognitiveAccount(id="/missing/properties", name="missing-properties", properties=None),
        )
    )
    provider, client, _ = _provider(operations)

    result = provider.discover(SUBSCRIPTION_ID)

    assert result.resources == ()
    assert [warning.code for warning in result.warnings[:3]] == [
        "malformed-cognitive-services-metadata",
        "malformed-cognitive-services-metadata",
        "malformed-cognitive-services-metadata",
    ]
    assert operations.list_keys_calls == 0
    assert operations.regenerate_key_calls == 0
    assert client.closed


def test_cognitive_permission_error_is_redacted_and_partial() -> None:
    sensitive_value = "do-not-render-this-key"
    error = HttpResponseError(message=sensitive_value)
    error.status_code = 403
    operations = FakeCognitiveOperations(error=error)
    provider, client, _ = _provider(operations)

    result = provider.discover(SUBSCRIPTION_ID)
    rendered = result.model_dump_json()

    assert result.resources == ()
    assert result.warnings[0].code == "cognitive-services-discovery-forbidden"
    assert sensitive_value not in rendered
    assert operations.list_keys_calls == 0
    assert operations.regenerate_key_calls == 0
    assert client.closed


@pytest.mark.parametrize(
    ("error_type", "phase"),
    ((ServiceRequestError, "request"), (ServiceResponseError, "response")),
)
def test_cognitive_discovery_transport_failure_is_redacted(
    error_type: type[Exception],
    phase: str,
) -> None:
    sensitive_value = "cognitive-discovery-transport-secret"
    operations = FakeCognitiveOperations(error=error_type(sensitive_value))
    provider, client, _ = _provider(operations)

    result = provider.discover(SUBSCRIPTION_ID)

    assert result.resources == ()
    assert result.warnings[0].code == "cognitive-services-discovery-failed"
    assert phase in result.warnings[0].message
    assert sensitive_value not in result.model_dump_json()
    assert operations.list_keys_calls == 0
    assert operations.regenerate_key_calls == 0
    assert client.closed


def _candidate_resource() -> DiscoveredResource:
    return DiscoveredResource(
        resource_id=(
            f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
            "Microsoft.CognitiveServices/accounts/openai-one"
        ),
        name="openai-one",
        resource_type="Microsoft.CognitiveServices/accounts",
        location="germanywestcentral",
        kind="OpenAI",
        provider="azure-cognitive-services",
        key_authentication=KeyAuthentication.enabled,
        endpoint="https://openai-one.openai.azure.com/",
        key_slots=(
            KeySlot(name="Key1", values_retrievable=True, rotatable=True),
            KeySlot(name="Key2", values_retrievable=True, rotatable=True),
        ),
    )


def test_cognitive_candidate_inspection_streams_declared_key_pair() -> None:
    operations = FakeCognitiveOperations(
        key_result=FakeApiKeys("ai-secret-one", "ai-secret-two"),
        allow_key_calls=True,
    )
    provider, client, factory = _provider(operations)
    consumed: list[tuple[str, str, str]] = []
    resource = _candidate_resource()

    result = provider.inspect_candidates(
        SUBSCRIPTION_ID,
        (resource,),
        lambda resource_id, slot, value: consumed.append((resource_id, slot, value)),
    )

    assert factory.subscription_ids == [SUBSCRIPTION_ID]
    assert operations.key_call_arguments == [("rg", "openai-one", False)]
    assert consumed == [
        (resource.resource_id, "Key1", "ai-secret-one"),
        (resource.resource_id, "Key2", "ai-secret-two"),
    ]
    assert result.inspections[0].status is CandidateInspectionStatus.compared
    assert result.inspections[0].key_slots == ("Key1", "Key2")
    assert result.warnings == ()
    assert "ai-secret" not in result.model_dump_json()
    assert operations.regenerate_key_calls == 0
    assert client.closed


@pytest.mark.parametrize(
    "key_result",
    (
        FakeApiKeys(None, "ai-secret-two"),
        FakeApiKeys("ai-secret-one", None),
        FakeApiKeys("", "ai-secret-two"),
        FakeApiKeys(b"non-string-ai-secret", "ai-secret-two"),
        cast(FakeApiKeys, object()),
    ),
)
def test_cognitive_candidate_inspection_rejects_noncanonical_key_responses(
    key_result: FakeApiKeys,
) -> None:
    operations = FakeCognitiveOperations(key_result=key_result, allow_key_calls=True)
    provider, client, _ = _provider(operations)
    consumed: list[tuple[str, str, str]] = []
    resource = _candidate_resource()

    result = provider.inspect_candidates(
        SUBSCRIPTION_ID,
        (resource,),
        lambda resource_id, slot, value: consumed.append((resource_id, slot, value)),
    )

    assert consumed == []
    assert result.inspections[0].status is CandidateInspectionStatus.unavailable
    assert result.inspections[0].key_slots == ()
    assert [warning.code for warning in result.warnings] == ["cognitive-services-key-response-incomplete"]
    serialized = result.model_dump_json()
    assert "ai-secret" not in serialized
    assert "non-string-ai-secret" not in serialized
    assert operations.regenerate_key_calls == 0
    assert client.closed


def test_cognitive_candidate_permission_failure_is_resource_scoped_and_redacted() -> None:
    sensitive_value = "ai-secret-must-not-render"
    error = HttpResponseError(message=sensitive_value)
    error.status_code = 403
    operations = FakeCognitiveOperations(key_error=error, allow_key_calls=True)
    provider, client, _ = _provider(operations)
    resource = _candidate_resource()

    result = provider.inspect_candidates(SUBSCRIPTION_ID, (resource,), lambda resource_id, slot, value: None)
    serialized = result.model_dump_json()

    assert result.inspections[0].status is CandidateInspectionStatus.unavailable
    assert result.warnings[0].code == "cognitive-services-key-retrieval-forbidden"
    assert result.warnings[0].resource_id == resource.resource_id
    assert sensitive_value not in serialized
    assert operations.regenerate_key_calls == 0
    assert client.closed


@pytest.mark.parametrize(
    ("error_type", "phase"),
    ((ServiceRequestError, "request"), (ServiceResponseError, "response")),
)
def test_cognitive_candidate_transport_failure_is_resource_scoped_and_redacted(
    error_type: type[Exception],
    phase: str,
) -> None:
    sensitive_value = "cognitive-key-transport-secret"
    operations = FakeCognitiveOperations(
        key_error=error_type(sensitive_value),
        allow_key_calls=True,
    )
    provider, client, _ = _provider(operations)
    resource = _candidate_resource()

    result = provider.inspect_candidates(SUBSCRIPTION_ID, (resource,), lambda resource_id, slot, value: None)

    assert result.inspections[0].status is CandidateInspectionStatus.unavailable
    assert result.warnings[0].code == "cognitive-services-key-retrieval-failed"
    assert phase in result.warnings[0].message
    assert sensitive_value not in result.model_dump_json()
    assert operations.regenerate_key_calls == 0
    assert client.closed


def test_cognitive_candidate_inspection_rejects_malformed_resource_id_before_key_call() -> None:
    operations = FakeCognitiveOperations(allow_key_calls=True)
    provider, client, _ = _provider(operations)
    resource = _candidate_resource().model_copy(update={"resource_id": "/not/an/arm/id"})

    result = provider.inspect_candidates(SUBSCRIPTION_ID, (resource,), lambda resource_id, slot, value: None)

    assert operations.list_keys_calls == 0
    assert result.inspections[0].status is CandidateInspectionStatus.unavailable
    assert result.warnings[0].code == "malformed-cognitive-services-resource-id"
    assert operations.regenerate_key_calls == 0
    assert client.closed


def test_cognitive_use_key_slot_exposes_only_the_selected_value() -> None:
    operations = FakeCognitiveOperations(
        key_result=FakeApiKeys("ai-secret-one", "ai-secret-two"),
        allow_key_calls=True,
    )
    provider, client, _ = _provider(operations)
    consumed: list[str] = []

    provider.use_key_slot(SUBSCRIPTION_ID, _candidate_resource(), "Key2", consumed.append)

    assert consumed == ["ai-secret-two"]
    assert operations.key_call_arguments == [("rg", "openai-one", False)]
    assert operations.regenerate_key_calls == 0
    assert client.closed


def test_cognitive_key_state_streams_the_exact_reviewed_pair() -> None:
    operations = FakeCognitiveOperations(
        key_result=FakeApiKeys("ai-secret-one", "ai-secret-two"),
        allow_key_calls=True,
    )
    provider, client, _ = _provider(operations)
    consumed: list[tuple[str, str]] = []

    provider.use_key_state(
        SUBSCRIPTION_ID,
        _candidate_resource(),
        lambda slot, value: consumed.append((slot, value)),
    )

    assert consumed == [("Key1", "ai-secret-one"), ("Key2", "ai-secret-two")]
    consumed.clear()
    assert operations.key_call_arguments == [("rg", "openai-one", False)]
    assert client.closed


def test_cognitive_regeneration_delegates_retries_to_the_sdk_for_one_exact_slot() -> None:
    operations = FakeCognitiveOperations(
        regenerate_result=FakeApiKeys("new-ai-secret", "sibling-ai-secret"),
        allow_regenerate_calls=True,
    )
    provider, client, _ = _provider(operations)

    result = provider.regenerate_key(SUBSCRIPTION_ID, _candidate_resource(), "Key1")

    assert result is None
    assert operations.key_call_arguments == []
    assert operations.regenerate_call_arguments == [("rg", "openai-one", "Key1", False)]
    assert client.closed


@pytest.mark.parametrize(
    "regenerated",
    (
        FakeApiKeys(None, "sibling-ai-secret"),
        FakeApiKeys("new-ai-secret", None),
    ),
)
def test_cognitive_regeneration_rejects_an_invalid_response_without_rendering_keys(
    regenerated: FakeApiKeys,
) -> None:
    operations = FakeCognitiveOperations(
        regenerate_result=regenerated,
        allow_regenerate_calls=True,
    )
    provider, client, _ = _provider(operations)

    with pytest.raises(ProviderOperationError) as caught:
        provider.regenerate_key(SUBSCRIPTION_ID, _candidate_resource(), "Key1")

    assert caught.value.code == "cognitive-services-key-response-invalid"
    assert "ai-secret" not in str(caught.value)
    assert client.closed


def test_cognitive_regeneration_http_failure_is_status_only() -> None:
    response_secret = "azure-error-containing-a-key"
    error = HttpResponseError(message=response_secret)
    error.status_code = 403
    operations = FakeCognitiveOperations(
        regenerate_error=error,
        allow_regenerate_calls=True,
    )
    provider, client, _ = _provider(operations)

    with pytest.raises(ProviderOperationError) as caught:
        provider.regenerate_key(SUBSCRIPTION_ID, _candidate_resource(), "Key2")

    assert caught.value.code == "cognitive-services-key-regeneration-forbidden"
    assert response_secret not in str(caught.value)
    assert "ai-secret" not in str(caught.value)
    assert client.closed


def test_cognitive_regeneration_redacts_a_terminal_sdk_request_failure() -> None:
    sensitive_value = "request-error-containing-an-ai-key"
    operations = FakeCognitiveOperations(
        regenerate_error=ServiceRequestError(sensitive_value),
        allow_regenerate_calls=True,
    )
    provider, client, _ = _provider(operations)

    with pytest.raises(ProviderOperationError) as caught:
        provider.regenerate_key(SUBSCRIPTION_ID, _candidate_resource(), "Key1")

    assert caught.value.code == "cognitive-services-key-regeneration-request-failed"
    assert sensitive_value not in str(caught.value)
    assert operations.list_keys_calls == 0
    assert operations.regenerate_call_arguments == [("rg", "openai-one", "Key1", False)]
    assert client.closed

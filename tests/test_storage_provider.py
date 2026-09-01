"""Tests for reviewed Azure Storage discovery, matching, and rotation boundaries."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import cast

import pytest
from azure.core.exceptions import HttpResponseError, ServiceRequestError, ServiceResponseError
from azure.mgmt.storage.models import StorageAccountRegenerateKeyParameters

from azurator.clients import (
    AzureClientFactory,
    StorageAccountLike,
    StorageAccountListKeysResultLike,
    StorageAccountOperations,
    StorageManagementClientLike,
)
from azurator.models import CandidateInspectionStatus, DiscoveredResource, KeyAuthentication, KeySlot
from azurator.providers.base import ProviderOperationError
from azurator.providers.storage import StorageProvider

SUBSCRIPTION_ID = "11111111-1111-1111-1111-111111111111"


@dataclass(frozen=True)
class FakeStorageAccount:
    id: str | None
    name: str | None
    type: str | None = "Microsoft.Storage/storageAccounts"
    location: str | None = "westeurope"
    kind: str | None = "StorageV2"
    allow_shared_key_access: bool | None = True


@dataclass(frozen=True)
class FakeStorageKey:
    key_name: object
    value: object


@dataclass(frozen=True)
class FakeStorageKeyResult:
    keys_property: tuple[FakeStorageKey, ...] | None


class FakeStorageOperations:
    def __init__(
        self,
        accounts: tuple[FakeStorageAccount, ...] = (),
        *,
        error: Exception | None = None,
        key_result: FakeStorageKeyResult | None = None,
        key_error: Exception | None = None,
        regeneration_error: Exception | None = None,
        allow_key_calls: bool = False,
        allow_regeneration: bool = False,
    ) -> None:
        self.accounts = accounts
        self.error = error
        self.key_result = key_result
        self.key_error = key_error
        self.regeneration_error = regeneration_error
        self.allow_key_calls = allow_key_calls
        self.allow_regeneration = allow_regeneration
        self.list_calls = 0
        self.list_keys_calls = 0
        self.key_call_arguments: list[tuple[str, str, str | None, bool]] = []
        self.regenerate_calls: list[tuple[str, str, str | None, bool]] = []

    def list(self) -> Iterable[StorageAccountLike]:
        self.list_calls += 1
        if self.error is not None:
            raise self.error
        return tuple(cast(StorageAccountLike, account) for account in self.accounts)

    def list_keys(
        self,
        resource_group_name: str,
        account_name: str,
        *,
        expand: str | None = None,
        logging_enable: bool = False,
    ) -> StorageAccountListKeysResultLike:
        self.list_keys_calls += 1
        self.key_call_arguments.append((resource_group_name, account_name, expand, logging_enable))
        if not self.allow_key_calls:
            raise AssertionError("metadata discovery must never retrieve Storage Account keys")
        if self.key_error is not None:
            raise self.key_error
        assert self.key_result is not None
        return cast(StorageAccountListKeysResultLike, self.key_result)

    def regenerate_key(
        self,
        resource_group_name: str,
        account_name: str,
        regenerate_key: StorageAccountRegenerateKeyParameters,
        *,
        logging_enable: bool = False,
    ) -> StorageAccountListKeysResultLike:
        self.regenerate_calls.append((resource_group_name, account_name, regenerate_key.key_name, logging_enable))
        if not self.allow_regeneration:
            raise AssertionError("read-only operations must never regenerate Storage Account keys")
        if self.regeneration_error is not None:
            raise self.regeneration_error
        assert self.key_result is not None
        return cast(StorageAccountListKeysResultLike, self.key_result)


class FakeStorageClient:
    def __init__(self, operations: FakeStorageOperations) -> None:
        self._operations = operations
        self.closed = False

    @property
    def storage_accounts(self) -> StorageAccountOperations:
        return self._operations

    def close(self) -> None:
        self.closed = True


class FakeClientFactory:
    def __init__(self, client: FakeStorageClient) -> None:
        self.client = client
        self.subscription_ids: list[str] = []

    def storage_management(self, subscription_id: str) -> StorageManagementClientLike:
        self.subscription_ids.append(subscription_id)
        return self.client


def _provider(operations: FakeStorageOperations) -> tuple[StorageProvider, FakeStorageClient, FakeClientFactory]:
    client = FakeStorageClient(operations)
    factory = FakeClientFactory(client)
    return StorageProvider(cast(AzureClientFactory, factory)), client, factory


def test_storage_discovery_lists_metadata_without_retrieving_keys() -> None:
    operations = FakeStorageOperations(
        (
            FakeStorageAccount(id="/subscriptions/example/resourceGroups/rg/providers/storage/one", name="one"),
            FakeStorageAccount(
                id="/subscriptions/example/resourceGroups/rg/providers/storage/two",
                name="two",
                allow_shared_key_access=False,
            ),
        )
    )
    provider, client, factory = _provider(operations)

    result = provider.discover(SUBSCRIPTION_ID)

    assert provider.info.resource_types == ("Microsoft.Storage/storageAccounts",)
    assert factory.subscription_ids == [SUBSCRIPTION_ID]
    assert operations.list_calls == 1
    assert operations.list_keys_calls == 0
    assert client.closed
    assert [resource.key_authentication for resource in result.resources] == [
        KeyAuthentication.enabled,
        KeyAuthentication.disabled,
    ]
    assert result.resources[0].kind == "StorageV2"
    assert [slot.name for slot in result.resources[0].key_slots] == ["key1", "key2"]
    assert all(slot.values_retrievable for slot in result.resources[0].key_slots)
    assert not any(slot.values_retrievable for slot in result.resources[1].key_slots)


def test_storage_discovery_reports_malformed_metadata_without_values() -> None:
    operations = FakeStorageOperations(
        (
            FakeStorageAccount(id=None, name="missing-id"),
            FakeStorageAccount(id="/wrong/type", name="wrong-type", type="Microsoft.Example/accounts"),
        )
    )
    provider, client, _ = _provider(operations)

    result = provider.discover(SUBSCRIPTION_ID)

    assert result.resources == ()
    assert [warning.code for warning in result.warnings[:2]] == [
        "malformed-storage-metadata",
        "malformed-storage-metadata",
    ]
    assert client.closed


def test_storage_permission_error_is_redacted_and_partial() -> None:
    sensitive_value = "do-not-render-this-key"
    error = HttpResponseError(message=sensitive_value)
    error.status_code = 403
    operations = FakeStorageOperations(error=error)
    provider, client, _ = _provider(operations)

    result = provider.discover(SUBSCRIPTION_ID)
    rendered = result.model_dump_json()

    assert result.resources == ()
    assert result.warnings[0].code == "storage-discovery-forbidden"
    assert sensitive_value not in rendered
    assert operations.list_keys_calls == 0
    assert client.closed


@pytest.mark.parametrize(
    ("error_type", "phase"),
    ((ServiceRequestError, "request"), (ServiceResponseError, "response")),
)
def test_storage_discovery_transport_failure_is_redacted(
    error_type: type[Exception],
    phase: str,
) -> None:
    sensitive_value = "storage-discovery-transport-secret"
    operations = FakeStorageOperations(error=error_type(sensitive_value))
    provider, client, _ = _provider(operations)

    result = provider.discover(SUBSCRIPTION_ID)

    assert result.resources == ()
    assert result.warnings[0].code == "storage-discovery-failed"
    assert phase in result.warnings[0].message
    assert sensitive_value not in result.model_dump_json()
    assert operations.list_keys_calls == 0
    assert client.closed


def _candidate_resource() -> DiscoveredResource:
    return DiscoveredResource(
        resource_id=(
            f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/accountone"
        ),
        name="accountone",
        resource_type="Microsoft.Storage/storageAccounts",
        location="westeurope",
        kind="StorageV2",
        provider="azure-storage",
        key_authentication=KeyAuthentication.enabled,
        key_slots=(
            KeySlot(name="key1", values_retrievable=True, rotatable=True),
            KeySlot(name="key2", values_retrievable=True, rotatable=True),
        ),
    )


def test_storage_candidate_inspection_streams_the_exact_declared_pair() -> None:
    operations = FakeStorageOperations(
        key_result=FakeStorageKeyResult(
            (
                FakeStorageKey("key1", "storage-secret-one"),
                FakeStorageKey("key2", "storage-secret-two"),
            )
        ),
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
    assert operations.key_call_arguments == [("rg", "accountone", None, False)]
    assert consumed == [
        (resource.resource_id, "key1", "storage-secret-one"),
        (resource.resource_id, "key2", "storage-secret-two"),
    ]
    assert result.inspections[0].status is CandidateInspectionStatus.compared
    assert result.inspections[0].key_slots == ("key1", "key2")
    assert result.warnings == ()
    assert "storage-secret" not in result.model_dump_json()
    assert client.closed


@pytest.mark.parametrize(
    "key_result",
    (
        FakeStorageKeyResult(None),
        FakeStorageKeyResult((FakeStorageKey("key1", "storage-secret-one"),)),
        FakeStorageKeyResult(
            (
                FakeStorageKey("key1", "storage-secret-one"),
                FakeStorageKey("key1", "duplicate-storage-secret"),
                FakeStorageKey("key2", "storage-secret-two"),
            )
        ),
        FakeStorageKeyResult(
            (
                FakeStorageKey("key1", "storage-secret-one"),
                FakeStorageKey("key2", "storage-secret-two"),
                FakeStorageKey("kerb1", "unexpected-storage-secret"),
            )
        ),
        FakeStorageKeyResult(
            (
                FakeStorageKey("key1", ""),
                FakeStorageKey("key2", "storage-secret-two"),
            )
        ),
        FakeStorageKeyResult(
            (
                FakeStorageKey("key1", b"non-string-storage-secret"),
                FakeStorageKey("key2", "storage-secret-two"),
            )
        ),
        FakeStorageKeyResult(
            (
                cast(FakeStorageKey, object()),
                FakeStorageKey("key2", "storage-secret-two"),
            )
        ),
    ),
)
def test_storage_candidate_inspection_rejects_noncanonical_key_responses(
    key_result: FakeStorageKeyResult,
) -> None:
    operations = FakeStorageOperations(key_result=key_result, allow_key_calls=True)
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
    assert [warning.code for warning in result.warnings] == ["storage-key-response-incomplete"]
    serialized = result.model_dump_json()
    assert "storage-secret" not in serialized
    assert "duplicate-storage-secret" not in serialized
    assert "unexpected-storage-secret" not in serialized
    assert "non-string-storage-secret" not in serialized
    assert client.closed


def test_storage_candidate_permission_failure_is_resource_scoped_and_redacted() -> None:
    sensitive_value = "storage-secret-must-not-render"
    error = HttpResponseError(message=sensitive_value)
    error.status_code = 403
    operations = FakeStorageOperations(key_error=error, allow_key_calls=True)
    provider, client, _ = _provider(operations)
    resource = _candidate_resource()

    result = provider.inspect_candidates(SUBSCRIPTION_ID, (resource,), lambda resource_id, slot, value: None)
    serialized = result.model_dump_json()

    assert result.inspections[0].status is CandidateInspectionStatus.unavailable
    assert result.warnings[0].code == "storage-key-retrieval-forbidden"
    assert result.warnings[0].resource_id == resource.resource_id
    assert sensitive_value not in serialized
    assert client.closed


@pytest.mark.parametrize(
    ("error_type", "phase"),
    ((ServiceRequestError, "request"), (ServiceResponseError, "response")),
)
def test_storage_candidate_transport_failure_is_resource_scoped_and_redacted(
    error_type: type[Exception],
    phase: str,
) -> None:
    sensitive_value = "storage-key-transport-secret"
    operations = FakeStorageOperations(
        key_error=error_type(sensitive_value),
        allow_key_calls=True,
    )
    provider, client, _ = _provider(operations)
    resource = _candidate_resource()

    result = provider.inspect_candidates(SUBSCRIPTION_ID, (resource,), lambda resource_id, slot, value: None)

    assert result.inspections[0].status is CandidateInspectionStatus.unavailable
    assert result.warnings[0].code == "storage-key-retrieval-failed"
    assert phase in result.warnings[0].message
    assert sensitive_value not in result.model_dump_json()
    assert client.closed


def test_storage_candidate_inspection_rejects_malformed_resource_id_before_key_call() -> None:
    operations = FakeStorageOperations(allow_key_calls=True)
    provider, client, _ = _provider(operations)
    resource = _candidate_resource().model_copy(update={"resource_id": "/not/an/arm/id"})

    result = provider.inspect_candidates(SUBSCRIPTION_ID, (resource,), lambda resource_id, slot, value: None)

    assert operations.list_keys_calls == 0
    assert result.inspections[0].status is CandidateInspectionStatus.unavailable
    assert result.warnings[0].code == "malformed-storage-resource-id"
    assert client.closed


def test_storage_rotation_reads_only_the_requested_slot_through_a_callback() -> None:
    operations = FakeStorageOperations(
        key_result=FakeStorageKeyResult(
            (
                FakeStorageKey("key1", "storage-secret-one"),
                FakeStorageKey("key2", "storage-secret-two"),
            )
        ),
        allow_key_calls=True,
    )
    provider, client, _ = _provider(operations)
    consumed: list[str] = []

    provider.use_key_slot(SUBSCRIPTION_ID, _candidate_resource(), "key2", consumed.append)

    assert consumed == ["storage-secret-two"]
    consumed.clear()
    assert operations.key_call_arguments == [("rg", "accountone", None, False)]
    assert client.closed


def test_storage_key_state_streams_the_exact_reviewed_pair() -> None:
    operations = FakeStorageOperations(
        key_result=FakeStorageKeyResult(
            (
                FakeStorageKey("key1", "storage-secret-one"),
                FakeStorageKey("key2", "storage-secret-two"),
            )
        ),
        allow_key_calls=True,
    )
    provider, client, _ = _provider(operations)
    consumed: list[tuple[str, str]] = []

    provider.use_key_state(
        SUBSCRIPTION_ID,
        _candidate_resource(),
        lambda slot, value: consumed.append((slot, value)),
    )

    assert consumed == [("key1", "storage-secret-one"), ("key2", "storage-secret-two")]
    consumed.clear()
    assert operations.key_call_arguments == [("rg", "accountone", None, False)]
    assert client.closed


def test_storage_rotation_delegates_retries_to_the_sdk_for_one_exact_slot() -> None:
    operations = FakeStorageOperations(
        key_result=FakeStorageKeyResult(
            (
                FakeStorageKey("key1", "new-storage-secret-one"),
                FakeStorageKey("key2", "storage-secret-two"),
            )
        ),
        allow_regeneration=True,
    )
    provider, client, _ = _provider(operations)

    provider.regenerate_key(SUBSCRIPTION_ID, _candidate_resource(), "key1")

    assert operations.regenerate_calls == [("rg", "accountone", "key1", False)]
    assert operations.list_keys_calls == 0
    assert client.closed


def test_storage_rotation_rejects_an_unreviewed_target_before_mutation() -> None:
    operations = FakeStorageOperations(allow_regeneration=True)
    provider, client, _ = _provider(operations)
    resource = _candidate_resource().model_copy(update={"resource_id": "/not/an/arm/id"})

    with pytest.raises(ProviderOperationError) as caught:
        provider.regenerate_key(SUBSCRIPTION_ID, resource, "key1")

    assert caught.value.code == "storage-operation-contract-invalid"
    assert operations.regenerate_calls == []
    assert not client.closed


def test_storage_rotation_failure_is_status_only_and_redacted() -> None:
    sensitive_value = "storage-provider-error-secret"
    error = HttpResponseError(message=sensitive_value)
    error.status_code = 403
    operations = FakeStorageOperations(regeneration_error=error, allow_regeneration=True)
    provider, client, _ = _provider(operations)

    with pytest.raises(ProviderOperationError) as caught:
        provider.regenerate_key(SUBSCRIPTION_ID, _candidate_resource(), "key1")

    assert caught.value.code == "storage-key-regeneration-forbidden"
    assert sensitive_value not in str(caught.value)
    assert sensitive_value not in repr(caught.value)
    assert client.closed


def test_storage_rotation_redacts_a_terminal_sdk_request_failure() -> None:
    sensitive_value = "request-error-containing-a-key"
    operations = FakeStorageOperations(
        regeneration_error=ServiceRequestError(sensitive_value),
        allow_regeneration=True,
    )
    provider, client, _ = _provider(operations)

    with pytest.raises(ProviderOperationError) as caught:
        provider.regenerate_key(SUBSCRIPTION_ID, _candidate_resource(), "key1")

    assert caught.value.code == "storage-key-regeneration-request-failed"
    assert sensitive_value not in str(caught.value)
    assert operations.regenerate_calls == [("rg", "accountone", "key1", False)]
    assert client.closed


def test_storage_rotation_rejects_an_incomplete_key_response_without_exposing_it() -> None:
    sensitive_value = "only-returned-storage-secret"
    operations = FakeStorageOperations(
        key_result=FakeStorageKeyResult((FakeStorageKey("key1", sensitive_value),)),
        allow_regeneration=True,
    )
    provider, client, _ = _provider(operations)

    with pytest.raises(ProviderOperationError) as caught:
        provider.regenerate_key(SUBSCRIPTION_ID, _candidate_resource(), "key1")

    assert caught.value.code == "storage-key-response-invalid"
    assert sensitive_value not in str(caught.value)
    assert client.closed

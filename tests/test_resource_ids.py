"""Tests for strict ARM resource-scope validation before key operations."""

from __future__ import annotations

import pytest

from azurator.providers.resource_ids import (
    ProjectConnectionCoordinates,
    ResourceCoordinates,
    ResourceIdError,
    project_connection_coordinates,
    resource_coordinates,
)

SUBSCRIPTION_ID = "11111111-1111-1111-1111-111111111111"


def test_resource_coordinates_accepts_the_exact_selected_scope() -> None:
    resource_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/accountone"
    )

    result = resource_coordinates(
        resource_id,
        subscription_id=SUBSCRIPTION_ID,
        expected_resource_type="Microsoft.Storage/storageAccounts",
        expected_name="accountone",
    )

    assert result == ResourceCoordinates(resource_group="rg", resource_name="accountone")


@pytest.mark.parametrize(
    "resource_id",
    [
        "/not/an/arm/id",
        (
            "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg/providers/"
            "Microsoft.Storage/storageAccounts/accountone"
        ),
        (
            f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
            "Microsoft.CognitiveServices/accounts/accountone"
        ),
        (f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/different"),
        (
            f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
            "Microsoft.Storage/storageAccounts/accountone/blobServices/default"
        ),
    ],
)
def test_resource_coordinates_rejects_scope_drift(resource_id: str) -> None:
    with pytest.raises(ResourceIdError):
        resource_coordinates(
            resource_id,
            subscription_id=SUBSCRIPTION_ID,
            expected_resource_type="Microsoft.Storage/storageAccounts",
            expected_name="accountone",
        )


def test_project_connection_coordinates_accepts_the_exact_nested_scope() -> None:
    project_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.CognitiveServices/accounts/foundryone/projects/projectone"
    )

    result = project_connection_coordinates(
        f"{project_id}/connections/storage-connection",
        subscription_id=SUBSCRIPTION_ID,
        expected_project_id=project_id,
        expected_connection_name="storage-connection",
    )

    assert result == ProjectConnectionCoordinates(
        resource_group="rg",
        account_name="foundryone",
        project_name="projectone",
        connection_name="storage-connection",
    )


@pytest.mark.parametrize(
    "connection_id",
    [
        "/not/an/arm/id",
        (
            "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg/providers/"
            "Microsoft.CognitiveServices/accounts/foundryone/projects/projectone/connections/storage-connection"
        ),
        (
            f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
            "Microsoft.CognitiveServices/accounts/foundryone/projects/other/connections/storage-connection"
        ),
        (
            f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
            "Microsoft.CognitiveServices/accounts/foundryone/projects/projectone/connections/other"
        ),
        (
            f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
            "Microsoft.CognitiveServices/accounts/foundryone/projects/projectone/connections/"
            "storage-connection/children/nested"
        ),
    ],
)
def test_project_connection_coordinates_rejects_scope_drift(connection_id: str) -> None:
    project_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.CognitiveServices/accounts/foundryone/projects/projectone"
    )

    with pytest.raises(ResourceIdError):
        project_connection_coordinates(
            connection_id,
            subscription_id=SUBSCRIPTION_ID,
            expected_project_id=project_id,
            expected_connection_name="storage-connection",
        )

"""Validated extraction of Azure SDK call coordinates from ARM resource IDs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast

from azure.mgmt.core.tools import parse_resource_id


class ResourceIdError(ValueError):
    """A discovered resource ID cannot safely scope a provider operation."""


@dataclass(frozen=True)
class ResourceCoordinates:
    """Names required by generated Azure management operations."""

    resource_group: str
    resource_name: str


@dataclass(frozen=True)
class ProjectConnectionCoordinates:
    """Names required by the supported Foundry project-connection operation."""

    resource_group: str
    account_name: str
    project_name: str
    connection_name: str


def resource_coordinates(
    resource_id: str,
    *,
    subscription_id: str,
    expected_resource_type: str,
    expected_name: str,
) -> ResourceCoordinates:
    """Validate a top-level ARM ID before using its group and name in an SDK call."""

    try:
        expected_namespace, expected_type = expected_resource_type.split("/", 1)
    except ValueError as error:
        raise ResourceIdError("the provider has an invalid resource type contract") from error

    parsed = parse_resource_id(resource_id)
    subscription = parsed.get("subscription")
    resource_group = parsed.get("resource_group")
    namespace = parsed.get("namespace")
    resource_type = parsed.get("type")
    resource_name = parsed.get("name")
    children = parsed.get("children")

    string_values = (subscription, resource_group, namespace, resource_type, resource_name)
    if not all(isinstance(value, str) and value for value in string_values):
        raise ResourceIdError("Azure returned an incomplete top-level resource ID")
    assert isinstance(subscription, str)
    assert isinstance(resource_group, str)
    assert isinstance(namespace, str)
    assert isinstance(resource_type, str)
    assert isinstance(resource_name, str)

    if subscription.casefold() != subscription_id.casefold():
        raise ResourceIdError("the resource ID belongs to a different subscription")
    if namespace.casefold() != expected_namespace.casefold() or resource_type.casefold() != expected_type.casefold():
        raise ResourceIdError("the resource ID does not match the supported key-resource type")
    if resource_name.casefold() != expected_name.casefold():
        raise ResourceIdError("the resource ID and discovered resource name do not agree")
    if children != "":
        raise ResourceIdError("the resource ID is not one complete top-level resource ID")

    return ResourceCoordinates(resource_group=resource_group, resource_name=resource_name)


def project_connection_coordinates(
    connection_id: str,
    *,
    subscription_id: str,
    expected_project_id: str,
    expected_connection_name: str,
) -> ProjectConnectionCoordinates:
    """Validate one exact Cognitive Services project-connection ARM ID."""

    parsed = parse_resource_id(connection_id)
    expected_project = parse_resource_id(expected_project_id)
    raw_fields = {
        "subscription": parsed.get("subscription"),
        "resource_group": parsed.get("resource_group"),
        "namespace": parsed.get("namespace"),
        "type": parsed.get("type"),
        "account_name": parsed.get("name"),
        "project_type": parsed.get("child_type_1"),
        "project_name": parsed.get("child_name_1"),
        "connection_type": parsed.get("child_type_2"),
        "connection_name": parsed.get("child_name_2"),
    }
    if not all(isinstance(value, str) and value for value in raw_fields.values()):
        raise ResourceIdError("Azure returned an incomplete project-connection resource ID")
    fields = cast(dict[str, str], raw_fields)
    if parsed.get("last_child_num") != 2:
        raise ResourceIdError("the connection ID has an unsupported nested resource shape")

    raw_expected_fields = {
        "subscription": expected_project.get("subscription"),
        "resource_group": expected_project.get("resource_group"),
        "namespace": expected_project.get("namespace"),
        "type": expected_project.get("type"),
        "account_name": expected_project.get("name"),
        "project_type": expected_project.get("child_type_1"),
        "project_name": expected_project.get("child_name_1"),
    }
    if not all(isinstance(value, str) and value for value in raw_expected_fields.values()):
        raise ResourceIdError("the expected project ID is incomplete")
    expected_fields = cast(dict[str, str], raw_expected_fields)
    if expected_project.get("last_child_num") != 1:
        raise ResourceIdError("the expected project ID has an unsupported nested resource shape")

    if fields["subscription"].casefold() != subscription_id.casefold():
        raise ResourceIdError("the connection belongs to a different subscription")
    if fields["namespace"].casefold() != "microsoft.cognitiveservices":
        raise ResourceIdError("the connection does not use the supported resource provider")
    if fields["type"].casefold() != "accounts":
        raise ResourceIdError("the connection does not belong to a Cognitive Services account")
    if fields["project_type"].casefold() != "projects" or fields["connection_type"].casefold() != "connections":
        raise ResourceIdError("the connection does not use the supported project hierarchy")
    if any(fields[name].casefold() != expected_fields[name].casefold() for name in expected_fields):
        raise ResourceIdError("the connection ID and project coordinates do not agree")
    if fields["connection_name"] != expected_connection_name:
        raise ResourceIdError("the connection ID and expected connection name do not agree")

    return ProjectConnectionCoordinates(
        resource_group=fields["resource_group"],
        account_name=fields["account_name"],
        project_name=fields["project_name"],
        connection_name=fields["connection_name"],
    )

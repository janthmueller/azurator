"""Strict, secret-free selector mappings for reusable Azure-key export."""

from __future__ import annotations

import json
import re
from uuid import UUID

from azure.mgmt.core.tools import parse_resource_id
from pydantic import ValidationError

from azurator.inputs import SecretInputError, validate_dotenv_selector
from azurator.models import KeyMap, KeyMapEntry, MatchReport, MatchResource

_KEY_SLOT_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9]*$")


class KeyMapError(RuntimeError):
    """A key map cannot be created or loaded without guessing its meaning."""


class _DuplicateJsonMemberError(ValueError):
    """One JSON object repeated a member name."""


def _reject_duplicate_json_members(pairs: list[tuple[str, object]]) -> dict[str, object]:
    decoded: dict[str, object] = {}
    for name, value in pairs:
        if name in decoded:
            raise _DuplicateJsonMemberError
        decoded[name] = value
    return decoded


def _subscription_uuid(value: str, *, source: str) -> UUID:
    try:
        subscription_id = UUID(value)
    except ValueError:
        raise KeyMapError(f"{source} contains an invalid Azure subscription ID") from None
    if subscription_id.int == 0 or str(subscription_id) != value.casefold():
        raise KeyMapError(f"{source} contains an invalid Azure subscription ID")
    return subscription_id


def _validate_mapping_contract(
    mapping: KeyMapEntry,
    *,
    subscription_id: UUID,
    source: str,
) -> None:
    try:
        parsed = parse_resource_id(mapping.key_resource_id)
    except (TypeError, ValueError):
        raise KeyMapError(f"{source} contains an invalid top-level Azure resource ID") from None

    fields = {
        "subscription": parsed.get("subscription"),
        "resource_group": parsed.get("resource_group"),
        "namespace": parsed.get("namespace"),
        "type": parsed.get("type"),
        "name": parsed.get("name"),
    }
    if not all(isinstance(value, str) and value for value in fields.values()) or parsed.get("children") not in {
        None,
        "",
    }:
        raise KeyMapError(f"{source} contains an invalid top-level Azure resource ID")

    resource_subscription = fields["subscription"]
    assert isinstance(resource_subscription, str)
    try:
        parsed_subscription = UUID(resource_subscription)
    except ValueError:
        raise KeyMapError(f"{source} contains an invalid top-level Azure resource ID") from None
    if str(parsed_subscription) != resource_subscription.casefold():
        raise KeyMapError(f"{source} contains an invalid top-level Azure resource ID")
    if parsed_subscription != subscription_id:
        raise KeyMapError(f"{source} contains a resource ID from a different Azure subscription")

    canonical_id = (
        f"/subscriptions/{fields['subscription']}"
        f"/resourceGroups/{fields['resource_group']}"
        f"/providers/{fields['namespace']}/{fields['type']}/{fields['name']}"
    )
    if canonical_id.casefold() != mapping.key_resource_id.casefold():
        raise KeyMapError(f"{source} contains an invalid top-level Azure resource ID")
    if _KEY_SLOT_PATTERN.fullmatch(mapping.key_slot) is None:
        raise KeyMapError(f"{source} contains an invalid Azure key slot name")


def _validate_key_map_contract(key_map: KeyMap, *, source: str) -> None:
    subscription_id = _subscription_uuid(key_map.subscription_id, source=source)
    for mapping in key_map.mappings:
        try:
            validate_dotenv_selector(mapping.selector)
        except SecretInputError:
            raise KeyMapError(f"{source} contains an invalid dotenv selector") from None
        _validate_mapping_contract(
            mapping,
            subscription_id=subscription_id,
            source=source,
        )


def build_key_map(report: MatchReport) -> KeyMap:
    """Project confirmed, unambiguous matches into one portable key map."""

    if len(set(report.input_selectors)) != len(report.input_selectors):
        raise KeyMapError("the match report contains one input selector more than once")

    resources: dict[str, MatchResource] = {}
    for resource in report.resources:
        if resource.resource_id in resources:
            raise KeyMapError("the match report contains one Azure key resource more than once")
        resources[resource.resource_id] = resource

    identities_by_selector: dict[str, list[tuple[str, str]]] = {}
    for match in report.matches:
        resource = resources.get(match.resource_id)
        if resource is None:
            raise KeyMapError("a confirmed match has no Azure key-resource metadata")
        if match.input_selector not in report.input_selectors:
            raise KeyMapError("a confirmed match references an unknown input selector")
        key_slots = {slot.name for slot in resource.key_slots}
        if match.key_slot not in key_slots:
            raise KeyMapError("a confirmed match references an unknown Azure key slot")
        identity = (match.resource_id, match.key_slot)
        identities = identities_by_selector.setdefault(match.input_selector, [])
        if identity in identities:
            raise KeyMapError("the match report contains one confirmed mapping more than once")
        identities.append(identity)

    mappings: list[KeyMapEntry] = []
    for selector in report.input_selectors:
        identities = identities_by_selector.get(selector, [])
        if len(identities) > 1:
            raise KeyMapError(f"dotenv selector {selector!r} matched more than one Azure key slot")
        if not identities:
            continue
        try:
            validate_dotenv_selector(selector)
        except SecretInputError:
            raise KeyMapError("a matched selector violates the supported dotenv contract") from None
        resource_id, key_slot = identities[0]
        mappings.append(
            KeyMapEntry(
                selector=selector,
                key_resource_id=resource_id,
                key_slot=key_slot,
            )
        )

    if not mappings:
        raise KeyMapError("no confirmed Azure key matches are available for a key map")
    key_map = KeyMap(subscription_id=report.subscription_id, mappings=tuple(mappings))
    _validate_key_map_contract(key_map, source="the match report")
    return key_map


def parse_key_map(payload: str) -> KeyMap:
    """Validate one exact current key-map JSON document without rendering its content."""

    try:
        decoded = json.loads(payload, object_pairs_hook=_reject_duplicate_json_members)
        key_map = KeyMap.model_validate(decoded)
    except (json.JSONDecodeError, _DuplicateJsonMemberError, ValidationError):
        raise KeyMapError("the key-map file does not satisfy the current Azurator key-map format") from None

    _validate_key_map_contract(key_map, source="the key-map file")
    return key_map

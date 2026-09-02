"""Secret-free key-map creation, parsing, and export-resolution tests."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from azurator.exporting import ExportError, build_key_map_export_assignments
from azurator.key_map import KeyMapError, build_key_map, parse_key_map
from azurator.models import KeyAuthentication, KeyMap, KeyMapEntry, KeyMatch
from tests.cli_test_support import SUBSCRIPTION_ID, make_inventory, make_match_report


def test_key_map_projects_confirmed_matches_in_input_order_and_preserves_aliases() -> None:
    report = make_match_report()
    first = report.matches[0]
    report = report.model_copy(
        update={
            "input_selectors": ("STORAGE_ALIAS", *report.input_selectors),
            "matches": (
                KeyMatch(
                    input_selector="STORAGE_ALIAS",
                    resource_id=first.resource_id,
                    key_slot=first.key_slot,
                ),
                *report.matches,
            ),
        }
    )

    key_map = build_key_map(report)

    assert key_map == KeyMap(
        subscription_id=SUBSCRIPTION_ID,
        mappings=(
            KeyMapEntry(
                selector="STORAGE_ALIAS",
                key_resource_id=first.resource_id,
                key_slot="key1",
            ),
            KeyMapEntry(
                selector="STORAGE_KEY",
                key_resource_id=first.resource_id,
                key_slot="key1",
            ),
            KeyMapEntry(
                selector="SECOND_STORAGE_KEY",
                key_resource_id=first.resource_id,
                key_slot="key2",
            ),
        ),
    )
    payload = json.loads(key_map.model_dump_json())
    assert set(payload) == {"schema_version", "subscription_id", "mappings"}
    assert "generated_at" not in payload
    assert "source_path" not in payload


def test_key_map_rejects_ambiguous_or_duplicate_report_matches() -> None:
    report = make_match_report()
    first = report.matches[0]
    ambiguous = report.model_copy(
        update={
            "matches": (
                *report.matches,
                first.model_copy(update={"key_slot": "key2"}),
            )
        }
    )
    duplicate = report.model_copy(update={"matches": (*report.matches, first)})

    with pytest.raises(KeyMapError, match="matched more than one"):
        build_key_map(ambiguous)
    with pytest.raises(KeyMapError, match="more than once"):
        build_key_map(duplicate)


def test_key_map_rejects_inconsistent_match_report_metadata() -> None:
    report = make_match_report()
    first_match = report.matches[0]
    first_resource = report.resources[0]
    duplicate_resource = report.model_copy(update={"resources": (*report.resources, first_resource)})
    missing_resource = report.model_copy(
        update={"matches": (first_match.model_copy(update={"resource_id": f"{first_match.resource_id}-missing"}),)}
    )
    unknown_selector = report.model_copy(
        update={"matches": (first_match.model_copy(update={"input_selector": "UNKNOWN_SELECTOR"}),)}
    )
    unknown_slot = report.model_copy(update={"matches": (first_match.model_copy(update={"key_slot": "unknown"}),)})
    invalid_selector = report.model_copy(
        update={
            "input_selectors": ("INVALID-NAME",),
            "matches": (first_match.model_copy(update={"input_selector": "INVALID-NAME"}),),
        }
    )
    invalid_subscription = report.model_copy(update={"subscription_id": "not-a-uuid"})
    duplicate_input_selector = report.model_copy(
        update={"input_selectors": (*report.input_selectors, report.input_selectors[0])}
    )
    invalid_resource = first_resource.model_copy(update={"resource_id": "not-an-arm-id"})
    invalid_resource_report = report.model_copy(
        update={
            "resources": (invalid_resource, *report.resources[1:]),
            "matches": (first_match.model_copy(update={"resource_id": invalid_resource.resource_id}),),
        }
    )

    with pytest.raises(KeyMapError, match="invalid Azure subscription"):
        build_key_map(invalid_subscription)
    with pytest.raises(KeyMapError, match="input selector more than once"):
        build_key_map(duplicate_input_selector)
    with pytest.raises(KeyMapError, match="invalid top-level Azure resource ID"):
        build_key_map(invalid_resource_report)
    with pytest.raises(KeyMapError, match="key resource more than once"):
        build_key_map(duplicate_resource)
    with pytest.raises(KeyMapError, match="no Azure key-resource metadata"):
        build_key_map(missing_resource)
    with pytest.raises(KeyMapError, match="unknown input selector"):
        build_key_map(unknown_selector)
    with pytest.raises(KeyMapError, match="unknown Azure key slot"):
        build_key_map(unknown_slot)
    with pytest.raises(KeyMapError, match="violates the supported dotenv contract"):
        build_key_map(invalid_selector)


def test_key_map_requires_at_least_one_confirmed_match() -> None:
    report = make_match_report().model_copy(update={"matches": ()})

    with pytest.raises(KeyMapError, match="no confirmed"):
        build_key_map(report)


def test_key_map_parser_rejects_invalid_contracts_without_rendering_content() -> None:
    resource_id = make_inventory().resources[0].resource_id
    valid = KeyMap(
        subscription_id=SUBSCRIPTION_ID,
        mappings=(KeyMapEntry(selector="STORAGE_KEY", key_resource_id=resource_id, key_slot="key1"),),
    )

    assert parse_key_map(valid.model_dump_json()) == valid

    duplicate_selector = {
        "schema_version": "1",
        "subscription_id": SUBSCRIPTION_ID,
        "mappings": [
            {"selector": "STORAGE_KEY", "key_resource_id": resource_id, "key_slot": "key1"},
            {"selector": "STORAGE_KEY", "key_resource_id": resource_id, "key_slot": "key2"},
        ],
    }
    invalid_selector = valid.model_copy(
        update={"mappings": (valid.mappings[0].model_copy(update={"selector": "INVALID-NAME"}),)}
    )
    invalid_subscription = valid.model_copy(update={"subscription_id": "not-a-uuid"})
    zero_subscription = valid.model_copy(update={"subscription_id": "00000000-0000-0000-0000-000000000000"})
    noncanonical_subscription = valid.model_copy(update={"subscription_id": SUBSCRIPTION_ID.replace("-", "")})
    invalid_resource = valid.model_copy(
        update={"mappings": (valid.mappings[0].model_copy(update={"key_resource_id": "not-an-arm-id"}),)}
    )
    nested_resource = valid.model_copy(
        update={
            "mappings": (
                valid.mappings[0].model_copy(update={"key_resource_id": f"{resource_id}/blobServices/default"}),
            )
        }
    )
    invalid_embedded_subscription = valid.model_copy(
        update={
            "mappings": (
                valid.mappings[0].model_copy(
                    update={"key_resource_id": resource_id.replace(SUBSCRIPTION_ID, "not-a-uuid")}
                ),
            )
        }
    )
    noncanonical_embedded_subscription = valid.model_copy(
        update={
            "mappings": (
                valid.mappings[0].model_copy(
                    update={"key_resource_id": resource_id.replace(SUBSCRIPTION_ID, SUBSCRIPTION_ID.replace("-", ""))}
                ),
            )
        }
    )
    noncanonical_resource = valid.model_copy(
        update={"mappings": (valid.mappings[0].model_copy(update={"key_resource_id": f"{resource_id}/"}),)}
    )
    other_subscription_id = "22222222-2222-2222-2222-222222222222"
    cross_subscription_resource = valid.model_copy(
        update={
            "mappings": (
                valid.mappings[0].model_copy(
                    update={
                        "key_resource_id": resource_id.replace(
                            SUBSCRIPTION_ID,
                            other_subscription_id,
                        )
                    }
                ),
            )
        }
    )
    invalid_slot = valid.model_copy(
        update={"mappings": (valid.mappings[0].model_copy(update={"key_slot": "not a slot"}),)}
    )

    with pytest.raises(KeyMapError, match="current Azurator key-map format"):
        parse_key_map(json.dumps(duplicate_selector))
    with pytest.raises(KeyMapError, match="invalid dotenv selector"):
        parse_key_map(invalid_selector.model_dump_json())
    with pytest.raises(KeyMapError, match="invalid Azure subscription"):
        parse_key_map(invalid_subscription.model_dump_json())
    with pytest.raises(KeyMapError, match="invalid Azure subscription"):
        parse_key_map(zero_subscription.model_dump_json())
    with pytest.raises(KeyMapError, match="invalid Azure subscription"):
        parse_key_map(noncanonical_subscription.model_dump_json())
    with pytest.raises(KeyMapError, match="invalid top-level Azure resource ID"):
        parse_key_map(invalid_resource.model_dump_json())
    with pytest.raises(KeyMapError, match="invalid top-level Azure resource ID"):
        parse_key_map(nested_resource.model_dump_json())
    with pytest.raises(KeyMapError, match="invalid top-level Azure resource ID"):
        parse_key_map(invalid_embedded_subscription.model_dump_json())
    with pytest.raises(KeyMapError, match="invalid top-level Azure resource ID"):
        parse_key_map(noncanonical_embedded_subscription.model_dump_json())
    with pytest.raises(KeyMapError, match="invalid top-level Azure resource ID"):
        parse_key_map(noncanonical_resource.model_dump_json())
    with pytest.raises(KeyMapError, match="different Azure subscription"):
        parse_key_map(cross_subscription_resource.model_dump_json())
    with pytest.raises(KeyMapError, match="invalid Azure key slot name"):
        parse_key_map(invalid_slot.model_dump_json())


@pytest.mark.parametrize(
    "payload",
    (
        (
            '{"schema_version":"1","subscription_id":"11111111-1111-1111-1111-111111111111",'
            '"subscription_id":"22222222-2222-2222-2222-222222222222",'
            '"mappings":[{"selector":"STORAGE_KEY","key_resource_id":'
            '"/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/example/'
            'providers/Microsoft.Storage/storageAccounts/example","key_slot":"key1"}]}'
        ),
        (
            '{"schema_version":"1","subscription_id":"11111111-1111-1111-1111-111111111111",'
            '"mappings":[{"selector":"STORAGE_KEY","selector":"STORAGE_ALIAS",'
            '"key_resource_id":"/subscriptions/11111111-1111-1111-1111-111111111111/'
            'resourceGroups/example/providers/Microsoft.Storage/storageAccounts/example",'
            '"key_slot":"key1"}]}'
        ),
    ),
)
def test_key_map_parser_rejects_duplicate_json_member_names(payload: str) -> None:
    with pytest.raises(KeyMapError, match="current Azurator key-map format"):
        parse_key_map(payload)


def test_key_map_model_rejects_duplicate_selectors() -> None:
    resource_id = make_inventory().resources[0].resource_id

    with pytest.raises(ValidationError, match="key-map selectors must be unique"):
        KeyMap(
            subscription_id=SUBSCRIPTION_ID,
            mappings=(
                KeyMapEntry(selector="STORAGE_KEY", key_resource_id=resource_id, key_slot="key1"),
                KeyMapEntry(selector="STORAGE_KEY", key_resource_id=resource_id, key_slot="key2"),
            ),
        )


def test_key_map_export_resolution_preserves_aliases_and_exact_slots() -> None:
    inventory = make_inventory()
    resource = inventory.resources[0]
    key_map = KeyMap(
        subscription_id=SUBSCRIPTION_ID,
        mappings=(
            KeyMapEntry(selector="PRIMARY_KEY", key_resource_id=resource.resource_id, key_slot="key1"),
            KeyMapEntry(selector="PRIMARY_ALIAS", key_resource_id=resource.resource_id, key_slot="key1"),
            KeyMapEntry(selector="SECONDARY_KEY", key_resource_id=resource.resource_id, key_slot="key2"),
        ),
    )

    assignments = build_key_map_export_assignments(inventory, key_map)

    assert [assignment.selector for assignment in assignments] == [
        "PRIMARY_KEY",
        "PRIMARY_ALIAS",
        "SECONDARY_KEY",
    ]
    assert [assignment.key_slot for assignment in assignments] == ["key1", "key1", "key2"]
    assert all(assignment.resource == resource for assignment in assignments)


def test_key_map_export_resolution_does_not_add_an_unmapped_sibling_slot() -> None:
    inventory = make_inventory()
    resource = inventory.resources[0]
    key_map = KeyMap(
        subscription_id=SUBSCRIPTION_ID,
        mappings=(KeyMapEntry(selector="ONLY_PRIMARY", key_resource_id=resource.resource_id, key_slot="key1"),),
    )

    assignments = build_key_map_export_assignments(inventory, key_map)

    assert [(assignment.selector, assignment.key_slot) for assignment in assignments] == [("ONLY_PRIMARY", "key1")]


def test_key_map_export_resolution_fails_closed_on_scope_resource_and_slot_drift() -> None:
    inventory = make_inventory()
    resource = inventory.resources[0]
    mapping = KeyMapEntry(selector="STORAGE_KEY", key_resource_id=resource.resource_id, key_slot="key1")

    wrong_subscription = KeyMap(
        subscription_id="22222222-2222-2222-2222-222222222222",
        mappings=(mapping,),
    )
    missing_resource = KeyMap(
        subscription_id=SUBSCRIPTION_ID,
        mappings=(mapping.model_copy(update={"key_resource_id": f"{resource.resource_id}-missing"}),),
    )
    unknown_slot = KeyMap(
        subscription_id=SUBSCRIPTION_ID,
        mappings=(mapping.model_copy(update={"key_slot": "unknown"}),),
    )
    disabled_inventory = inventory.model_copy(
        update={"resources": (resource.model_copy(update={"key_authentication": KeyAuthentication.disabled}),)}
    )

    with pytest.raises(ExportError, match="different Azure subscription"):
        build_key_map_export_assignments(inventory, wrong_subscription)
    with pytest.raises(ExportError, match="outside the discovered inventory"):
        build_key_map_export_assignments(inventory, missing_resource)
    with pytest.raises(ExportError, match="retrievable key-pair contract"):
        build_key_map_export_assignments(inventory, unknown_slot)
    with pytest.raises(ExportError, match="retrievable key-pair contract"):
        build_key_map_export_assignments(
            disabled_inventory, KeyMap(subscription_id=SUBSCRIPTION_ID, mappings=(mapping,))
        )

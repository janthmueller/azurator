"""Tests for reviewed raw-key and Storage connection-string value forms."""

from __future__ import annotations

import pytest

from azurator.credential_values import (
    CredentialValueState,
    credential_value_matches,
    credential_value_shape_matches_resource,
    credential_values_match,
    parse_storage_shared_key_connection_string,
    replace_credential_value,
    transition_credential_value,
    transition_credential_values,
)

STORAGE_RESOURCE_TYPE = "Microsoft.Storage/storageAccounts"
STORAGE_ACCOUNT = "storageone"
CURRENT_KEY = "current-storage-key=="
REPLACEMENT_KEY = "replacement-storage-key=="


def _connection_string(key: str = CURRENT_KEY) -> str:
    return (
        f"DefaultEndpointsProtocol=https;AccountName={STORAGE_ACCOUNT};AccountKey={key};EndpointSuffix=core.windows.net"
    )


@pytest.mark.parametrize(
    "value",
    (
        _connection_string(),
        (
            "DefaultEndpointsProtocol=https;BlobEndpoint=https://storage.example.test/custom/path;"
            f"AccountName={STORAGE_ACCOUNT};AccountKey={CURRENT_KEY};"
        ),
    ),
)
def test_parse_accepts_documented_storage_shared_key_forms(value: str) -> None:
    parsed = parse_storage_shared_key_connection_string(value)

    assert parsed is not None
    assert parsed.account_name == STORAGE_ACCOUNT
    assert parsed.account_key == CURRENT_KEY
    assert parsed.replace_account_key(value, REPLACEMENT_KEY) == value.replace(CURRENT_KEY, REPLACEMENT_KEY)
    assert CURRENT_KEY not in repr(parsed)


@pytest.mark.parametrize(
    "value",
    (
        "UseDevelopmentStorage=true",
        "BlobEndpoint=https://storage.example.test;SharedAccessSignature=secret",
        f"AccountName={STORAGE_ACCOUNT};AccountKey={CURRENT_KEY}",
        f"DefaultEndpointsProtocol=ftp;AccountName={STORAGE_ACCOUNT};AccountKey={CURRENT_KEY}",
        f"DefaultEndpointsProtocol=https;accountname={STORAGE_ACCOUNT};AccountKey={CURRENT_KEY}",
        f"DefaultEndpointsProtocol=https;AccountName={STORAGE_ACCOUNT};AccountKey={CURRENT_KEY};AccountKey=again",
        f"DefaultEndpointsProtocol=https;;AccountName={STORAGE_ACCOUNT};AccountKey={CURRENT_KEY}",
        f"DefaultEndpointsProtocol=https;AccountName=OTHER;AccountKey={CURRENT_KEY}",
        f"DefaultEndpointsProtocol=https;AccountName={STORAGE_ACCOUNT};AccountKey={CURRENT_KEY};Unknown=value",
        (f"BlobEndpoint=https://storage.example.test;AccountName={STORAGE_ACCOUNT};AccountKey={CURRENT_KEY}"),
        f"BlobEndpoint=not-a-uri;AccountName={STORAGE_ACCOUNT};AccountKey={CURRENT_KEY}",
        (
            f"DefaultEndpointsProtocol=https;AccountName={STORAGE_ACCOUNT};AccountKey={CURRENT_KEY};"
            "BlobEndpoint=https://:"
        ),
        (
            f"DefaultEndpointsProtocol=https;AccountName={STORAGE_ACCOUNT};AccountKey={CURRENT_KEY};"
            "BlobEndpoint=https://storage example.test"
        ),
        (
            f"DefaultEndpointsProtocol=https;AccountName={STORAGE_ACCOUNT};AccountKey={CURRENT_KEY};"
            "BlobEndpoint=https://storage.example.test:invalid"
        ),
        (
            f"DefaultEndpointsProtocol=https;AccountName={STORAGE_ACCOUNT};AccountKey={CURRENT_KEY};"
            "BlobEndpoint=https://storage.example.test/%invalid"
        ),
        (
            f"DefaultEndpointsProtocol=https;AccountName={STORAGE_ACCOUNT};AccountKey={CURRENT_KEY};"
            "BlobEndpoint=https://user@storage.example.test"
        ),
        (
            f"DefaultEndpointsProtocol=https;AccountName={STORAGE_ACCOUNT};AccountKey={CURRENT_KEY};"
            "BlobEndpoint=https://storage.example.test/#fragment"
        ),
        f"DefaultEndpointsProtocol=https;AccountName={STORAGE_ACCOUNT};AccountKey={CURRENT_KEY};EndpointSuffix=a..b",
        (
            f"DefaultEndpointsProtocol=https;AccountName={STORAGE_ACCOUNT};AccountKey={CURRENT_KEY};"
            f"EndpointSuffix={'a' * 64}.example"
        ),
    ),
)
def test_parse_rejects_values_outside_the_reviewed_contract(value: str) -> None:
    assert parse_storage_shared_key_connection_string(value) is None


def test_transition_preserves_the_connection_string_and_changes_only_account_key() -> None:
    value = _connection_string()

    state, replacement = transition_credential_value(
        value,
        resource_type=STORAGE_RESOURCE_TYPE,
        resource_name=STORAGE_ACCOUNT,
        expected_key=CURRENT_KEY,
        replacement_key=REPLACEMENT_KEY,
    )

    assert state is CredentialValueState.expected
    assert replacement == _connection_string(REPLACEMENT_KEY)
    assert credential_value_matches(
        replacement or "",
        resource_type=STORAGE_RESOURCE_TYPE,
        resource_name=STORAGE_ACCOUNT,
        expected_key=REPLACEMENT_KEY,
    )


def test_replacement_changes_only_the_parsed_account_key_span() -> None:
    value = (
        "DefaultEndpointsProtocol=https;"
        f"BlobEndpoint=https://example.test/{CURRENT_KEY};"
        f"AccountName={STORAGE_ACCOUNT};AccountKey={CURRENT_KEY}"
    )

    parsed = parse_storage_shared_key_connection_string(value)

    assert parsed is not None
    assert parsed.replace_account_key(value, REPLACEMENT_KEY) == (
        "DefaultEndpointsProtocol=https;"
        f"BlobEndpoint=https://example.test/{CURRENT_KEY};"
        f"AccountName={STORAGE_ACCOUNT};AccountKey={REPLACEMENT_KEY}"
    )


def test_transition_rejects_a_connection_string_for_another_storage_account() -> None:
    value = _connection_string().replace(STORAGE_ACCOUNT, "storagetwo")

    state, replacement = transition_credential_value(
        value,
        resource_type=STORAGE_RESOURCE_TYPE,
        resource_name=STORAGE_ACCOUNT,
        expected_key=CURRENT_KEY,
        replacement_key=REPLACEMENT_KEY,
    )

    assert state is CredentialValueState.drift
    assert replacement is None
    with pytest.raises(ValueError, match="different key resource"):
        replace_credential_value(
            value,
            resource_type=STORAGE_RESOURCE_TYPE,
            resource_name=STORAGE_ACCOUNT,
            replacement_key=REPLACEMENT_KEY,
        )


def test_transition_treats_an_unexpected_embedded_key_as_drift() -> None:
    state, replacement = transition_credential_value(
        _connection_string("unrelated-storage-key=="),
        resource_type=STORAGE_RESOURCE_TYPE,
        resource_name=STORAGE_ACCOUNT,
        expected_key=CURRENT_KEY,
        replacement_key=REPLACEMENT_KEY,
    )

    assert state is CredentialValueState.drift
    assert replacement is None


def test_raw_key_values_keep_the_existing_transition_contract() -> None:
    state, replacement = transition_credential_value(
        CURRENT_KEY,
        resource_type=STORAGE_RESOURCE_TYPE,
        resource_name=STORAGE_ACCOUNT,
        expected_key=CURRENT_KEY,
        replacement_key=REPLACEMENT_KEY,
    )

    assert state is CredentialValueState.expected
    assert replacement == REPLACEMENT_KEY


def test_grouped_transition_preserves_each_representation_and_rejects_mixed_state() -> None:
    values = {
        "CONNECTION": _connection_string(),
        "RAW_ALIAS": CURRENT_KEY,
    }

    state, replacements = transition_credential_values(
        values,
        ("CONNECTION", "RAW_ALIAS"),
        resource_type=STORAGE_RESOURCE_TYPE,
        resource_name=STORAGE_ACCOUNT,
        expected_key=CURRENT_KEY,
        replacement_key=REPLACEMENT_KEY,
    )

    assert state is CredentialValueState.expected
    assert replacements == {
        "CONNECTION": _connection_string(REPLACEMENT_KEY),
        "RAW_ALIAS": REPLACEMENT_KEY,
    }

    mixed = {**values, "CONNECTION": _connection_string(REPLACEMENT_KEY)}
    state, replacements = transition_credential_values(
        mixed,
        ("CONNECTION", "RAW_ALIAS"),
        resource_type=STORAGE_RESOURCE_TYPE,
        resource_name=STORAGE_ACCOUNT,
        expected_key=CURRENT_KEY,
        replacement_key=REPLACEMENT_KEY,
    )

    assert state is CredentialValueState.drift
    assert replacements == {}


def test_grouped_transition_recognizes_a_completed_structured_update() -> None:
    values = {
        "CONNECTION": _connection_string(REPLACEMENT_KEY),
        "RAW_ALIAS": REPLACEMENT_KEY,
    }

    state, replacements = transition_credential_values(
        values,
        ("CONNECTION", "RAW_ALIAS"),
        resource_type=STORAGE_RESOURCE_TYPE,
        resource_name=STORAGE_ACCOUNT,
        expected_key=CURRENT_KEY,
        replacement_key=REPLACEMENT_KEY,
    )

    assert state is CredentialValueState.replacement
    assert replacements == {}
    assert credential_values_match(
        values,
        ("CONNECTION", "RAW_ALIAS"),
        resource_type=STORAGE_RESOURCE_TYPE,
        resource_name=STORAGE_ACCOUNT,
        expected_key=REPLACEMENT_KEY,
    )


def test_structured_value_never_matches_or_maps_to_a_different_resource_type() -> None:
    value = _connection_string()

    assert not credential_value_matches(
        value,
        resource_type="Microsoft.CognitiveServices/accounts",
        resource_name=STORAGE_ACCOUNT,
        expected_key=CURRENT_KEY,
    )
    assert not credential_value_shape_matches_resource(
        value,
        resource_type="Microsoft.CognitiveServices/accounts",
        resource_name=STORAGE_ACCOUNT,
    )


def test_replacement_span_validation_is_fixed_and_secret_free() -> None:
    value = _connection_string()
    parsed = parse_storage_shared_key_connection_string(value)
    assert parsed is not None

    with pytest.raises(ValueError) as caught:
        parsed.replace_account_key(value.replace(CURRENT_KEY, "externally-changed-key"), REPLACEMENT_KEY)

    assert "externally-changed-key" not in str(caught.value)
    assert CURRENT_KEY not in str(caught.value)

"""Tests for ephemeral matching and durable key-state fingerprints."""

from __future__ import annotations

import pytest

from azurator.fingerprints import (
    EphemeralFingerprinter,
    derive_key_state_fingerprint,
    equal_key_state_fingerprints,
    erase_fingerprint,
    new_key_state_salt,
)


def test_fingerprints_match_only_within_the_same_session_key() -> None:
    with EphemeralFingerprinter(b"a" * 32) as first, EphemeralFingerprinter(b"b" * 32) as second:
        first_value = first.derive("same-value")
        first_duplicate = first.derive("same-value")
        different_value = first.derive("different-value")
        other_session = second.derive("same-value")

        assert first.equal(first_value, first_duplicate)
        assert not first.equal(first_value, different_value)
        assert not first.equal(first_value, other_session)

        for digest in (first_value, first_duplicate, different_value, other_session):
            erase_fingerprint(digest)
            assert set(digest) == {0}


def test_closed_fingerprinter_refuses_reuse() -> None:
    fingerprinter = EphemeralFingerprinter(b"a" * 32)
    fingerprinter.close()

    with pytest.raises(RuntimeError, match="closed"):
        fingerprinter.derive("value")


def test_ephemeral_key_must_be_256_bits() -> None:
    with pytest.raises(ValueError, match="256 bits"):
        EphemeralFingerprinter(b"short")


def test_key_state_fingerprints_are_stable_only_for_the_same_operation_identity() -> None:
    salt = "00" * 32
    first = derive_key_state_fingerprint(
        "azure-generated-key",
        salt=salt,
        resource_id="/subscriptions/example/resources/one",
        key_slot="key1",
    )
    duplicate = derive_key_state_fingerprint(
        "azure-generated-key",
        salt=salt,
        resource_id="/subscriptions/example/resources/one",
        key_slot="key1",
    )
    other_slot = derive_key_state_fingerprint(
        "azure-generated-key",
        salt=salt,
        resource_id="/subscriptions/example/resources/one",
        key_slot="key2",
    )
    other_salt = derive_key_state_fingerprint(
        "azure-generated-key",
        salt="11" * 32,
        resource_id="/subscriptions/example/resources/one",
        key_slot="key1",
    )

    assert first.startswith("sha256:v1:")
    assert "azure-generated-key" not in first
    assert equal_key_state_fingerprints(first, duplicate)
    assert not equal_key_state_fingerprints(first, other_slot)
    assert not equal_key_state_fingerprints(first, other_salt)


def test_key_state_salt_is_random_and_strictly_validated() -> None:
    first = new_key_state_salt()
    second = new_key_state_salt()

    assert len(first) == 64
    assert first != second
    with pytest.raises(ValueError, match="lowercase hexadecimal"):
        derive_key_state_fingerprint(
            "value",
            salt="AA" * 32,
            resource_id="resource",
            key_slot="key1",
        )

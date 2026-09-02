"""Domain-separated fingerprints for matching and durable key-state recovery."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from types import TracebackType

_SESSION_KEY_BYTES = 32
_DOMAIN = b"azurator/session-match/v1\x00"
_KEY_STATE_SALT_BYTES = 32
_KEY_STATE_DOMAIN = b"azurator/operation-key-state/v1\x00"
_KEY_STATE_PREFIX = "sha256:v1:"


class EphemeralFingerprinter:
    """Derive unlinkable per-run fingerprints and erase owned buffers on close."""

    def __init__(self, key: bytes | None = None) -> None:
        material = key if key is not None else secrets.token_bytes(_SESSION_KEY_BYTES)
        if len(material) != _SESSION_KEY_BYTES:
            raise ValueError("the ephemeral matching key must be exactly 256 bits")
        self._key = bytearray(material)
        self._closed = False

    def __enter__(self) -> EphemeralFingerprinter:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc_value, traceback
        self.close()

    def derive(self, value: str) -> bytearray:
        """Return a mutable session fingerprint without retaining ``value``."""

        self._ensure_open()
        encoded = bytearray(value.encode("utf-8"))
        message = bytearray(_DOMAIN)
        message.extend(encoded)
        try:
            return bytearray(hmac.digest(self._key, message, hashlib.sha256))
        finally:
            _erase(encoded)
            _erase(message)

    def equal(self, first: bytearray, second: bytearray) -> bool:
        """Compare two session fingerprints in constant time."""

        self._ensure_open()
        return hmac.compare_digest(first, second)

    def close(self) -> None:
        if not self._closed:
            _erase(self._key)
            self._closed = True

    def _ensure_open(self) -> None:
        if self._closed:
            raise RuntimeError("the ephemeral fingerprinter is closed")


def erase_fingerprint(value: bytearray) -> None:
    """Erase a mutable session-fingerprint buffer."""

    _erase(value)


def secret_values_equal(first: str, second: str) -> bool:
    """Compare arbitrary UTF-8 secret values and erase the owned byte buffers."""

    first_bytes = bytearray()
    second_bytes = bytearray()
    try:
        first_bytes.extend(first.encode("utf-8"))
        second_bytes.extend(second.encode("utf-8"))
        return hmac.compare_digest(first_bytes, second_bytes)
    finally:
        _erase(first_bytes)
        _erase(second_bytes)


def new_key_state_salt() -> str:
    """Return a per-operation salt that prevents cross-operation key correlation."""

    return secrets.token_hex(_KEY_STATE_SALT_BYTES)


def derive_key_state_fingerprint(
    value: str,
    *,
    salt: str,
    resource_id: str,
    key_slot: str,
) -> str:
    """Derive a versioned recovery verifier for one supported Azure key slot."""

    if not value or not resource_id or not key_slot:
        raise ValueError("key-state fingerprint inputs must be non-empty")
    if len(salt) != _KEY_STATE_SALT_BYTES * 2 or any(character not in "0123456789abcdef" for character in salt):
        raise ValueError("the key-state salt must be a 256-bit lowercase hexadecimal value")
    salt_bytes = bytes.fromhex(salt)

    encoded_value = bytearray(value.encode("utf-8"))
    digest = hashlib.sha256()
    digest.update(_KEY_STATE_DOMAIN)
    digest.update(salt_bytes)
    try:
        for part in (resource_id.encode("utf-8"), key_slot.encode("utf-8"), encoded_value):
            digest.update(len(part).to_bytes(8, "big"))
            digest.update(part)
        return f"{_KEY_STATE_PREFIX}{digest.hexdigest()}"
    finally:
        _erase(encoded_value)


def equal_key_state_fingerprints(first: str, second: str) -> bool:
    """Compare two durable key-state fingerprints in constant time."""

    return hmac.compare_digest(first, second)


def _erase(value: bytearray) -> None:
    value[:] = b"\x00" * len(value)

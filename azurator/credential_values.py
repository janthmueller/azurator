"""Reviewed representations that can store one supported Azure key value."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlsplit

from azurator.fingerprints import secret_values_equal

STORAGE_RESOURCE_TYPE = "Microsoft.Storage/storageAccounts"

_STORAGE_ACCOUNT_NAME = re.compile(r"^[a-z0-9]{3,24}$")
_ENDPOINT_SUFFIX_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_UNSAFE_URI_CHARACTER = re.compile(r"[\x00-\x20\x7f\\]")
_INVALID_PERCENT_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")
_EXPLICIT_ENDPOINT_FIELDS = frozenset(
    {
        "BlobEndpoint",
        "FileEndpoint",
        "QueueEndpoint",
        "TableEndpoint",
    }
)
_ALLOWED_FIELDS = frozenset(
    {
        "DefaultEndpointsProtocol",
        "AccountName",
        "AccountKey",
        "EndpointSuffix",
        *_EXPLICIT_ENDPOINT_FIELDS,
    }
)


class CredentialValueState(str, Enum):
    """How one stored credential value relates to an expected transition."""

    expected = "expected"
    replacement = "replacement"
    drift = "drift"


@dataclass(frozen=True, slots=True)
class StorageSharedKeyConnectionString:
    """Secret-sensitive fields and replacement span from one reviewed value."""

    account_name: str
    account_key: str = field(repr=False)
    account_key_start: int
    account_key_end: int

    def replace_account_key(self, value: str, replacement_key: str) -> str:
        """Replace exactly the parsed ``AccountKey`` value and preserve all other text."""

        if (
            not replacement_key
            or self.account_key_start < 0
            or self.account_key_end <= self.account_key_start
            or self.account_key_end > len(value)
            or not secret_values_equal(value[self.account_key_start : self.account_key_end], self.account_key)
        ):
            raise ValueError("the Storage connection-string replacement span is invalid")
        return f"{value[: self.account_key_start]}{replacement_key}{value[self.account_key_end :]}"


def parse_storage_shared_key_connection_string(value: str) -> StorageSharedKeyConnectionString | None:
    """Parse the documented Storage Shared Key forms without accepting aliases.

    This is intentionally not a general connection-string parser. It accepts
    canonical Microsoft field names, one optional trailing semicolon, and only
    the fields documented for account-key Storage connection strings.
    """

    if not value or "\x00" in value:
        return None
    segments = value.split(";")
    if segments and segments[-1] == "":
        segments.pop()
    if not segments or any(not segment for segment in segments):
        return None

    fields: dict[str, str] = {}
    account_key_start: int | None = None
    account_key_end: int | None = None
    offset = 0
    for segment in segments:
        separator = segment.find("=")
        if separator <= 0:
            return None
        name = segment[:separator]
        field_value = segment[separator + 1 :]
        if (
            name not in _ALLOWED_FIELDS
            or name in fields
            or not field_value
            or name != name.strip()
            or field_value != field_value.strip()
        ):
            return None
        fields[name] = field_value
        if name == "AccountKey":
            account_key_start = offset + separator + 1
            account_key_end = account_key_start + len(field_value)
        offset += len(segment) + 1

    account_name = fields.get("AccountName")
    account_key = fields.get("AccountKey")
    if (
        account_name is None
        or account_key is None
        or account_key_start is None
        or account_key_end is None
        or _STORAGE_ACCOUNT_NAME.fullmatch(account_name) is None
    ):
        return None

    protocol = fields.get("DefaultEndpointsProtocol")
    explicit_endpoints = _EXPLICIT_ENDPOINT_FIELDS.intersection(fields)
    if protocol not in {"http", "https"}:
        return None

    suffix = fields.get("EndpointSuffix")
    if suffix is not None and not _valid_endpoint_suffix(suffix):
        return None
    if any(not _valid_storage_endpoint(fields[name]) for name in explicit_endpoints):
        return None

    return StorageSharedKeyConnectionString(
        account_name=account_name,
        account_key=account_key,
        account_key_start=account_key_start,
        account_key_end=account_key_end,
    )


def credential_value_matches(
    value: str,
    *,
    resource_type: str,
    resource_name: str,
    expected_key: str,
) -> bool:
    """Compare a raw key or reviewed Storage connection string with one key resource."""

    parsed = parse_storage_shared_key_connection_string(value)
    if parsed is None:
        return secret_values_equal(value, expected_key)
    return (
        resource_type.casefold() == STORAGE_RESOURCE_TYPE.casefold()
        and parsed.account_name.casefold() == resource_name.casefold()
        and secret_values_equal(parsed.account_key, expected_key)
    )


def credential_value_shape_matches_resource(
    value: str,
    *,
    resource_type: str,
    resource_name: str,
) -> bool:
    """Require a recognized structured value to target the mapped resource."""

    parsed = parse_storage_shared_key_connection_string(value)
    return parsed is None or (
        resource_type.casefold() == STORAGE_RESOURCE_TYPE.casefold()
        and parsed.account_name.casefold() == resource_name.casefold()
    )


def transition_credential_value(
    value: str,
    *,
    resource_type: str,
    resource_name: str,
    expected_key: str,
    replacement_key: str,
) -> tuple[CredentialValueState, str | None]:
    """Classify one value and render its exact replacement when applicable."""

    parsed = parse_storage_shared_key_connection_string(value)
    if parsed is None:
        if secret_values_equal(value, replacement_key):
            return CredentialValueState.replacement, None
        if secret_values_equal(value, expected_key):
            return CredentialValueState.expected, replacement_key
        return CredentialValueState.drift, None

    if (
        resource_type.casefold() != STORAGE_RESOURCE_TYPE.casefold()
        or parsed.account_name.casefold() != resource_name.casefold()
    ):
        return CredentialValueState.drift, None
    if secret_values_equal(parsed.account_key, replacement_key):
        return CredentialValueState.replacement, None
    if not secret_values_equal(parsed.account_key, expected_key):
        return CredentialValueState.drift, None
    return CredentialValueState.expected, parsed.replace_account_key(value, replacement_key)


def transition_credential_values(
    values: Mapping[str, str | None],
    selectors: Sequence[str],
    *,
    resource_type: str,
    resource_name: str,
    expected_key: str,
    replacement_key: str,
) -> tuple[CredentialValueState, dict[str, str]]:
    """Classify one atomic alias group and render all required replacements."""

    states: list[CredentialValueState] = []
    replacements: dict[str, str] = {}
    for selector in selectors:
        value = values.get(selector)
        if value is None:
            states.append(CredentialValueState.drift)
            continue
        state, replacement = transition_credential_value(
            value,
            resource_type=resource_type,
            resource_name=resource_name,
            expected_key=expected_key,
            replacement_key=replacement_key,
        )
        states.append(state)
        if replacement is not None:
            replacements[selector] = replacement
    if states and all(state is CredentialValueState.replacement for state in states):
        return CredentialValueState.replacement, replacements
    if states and all(state is CredentialValueState.expected for state in states):
        return CredentialValueState.expected, replacements
    replacements.clear()
    return CredentialValueState.drift, replacements


def credential_values_match(
    values: Mapping[str, str | None],
    selectors: Sequence[str],
    *,
    resource_type: str,
    resource_name: str,
    expected_key: str,
) -> bool:
    """Require every selected raw or structured value to hold one expected key."""

    return bool(selectors) and all(
        values.get(selector) is not None
        and credential_value_matches(
            values[selector] or "",
            resource_type=resource_type,
            resource_name=resource_name,
            expected_key=expected_key,
        )
        for selector in selectors
    )


def replace_credential_value(
    value: str,
    *,
    resource_type: str,
    resource_name: str,
    replacement_key: str,
) -> str:
    """Preserve a reviewed Storage connection string or replace a raw value."""

    parsed = parse_storage_shared_key_connection_string(value)
    if parsed is None:
        return replacement_key
    if (
        resource_type.casefold() != STORAGE_RESOURCE_TYPE.casefold()
        or parsed.account_name.casefold() != resource_name.casefold()
    ):
        raise ValueError("the Storage connection string targets a different key resource")
    return parsed.replace_account_key(value, replacement_key)


def _valid_storage_endpoint(value: str) -> bool:
    if _UNSAFE_URI_CHARACTER.search(value) is not None or _INVALID_PERCENT_ESCAPE.search(value) is not None:
        return False
    try:
        parsed = urlsplit(value)
        valid = (
            parsed.scheme in {"http", "https"}
            and bool(parsed.netloc)
            and parsed.hostname is not None
            and parsed.username is None
            and parsed.password is None
            and not parsed.fragment
        )
        if not valid:
            return False
        parsed.port
        return True
    except (UnicodeError, ValueError):
        return False


def _valid_endpoint_suffix(value: str) -> bool:
    labels = value.split(".")
    return len(value) <= 253 and all(_ENDPOINT_SUFFIX_LABEL.fullmatch(label) is not None for label in labels)

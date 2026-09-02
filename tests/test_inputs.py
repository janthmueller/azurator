"""Tests for strict, streaming raw-secret input parsing."""

from __future__ import annotations

from io import StringIO

import pytest

from azurator.inputs import (
    SecretInputError,
    consume_dotenv,
    dotenv_values_equal,
    render_dotenv_assignment,
    replace_dotenv_assignments,
    replace_dotenv_values,
)


def test_dotenv_values_are_consumed_in_order_without_being_retained() -> None:
    consumed: list[tuple[str, str]] = []
    stream = StringIO(
        """\
# selected key values
export STORAGE_KEY = storage-value
OPENAI_KEY="openai-value"
SINGLE_QUOTED='single-value'
EMPTY=
"""
    )

    result = consume_dotenv(stream, lambda selector, value: consumed.append((selector, value)))

    assert consumed == [
        ("STORAGE_KEY", "storage-value"),
        ("OPENAI_KEY", "openai-value"),
        ("SINGLE_QUOTED", "single-value"),
    ]
    assert result.selectors == ("STORAGE_KEY", "OPENAI_KEY", "SINGLE_QUOTED")
    assert result.skipped_empty_selectors == ("EMPTY",)
    assert "storage-value" not in repr(result)


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        ("raw-secret-without-assignment\n", "not a NAME=VALUE assignment"),
        ("INVALID-NAME=raw-secret\n", "invalid selector name"),
        ("TOKEN='raw-secret\n", "unterminated quoted value"),
        ("TOKEN=raw-secret # comment\n", "inline comment"),
        ("TOKEN=first\nTOKEN=raw-secret\n", "declared more than once"),
        ("TOKEN=raw\x00secret\n", "unsupported NUL"),
    ],
)
def test_dotenv_errors_never_echo_values(payload: str, expected: str) -> None:
    with pytest.raises(SecretInputError) as raised:
        consume_dotenv(StringIO(payload), lambda selector, value: None)

    message = str(raised.value)
    assert expected in message
    assert "raw-secret" not in message
    assert "first" not in message


def test_dotenv_rejects_oversized_lines_without_echoing_them() -> None:
    value = "s" * 70_000

    with pytest.raises(SecretInputError, match="size limit") as raised:
        consume_dotenv(StringIO(f"TOKEN={value}\n"), lambda selector, raw: None)

    assert value not in str(raised.value)


def test_dotenv_replacement_preserves_structure_and_replaces_exact_selectors() -> None:
    content = """\
# application configuration
export FIRST_KEY = old-value
UNRELATED="leave-me"
SECOND_KEY='old-value'
"""

    replaced = replace_dotenv_values(content, ("FIRST_KEY", "SECOND_KEY"), "new-azure-key")

    assert (
        replaced
        == """\
# application configuration
export FIRST_KEY ='new-azure-key'
UNRELATED="leave-me"
SECOND_KEY='new-azure-key'
"""
    )
    assert dotenv_values_equal(replaced, ("FIRST_KEY", "SECOND_KEY"), "new-azure-key")
    assert not dotenv_values_equal(replaced, ("FIRST_KEY", "SECOND_KEY"), "different-key")


def test_dotenv_replacement_preserves_each_original_line_ending() -> None:
    content = "# comment\r\nFIRST_KEY=old\r\nUNRELATED=leave-me\nSECOND_KEY=old\r"

    replaced = replace_dotenv_values(content, ("FIRST_KEY", "SECOND_KEY"), "new-azure-key")

    assert replaced == "# comment\r\nFIRST_KEY='new-azure-key'\r\nUNRELATED=leave-me\nSECOND_KEY='new-azure-key'\r"
    assert dotenv_values_equal(replaced, ("FIRST_KEY", "SECOND_KEY"), "new-azure-key")


def test_dotenv_assignment_replacement_uses_distinct_values_and_preserves_unselected_content() -> None:
    content = "# keep\r\nFIRST=old-one\r\nUNRELATED='leave-me'\nSECOND=old-two\n"

    replaced = replace_dotenv_assignments(
        content,
        {
            "FIRST": "new-one",
            "SECOND": "new-two",
        },
    )

    assert replaced == "# keep\r\nFIRST='new-one'\r\nUNRELATED='leave-me'\nSECOND='new-two'\n"


def test_dotenv_assignment_renderer_uses_the_canonical_file_shape() -> None:
    assert render_dotenv_assignment("AZURE_STORAGE_KEY", "new-azure-key") == ("AZURE_STORAGE_KEY='new-azure-key'")


def test_dotenv_replacement_rejects_missing_selectors_without_exposing_values() -> None:
    existing = "EXISTING=old-secret\n"
    replacement = "replacement-secret"

    with pytest.raises(SecretInputError, match="MISSING") as raised:
        replace_dotenv_values(existing, ("MISSING",), replacement)

    assert "old-secret" not in str(raised.value)
    assert replacement not in str(raised.value)


def test_dotenv_assignment_replacement_rejects_one_missing_selector_without_partial_output() -> None:
    with pytest.raises(SecretInputError, match="SECOND") as raised:
        replace_dotenv_assignments(
            "FIRST=old-secret\n",
            {"FIRST": "first-replacement", "SECOND": "second-replacement"},
        )

    assert "old-secret" not in str(raised.value)
    assert "first-replacement" not in str(raised.value)
    assert "second-replacement" not in str(raised.value)


@pytest.mark.parametrize("value", ("contains'quote", "contains\nnewline", ""))
def test_dotenv_replacement_rejects_unrepresentable_values_without_echoing_them(value: str) -> None:
    with pytest.raises(SecretInputError, match="cannot be represented") as raised:
        replace_dotenv_values("TOKEN=old\n", ("TOKEN",), value)

    if value:
        assert value not in str(raised.value)

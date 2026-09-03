"""Strict streaming parsers for raw key values selected for matching."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from io import StringIO
from typing import TextIO

from azurator.fingerprints import secret_values_equal

_SELECTOR_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_MAX_LINE_LENGTH = 65_536
_MAX_SELECTORS = 10_000
MAX_DOTENV_FILE_BYTES = 1_048_576


class SecretInputError(ValueError):
    """Raw input is malformed; messages must never contain input values."""


@dataclass(frozen=True)
class DotenvReadResult:
    """Secret-free summary of a consumed dotenv stream."""

    selectors: tuple[str, ...]
    skipped_empty_selectors: tuple[str, ...]


SecretSink = Callable[[str, str], None]


@dataclass(frozen=True)
class _ParsedDotenvLine:
    selector: str
    value: str | None = field(repr=False)
    value_start: int


def consume_dotenv(stream: TextIO, consume: SecretSink) -> DotenvReadResult:
    """Parse a strict dotenv subset and immediately pass each non-empty value to ``consume``.

    Values are never accumulated by this module. Comments must occupy their own
    line, interpolation is deliberately unsupported, and matching outer quotes
    are removed without evaluating escapes.
    """

    selectors: list[str] = []
    skipped_empty: list[str] = []
    seen: set[str] = set()

    line_number = 0
    while True:
        line = stream.readline(_MAX_LINE_LENGTH + 1)
        if line == "":
            break
        line_number += 1
        if len(line) > _MAX_LINE_LENGTH:
            raise SecretInputError(f"dotenv line {line_number} exceeds the supported size limit")
        line = line.removesuffix("\n").removesuffix("\r")
        parsed = _parse_dotenv_line(line, line_number)
        line = ""
        if parsed is None:
            continue

        selector = parsed.selector
        value = parsed.value
        parsed = None
        if selector in seen:
            raise SecretInputError(f"dotenv selector {selector!r} is declared more than once")
        if len(seen) >= _MAX_SELECTORS:
            raise SecretInputError("dotenv input contains too many selectors")
        seen.add(selector)

        if value is None:
            skipped_empty.append(selector)
            continue
        selectors.append(selector)
        try:
            consume(selector, value)
        finally:
            value = ""

    return DotenvReadResult(tuple(selectors), tuple(skipped_empty))


def replace_dotenv_values(content: str, selectors: tuple[str, ...], value: str) -> str:
    """Replace exact assignments in the strict dotenv subset without interpreting the document."""

    return replace_dotenv_assignments(content, {selector: value for selector in selectors})


def replace_dotenv_assignments(content: str, replacements: Mapping[str, str]) -> str:
    """Replace exact assignments with selector-specific values in one strict parse."""

    selectors = tuple(replacements)
    selected = _validate_selected_selectors(selectors)
    encoded = {selector: _encode_dotenv_value(replacements[selector]) for selector in selectors}
    output: list[str] = []
    found: set[str] = set()
    seen: set[str] = set()
    stream = StringIO(content, newline="")
    line_number = 0

    while True:
        raw_line = stream.readline(_MAX_LINE_LENGTH + 1)
        if raw_line == "":
            break
        line_number += 1
        if len(raw_line) > _MAX_LINE_LENGTH:
            raise SecretInputError(f"dotenv line {line_number} exceeds the supported size limit")
        if raw_line.endswith("\r\n"):
            newline = "\r\n"
            line = raw_line[:-2]
        elif raw_line.endswith(("\r", "\n")):
            newline = raw_line[-1]
            line = raw_line[:-1]
        else:
            newline = ""
            line = raw_line
        parsed = _parse_dotenv_line(line, line_number)
        if parsed is None:
            output.append(raw_line)
            continue
        if parsed.selector in seen:
            raise SecretInputError(f"dotenv selector {parsed.selector!r} is declared more than once")
        if len(seen) >= _MAX_SELECTORS:
            raise SecretInputError("dotenv input contains too many selectors")
        seen.add(parsed.selector)
        if parsed.selector not in selected:
            output.append(raw_line)
            continue
        found.add(parsed.selector)
        output.append(f"{line[: parsed.value_start]}{encoded[parsed.selector]}{newline}")

    missing = selected - found
    if missing:
        raise SecretInputError(f"managed dotenv selector {sorted(missing)[0]!r} is missing")
    return "".join(output)


def render_dotenv_assignment(selector: str, value: str) -> str:
    """Render one canonical plaintext assignment without logging either input."""

    validate_dotenv_selector(selector)
    return f"{selector}={_encode_dotenv_value(value)}"


def validate_dotenv_selector(selector: str) -> None:
    """Validate one selector without accepting or retaining a secret value."""

    _validate_selected_selectors((selector,))


def validate_dotenv_assignments(content: str, selectors: tuple[str, ...]) -> None:
    """Require every selected assignment in one valid strict-subset document."""

    selected = _validate_selected_selectors(selectors)
    result = consume_dotenv(StringIO(content, newline=""), lambda _selector, _value: None)
    declared = set(result.selectors) | set(result.skipped_empty_selectors)
    missing = selected - declared
    if missing:
        raise SecretInputError(f"managed dotenv selector {sorted(missing)[0]!r} is missing")


def dotenv_selected_values(content: str, selectors: tuple[str, ...]) -> dict[str, str | None]:
    """Return only explicitly selected values from one validated dotenv document."""

    selected = _validate_selected_selectors(selectors)
    values: dict[str, str | None] = {}
    try:
        result = consume_dotenv(
            StringIO(content, newline=""),
            lambda selector, value: values.__setitem__(selector, value) if selector in selected else None,
        )
        for selector in result.skipped_empty_selectors:
            if selector in selected:
                values[selector] = None
        missing = selected - set(values)
        if missing:
            raise SecretInputError(f"managed dotenv selector {sorted(missing)[0]!r} is missing")
        return values
    except BaseException:
        values.clear()
        raise


def dotenv_values_equal(content: str, selectors: tuple[str, ...], expected: str) -> bool:
    """Compare exact dotenv assignments with one expected value without retaining their values."""

    return dotenv_stream_values_equal(StringIO(content, newline=""), selectors, expected)


def dotenv_stream_values_equal(stream: TextIO, selectors: tuple[str, ...], expected: str) -> bool:
    """Compare streamed dotenv assignments with one expected value."""

    selected = _validate_selected_selectors(selectors)
    matched: set[str] = set()

    def compare(selector: str, value: str) -> None:
        if selector in selected and secret_values_equal(value, expected):
            matched.add(selector)

    result = consume_dotenv(stream, compare)
    declared = set(result.selectors) | set(result.skipped_empty_selectors)
    return selected.issubset(declared) and matched == selected


def _parse_dotenv_line(line: str, line_number: int) -> _ParsedDotenvLine | None:
    bom_offset = 1 if line_number == 1 and line.startswith("\ufeff") else 0
    parsed_line = line[bom_offset:]
    stripped = parsed_line.strip()
    if not stripped or stripped.startswith("#"):
        return None

    leading_length = len(parsed_line) - len(parsed_line.lstrip())
    assignment_start = bom_offset + leading_length
    assignment = parsed_line.lstrip()
    if assignment.startswith("export "):
        assignment = assignment[7:]
        export_spacing = len(assignment) - len(assignment.lstrip())
        assignment_start += 7 + export_spacing
        assignment = assignment.lstrip()
    if "=" not in assignment:
        raise SecretInputError(f"dotenv line {line_number} is not a NAME=VALUE assignment")

    equals_index = assignment.index("=")
    raw_selector = assignment[:equals_index]
    selector = raw_selector.strip()
    if not _SELECTOR_PATTERN.fullmatch(selector):
        raise SecretInputError(f"dotenv line {line_number} has an invalid selector name")
    raw_value = assignment[equals_index + 1 :]
    return _ParsedDotenvLine(
        selector=selector,
        value=_parse_value(raw_value, line_number),
        value_start=assignment_start + equals_index + 1,
    )


def _validate_selected_selectors(selectors: tuple[str, ...]) -> set[str]:
    selected = set(selectors)
    if (
        not selectors
        or len(selected) != len(selectors)
        or any(_SELECTOR_PATTERN.fullmatch(selector) is None for selector in selectors)
    ):
        raise SecretInputError("dotenv selectors do not satisfy the supported format")
    return selected


def _encode_dotenv_value(value: str) -> str:
    if not value or any(character in value for character in ("'", "\r", "\n", "\x00")):
        raise SecretInputError("the Azure key cannot be represented by the supported dotenv output format")
    try:
        value.encode("utf-8")
    except UnicodeError:
        raise SecretInputError("the Azure key cannot be represented by the supported dotenv output format") from None
    return f"'{value}'"


def _parse_value(raw_value: str, line_number: int) -> str | None:
    value = raw_value.strip()
    if not value:
        return None
    if "\x00" in value:
        raise SecretInputError(f"dotenv line {line_number} contains an unsupported NUL character")

    quote = value[0]
    if quote in {"'", '"'}:
        if len(value) < 2 or value[-1] != quote:
            raise SecretInputError(f"dotenv line {line_number} has an unterminated quoted value")
        return value[1:-1] or None

    if " #" in value or "\t#" in value:
        raise SecretInputError(f"dotenv line {line_number} uses an inline comment; comments must occupy their own line")
    return value

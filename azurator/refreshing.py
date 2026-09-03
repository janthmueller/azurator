"""Strict one-way refresh of existing plaintext or SOPS dotenv bindings."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from io import StringIO
from pathlib import Path

from azurator.credential_values import (
    credential_value_matches,
    credential_value_shape_matches_resource,
    replace_credential_value,
)
from azurator.files import (
    MAX_OPERATION_ARTIFACT_BYTES,
    UnsafeInputPathError,
    UnsafeOutputPathError,
    commit_regular_copy,
    read_managed_plaintext,
    replace_managed_plaintext,
    temporary_regular_copy,
)
from azurator.fingerprints import EphemeralFingerprinter, erase_fingerprint
from azurator.inputs import (
    MAX_DOTENV_FILE_BYTES,
    SecretInputError,
    consume_dotenv,
    dotenv_selected_values,
    replace_dotenv_assignments,
    validate_dotenv_selector,
)
from azurator.models import DotenvKeyAssignment
from azurator.sops import SopsCommand, SopsError


class RefreshError(RuntimeError):
    """A refresh target or update cannot satisfy the reviewed file contract."""


@dataclass(frozen=True, slots=True)
class DotenvRefreshResult:
    """Secret-free result of refreshing one existing dotenv document."""

    assignment_count: int
    changed_assignment_count: int

    @property
    def already_current_count(self) -> int:
        return self.assignment_count - self.changed_assignment_count


class PlaintextDotenvRefreshService:
    """Atomically replace mapped values in one existing plaintext dotenv file."""

    def validate_target(self, path: Path, selectors: Sequence[str]) -> None:
        """Require every mapped selector before Azure key retrieval begins."""

        selected = _validated_selectors(selectors)
        content = ""
        values: dict[str, str | None] = {}
        try:
            content = read_managed_plaintext(path, max_bytes=MAX_DOTENV_FILE_BYTES)
            values = dotenv_selected_values(content, selected)
        except RefreshError:
            raise
        except SecretInputError as error:
            raise RefreshError(str(error)) from None
        except (OSError, UnicodeError, UnsafeInputPathError):
            raise RefreshError("the plaintext dotenv file is missing, unsafe, too large, or invalid") from None
        finally:
            content = ""
            values.clear()

    def refresh(
        self,
        path: Path,
        assignments: Sequence[DotenvKeyAssignment],
        current_dotenv: str,
    ) -> DotenvRefreshResult:
        """Replace all and only mapped assignments if the source remains unchanged."""

        selected, assignments_by_selector = _validated_assignments(assignments)
        desired: dict[str, str] = {}
        observed: dict[str, str | None] = {}
        replacements: dict[str, str] = {}
        content = ""
        replacement = ""
        try:
            desired = _desired_values(current_dotenv, selected)
            content = read_managed_plaintext(path, max_bytes=MAX_DOTENV_FILE_BYTES)
            observed = dotenv_selected_values(content, selected)
            replacements = _refresh_replacements(observed, desired, assignments_by_selector)
            if not replacements:
                return DotenvRefreshResult(len(selected), 0)

            replacement = replace_dotenv_assignments(
                content,
                replacements,
            )
            if len(replacement.encode("utf-8")) > MAX_DOTENV_FILE_BYTES:
                raise RefreshError("the refreshed dotenv file would exceed the supported 1 MiB limit")
            verified = dotenv_selected_values(replacement, selected)
            try:
                if not _mapped_values_current(verified, desired, assignments_by_selector):
                    raise RefreshError("the refreshed dotenv document did not retain every requested value")
            finally:
                verified.clear()

            replace_managed_plaintext(
                path,
                content,
                replacement,
                max_bytes=MAX_DOTENV_FILE_BYTES,
            )
            return DotenvRefreshResult(len(selected), len(replacements))
        except RefreshError:
            raise
        except SecretInputError as error:
            raise RefreshError(str(error)) from None
        except (OSError, UnicodeError, UnsafeInputPathError, UnsafeOutputPathError):
            raise RefreshError("the plaintext dotenv file changed or could not be refreshed safely") from None
        finally:
            current_dotenv = ""
            content = ""
            replacement = ""
            desired.clear()
            observed.clear()
            replacements.clear()

    def validate_mappings(self, path: Path, assignments: Sequence[DotenvKeyAssignment]) -> None:
        """Validate structured target values against mapped resources before key retrieval."""

        selected, assignments_by_selector = _validated_assignments(assignments)
        content = ""
        values: dict[str, str | None] = {}
        try:
            content = read_managed_plaintext(path, max_bytes=MAX_DOTENV_FILE_BYTES)
            values = dotenv_selected_values(content, selected)
            _validate_existing_mappings(values, assignments_by_selector)
        except RefreshError:
            raise
        except SecretInputError as error:
            raise RefreshError(str(error)) from None
        except (OSError, UnicodeError, UnsafeInputPathError):
            raise RefreshError("the plaintext dotenv file changed before refresh") from None
        finally:
            content = ""
            values.clear()


class SopsDotenvRefreshService:
    """Atomically refresh mapped SOPS dotenv values without plaintext disk I/O."""

    def __init__(self, command: SopsCommand) -> None:
        self._command = command

    def validate_target(self, path: Path, selectors: Sequence[str]) -> None:
        """Decrypt one private snapshot and require every mapped selector."""

        selected = _validated_selectors(selectors)
        content = ""
        values: dict[str, str | None] = {}
        try:
            with temporary_regular_copy(path, max_bytes=MAX_OPERATION_ARTIFACT_BYTES) as (temporary, _snapshot):
                content = self._command.decrypt_dotenv(temporary)
                values = dotenv_selected_values(content, selected)
        except RefreshError:
            raise
        except SecretInputError as error:
            raise RefreshError(str(error)) from None
        except (SopsError, OSError, UnicodeError, UnsafeInputPathError, UnsafeOutputPathError):
            raise RefreshError("the SOPS dotenv file is missing, unsafe, invalid, or could not be decrypted") from None
        finally:
            content = ""
            values.clear()

    def refresh(
        self,
        path: Path,
        assignments: Sequence[DotenvKeyAssignment],
        current_dotenv: str,
    ) -> DotenvRefreshResult:
        """Update one encrypted temporary, verify it in memory, and commit once."""

        selected, assignments_by_selector = _validated_assignments(assignments)
        desired: dict[str, str] = {}
        before_fingerprints: dict[str, bytearray | None] = {}
        after_fingerprints: dict[str, bytearray | None] = {}
        observed: dict[str, str | None] = {}
        verified: dict[str, str | None] = {}
        replacements: dict[str, str] = {}
        before = ""
        after = ""
        try:
            desired = _desired_values(current_dotenv, selected)
            with temporary_regular_copy(path, max_bytes=MAX_OPERATION_ARTIFACT_BYTES) as (temporary, snapshot):
                before = self._command.decrypt_dotenv(temporary)
                with EphemeralFingerprinter() as fingerprinter:
                    before_fingerprints = _dotenv_fingerprints(before, fingerprinter)
                    _require_present_selectors(before_fingerprints, selected)
                    observed = dotenv_selected_values(before, selected)
                    replacements = _refresh_replacements(observed, desired, assignments_by_selector)
                    before = ""
                    if not replacements:
                        return DotenvRefreshResult(len(selected), 0)

                    for selector in selected:
                        if selector in replacements:
                            self._command.set_dotenv_value(temporary, selector, replacements[selector])

                    after = self._command.decrypt_dotenv(temporary)
                    after_fingerprints = _dotenv_fingerprints(after, fingerprinter)
                    verified = dotenv_selected_values(after, selected)
                    after = ""
                    if set(before_fingerprints) != set(after_fingerprints):
                        raise RefreshError("SOPS changed the dotenv assignment set; the source file was not replaced")
                    if not _mapped_values_current(verified, desired, assignments_by_selector):
                        raise RefreshError(
                            "SOPS did not retain every refreshed value; the source file was not replaced"
                        )
                    if any(
                        not _fingerprints_equal(
                            before_fingerprints[selector],
                            after_fingerprints[selector],
                            fingerprinter,
                        )
                        for selector in set(before_fingerprints) - set(selected)
                    ):
                        raise RefreshError("SOPS changed an unmapped dotenv value; the source file was not replaced")

                commit_regular_copy(snapshot, temporary, max_bytes=MAX_OPERATION_ARTIFACT_BYTES)
                return DotenvRefreshResult(len(selected), len(replacements))
        except RefreshError:
            raise
        except SecretInputError as error:
            raise RefreshError(str(error)) from None
        except (SopsError, OSError, UnicodeError, UnsafeInputPathError, UnsafeOutputPathError):
            raise RefreshError("the SOPS dotenv file changed or could not be refreshed safely") from None
        finally:
            current_dotenv = ""
            before = ""
            after = ""
            desired.clear()
            observed.clear()
            verified.clear()
            replacements.clear()
            _erase_dotenv_fingerprints(before_fingerprints)
            _erase_dotenv_fingerprints(after_fingerprints)

    def validate_mappings(self, path: Path, assignments: Sequence[DotenvKeyAssignment]) -> None:
        """Validate decrypted structured values against mapped resources before key retrieval."""

        selected, assignments_by_selector = _validated_assignments(assignments)
        content = ""
        values: dict[str, str | None] = {}
        try:
            with temporary_regular_copy(path, max_bytes=MAX_OPERATION_ARTIFACT_BYTES) as (temporary, _snapshot):
                content = self._command.decrypt_dotenv(temporary)
                values = dotenv_selected_values(content, selected)
                _validate_existing_mappings(values, assignments_by_selector)
        except RefreshError:
            raise
        except SecretInputError as error:
            raise RefreshError(str(error)) from None
        except (SopsError, OSError, UnicodeError, UnsafeInputPathError, UnsafeOutputPathError):
            raise RefreshError("the SOPS dotenv file changed before refresh") from None
        finally:
            content = ""
            values.clear()


def _validated_selectors(selectors: Sequence[str]) -> tuple[str, ...]:
    selected = tuple(selectors)
    if not selected or len(set(selected)) != len(selected):
        raise RefreshError("refresh requires one or more unique dotenv selectors")
    try:
        for selector in selected:
            validate_dotenv_selector(selector)
    except SecretInputError:
        raise RefreshError("a refresh selector violates the supported dotenv contract") from None
    return selected


def _validated_assignments(
    assignments: Sequence[DotenvKeyAssignment],
) -> tuple[tuple[str, ...], dict[str, DotenvKeyAssignment]]:
    selected = _validated_selectors(tuple(assignment.selector for assignment in assignments))
    assignments_by_selector = {assignment.selector: assignment for assignment in assignments}
    if len(assignments_by_selector) != len(selected):
        raise RefreshError("refresh requires one resource mapping for every unique dotenv selector")
    return selected, assignments_by_selector


def _desired_values(content: str, selectors: tuple[str, ...]) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        result = consume_dotenv(
            StringIO(content, newline=""),
            lambda selector, value: values.__setitem__(selector, value),
        )
    except BaseException:
        values.clear()
        raise
    if result.skipped_empty_selectors or set(values) != set(selectors):
        values.clear()
        raise RefreshError("current Azure key material did not match the requested refresh assignments")
    return values


def _require_present_selectors(values: Mapping[str, object], selectors: tuple[str, ...]) -> None:
    missing = set(selectors) - set(values)
    if missing:
        raise RefreshError(f"mapped dotenv selector {sorted(missing)[0]!r} is missing from the target file")


def _refresh_replacements(
    observed: Mapping[str, str | None],
    desired: Mapping[str, str],
    assignments: Mapping[str, DotenvKeyAssignment],
) -> dict[str, str]:
    replacements: dict[str, str] = {}
    try:
        for selector, assignment in assignments.items():
            value = observed[selector]
            desired_key = desired[selector]
            resource = assignment.resource
            if value is not None and credential_value_matches(
                value,
                resource_type=resource.resource_type,
                resource_name=resource.name,
                expected_key=desired_key,
            ):
                continue
            try:
                replacements[selector] = replace_credential_value(
                    value or "",
                    resource_type=resource.resource_type,
                    resource_name=resource.name,
                    replacement_key=desired_key,
                )
            except ValueError:
                raise RefreshError(
                    "a mapped Storage connection string targets a different Azure key resource"
                ) from None
        return replacements
    except BaseException:
        replacements.clear()
        raise


def _validate_existing_mappings(
    observed: Mapping[str, str | None],
    assignments: Mapping[str, DotenvKeyAssignment],
) -> None:
    for selector, assignment in assignments.items():
        value = observed[selector]
        resource = assignment.resource
        if value is not None and not credential_value_shape_matches_resource(
            value,
            resource_type=resource.resource_type,
            resource_name=resource.name,
        ):
            raise RefreshError("a mapped Storage connection string targets a different Azure key resource")


def _mapped_values_current(
    observed: Mapping[str, str | None],
    desired: Mapping[str, str],
    assignments: Mapping[str, DotenvKeyAssignment],
) -> bool:
    return all(
        observed[selector] is not None
        and credential_value_matches(
            observed[selector] or "",
            resource_type=assignment.resource.resource_type,
            resource_name=assignment.resource.name,
            expected_key=desired[selector],
        )
        for selector, assignment in assignments.items()
    )


def _dotenv_fingerprints(
    content: str,
    fingerprinter: EphemeralFingerprinter,
) -> dict[str, bytearray | None]:
    fingerprints: dict[str, bytearray | None] = {}
    try:
        result = consume_dotenv(
            StringIO(content, newline=""),
            lambda selector, value: fingerprints.__setitem__(selector, fingerprinter.derive(value)),
        )
        for selector in result.skipped_empty_selectors:
            fingerprints[selector] = None
        return fingerprints
    except BaseException:
        _erase_dotenv_fingerprints(fingerprints)
        raise


def _fingerprints_equal(
    first: bytearray | None,
    second: bytearray | None,
    fingerprinter: EphemeralFingerprinter,
) -> bool:
    if first is None or second is None:
        return first is second
    return fingerprinter.equal(first, second)


def _erase_dotenv_fingerprints(fingerprints: dict[str, bytearray | None]) -> None:
    for fingerprint in fingerprints.values():
        if fingerprint is not None:
            erase_fingerprint(fingerprint)
    fingerprints.clear()

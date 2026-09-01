"""Synchronize Azurator's release version into its editable uv lock entry."""

from __future__ import annotations

import os
import re
import sys
import tempfile
from pathlib import Path

import tomllib
from packaging.version import InvalidVersion, Version

_VERSION_LINE = re.compile(r'version = "[^"]+"(?P<newline>\r?\n)?\Z')


def synchronize_version(repository: Path, requested_version: str) -> None:
    """Update and validate the one editable Azurator package in uv.lock."""

    try:
        normalized = str(Version(requested_version))
    except InvalidVersion as error:
        raise ValueError(f"invalid release version: {requested_version!r}") from error

    project = tomllib.loads((repository / "pyproject.toml").read_text(encoding="utf-8"))
    configured = str(project["project"]["version"])
    if Version(configured) != Version(normalized):
        raise ValueError(f"release version {normalized!r} does not match pyproject.toml version {configured!r}")

    lock_path = repository / "uv.lock"
    lines = lock_path.read_text(encoding="utf-8").splitlines(keepends=True)
    matching_blocks = _editable_project_blocks(lines)
    if len(matching_blocks) != 1:
        raise ValueError(f"expected one editable azurator package in uv.lock, found {len(matching_blocks)}")
    start, end = matching_blocks[0]
    version_indexes = tuple(index for index in range(start, end) if _VERSION_LINE.fullmatch(lines[index]) is not None)
    if len(version_indexes) != 1:
        raise ValueError("editable azurator package must contain exactly one version in uv.lock")

    index = version_indexes[0]
    newline = "\r\n" if lines[index].endswith("\r\n") else "\n"
    replacement = f'version = "{normalized}"{newline}'
    if lines[index] != replacement:
        lines[index] = replacement
        _atomic_write(lock_path, "".join(lines))

    locked = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    packages = tuple(
        package
        for package in locked.get("package", ())
        if package.get("name") == "azurator" and package.get("source") == {"editable": "."}
    )
    if len(packages) != 1 or Version(str(packages[0].get("version"))) != Version(normalized):
        raise RuntimeError("uv.lock version synchronization did not validate")


def _editable_project_blocks(lines: list[str]) -> tuple[tuple[int, int], ...]:
    starts = [index for index, line in enumerate(lines) if line.rstrip("\r\n") == "[[package]]"]
    blocks: list[tuple[int, int]] = []
    for ordinal, start in enumerate(starts):
        end = starts[ordinal + 1] if ordinal + 1 < len(starts) else len(lines)
        content = {line.rstrip("\r\n") for line in lines[start:end]}
        if 'name = "azurator"' in content and 'source = { editable = "." }' in content:
            blocks.append((start, end))
    return tuple(blocks)


def _atomic_write(path: Path, content: str) -> None:
    mode = path.stat().st_mode
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 1:
        raise SystemExit("usage: sync_lock_version.py VERSION")
    synchronize_version(Path(__file__).resolve().parents[2], arguments[0])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

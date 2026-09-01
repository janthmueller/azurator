"""Validate the active internal knowledge bundle without checking external URLs."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote

_MARKDOWN_LINK = re.compile(r"(?<!!)\[[^\]\n]*\]\((?P<target><[^>\n]+>|[^)\s]+)")
_TYPE_FIELD = re.compile(r"^type:\s*(?P<value>.+?)\s*$")


def _active_knowledge_files(repository: Path) -> tuple[Path, ...]:
    knowledge = repository / "knowledge"
    return tuple(
        sorted(
            path
            for path in knowledge.rglob("*")
            if path.suffix in {".md", ".mdx"} and "archive" not in path.relative_to(knowledge).parts
        )
    )


def _frontmatter_errors(path: Path, content: str) -> tuple[str, ...]:
    if path.name == "index.md":
        return ()
    lines = content.splitlines()
    if not lines or lines[0] != "---":
        return (f"{path}: missing OKF frontmatter",)
    try:
        closing = lines.index("---", 1)
    except ValueError:
        return (f"{path}: unterminated OKF frontmatter",)
    type_values = tuple(
        match.group("value").strip("\"' ")
        for line in lines[1:closing]
        if (match := _TYPE_FIELD.fullmatch(line)) is not None
    )
    if len(type_values) != 1 or not type_values[0]:
        return (f"{path}: frontmatter must contain exactly one non-empty type",)
    return ()


def _local_link_errors(repository: Path, path: Path, content: str) -> tuple[str, ...]:
    errors: list[str] = []
    for match in _MARKDOWN_LINK.finditer(content):
        raw_target = match.group("target")
        target = raw_target[1:-1] if raw_target.startswith("<") else raw_target
        if target.startswith("#") or "://" in target or target.startswith("mailto:"):
            continue
        local_target = unquote(target.split("#", 1)[0].split("?", 1)[0])
        if not local_target:
            continue
        resolved = (path.parent / local_target).resolve()
        if not resolved.is_relative_to(repository):
            errors.append(f"{path}: local link escapes the repository: {target}")
        elif not resolved.exists():
            errors.append(f"{path}: missing local link target: {target}")
    return tuple(errors)


def validate(repository: Path) -> tuple[str, ...]:
    """Return every active knowledge-frontmatter or local-link error."""

    repository = repository.resolve()
    root_index = repository / "knowledge" / "index.md"
    root_content = root_index.read_text(encoding="utf-8")
    errors: list[str] = []
    if 'okf_version: "0.2"' not in root_content.split("---", 2)[1]:
        errors.append(f'{root_index}: expected okf_version: "0.2"')

    knowledge_files = _active_knowledge_files(repository)
    link_sources = (
        repository / "AGENTS.md",
        repository / "CONTRIBUTING.md",
        repository / "README.md",
        *knowledge_files,
    )
    for path in knowledge_files:
        content = path.read_text(encoding="utf-8")
        errors.extend(_frontmatter_errors(path, content))
    for path in link_sources:
        errors.extend(_local_link_errors(repository, path, path.read_text(encoding="utf-8")))
    return tuple(errors)


def main() -> int:
    repository = Path(__file__).resolve().parents[2]
    errors = validate(repository)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("Active knowledge frontmatter and local links are valid.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

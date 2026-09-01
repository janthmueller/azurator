"""Opaque-on-disk SOPS command fake shared by encrypted-binding tests."""

from __future__ import annotations

import base64
from collections.abc import Callable
from pathlib import Path

from azurator.inputs import replace_dotenv_values

_PREFIX = b"fake-sops-v1\x00"


class FakeSopsCommand:
    def __init__(self) -> None:
        self.set_calls: list[str] = []
        self.change_unselected = False
        self.on_set: Callable[[], None] | None = None

    def decrypt_dotenv(self, path: Path) -> str:
        payload = path.read_bytes()
        if not payload.startswith(_PREFIX):
            raise RuntimeError("invalid fake ciphertext")
        return base64.b64decode(payload.removeprefix(_PREFIX)).decode("utf-8")

    def set_dotenv_value(self, path: Path, selector: str, value: str) -> None:
        content = self.decrypt_dotenv(path)
        replacement = replace_dotenv_values(content, (selector,), value)
        if self.change_unselected:
            replacement = replace_dotenv_values(replacement, ("UNRELATED",), "changed-unexpectedly")
        write_fake_sops_file(path, replacement, preserve_mode=True)
        self.set_calls.append(selector)
        if self.on_set is not None:
            self.on_set()


def write_fake_sops_file(path: Path, content: str, *, preserve_mode: bool = False) -> None:
    mode = path.stat().st_mode & 0o777 if preserve_mode and path.exists() else 0o644
    path.write_bytes(_PREFIX + base64.b64encode(content.encode("utf-8")))
    path.chmod(mode)

"""Tests for private operational-metadata writes."""

from __future__ import annotations

import os
import stat
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest

import azurator.files as files_module
from azurator.files import (
    UnsafeInputPathError,
    UnsafeOutputPathError,
    create_private_bytes,
    create_private_text,
    ensure_private_directory,
    managed_plaintext_permissions_are_broad,
    open_private_text,
    read_managed_plaintext,
    read_private_text,
    remove_empty_private_directory,
    remove_private_text,
    replace_managed_plaintext,
    write_private_text,
)


def test_write_private_text_is_atomic_and_private(tmp_path: Path) -> None:
    destination = tmp_path / "nested" / "inventory.json"

    write_private_text(destination, "first\n")
    write_private_text(destination, "second\n")

    assert destination.read_text(encoding="utf-8") == "second\n"
    if os.name != "nt":
        assert destination.stat().st_mode & 0o777 == 0o600
    assert list(destination.parent.glob(f".{destination.name}.*")) == []


def test_write_private_text_syncs_file_and_parent_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if os.name == "nt":
        pytest.skip("Windows does not expose directory fsync through this contract")
    synced_types: list[str] = []
    real_fsync = files_module.os.fsync

    def record_fsync(descriptor: int) -> None:
        mode = os.fstat(descriptor).st_mode
        synced_types.append("directory" if stat.S_ISDIR(mode) else "file")
        real_fsync(descriptor)

    monkeypatch.setattr(files_module.os, "fsync", record_fsync)

    write_private_text(tmp_path / "nested" / "plan.json", "payload\n")

    assert synced_types == ["file", "directory"]


def test_create_private_text_is_private_complete_and_exclusive(tmp_path: Path) -> None:
    destination = tmp_path / "nested" / "operation.json"

    create_private_text(destination, "complete\n")

    assert destination.read_text(encoding="utf-8") == "complete\n"
    if os.name != "nt":
        assert destination.stat().st_mode & 0o777 == 0o600
    assert list(destination.parent.glob(f".{destination.name}.*")) == []
    with pytest.raises(FileExistsError):
        create_private_text(destination, "replacement\n")
    assert destination.read_text(encoding="utf-8") == "complete\n"


def test_create_private_text_allows_only_one_concurrent_creator(tmp_path: Path) -> None:
    destination = tmp_path / "operation.json"
    contenders = 8
    barrier = Barrier(contenders)

    def attempt(index: int) -> tuple[str, str]:
        content = f"operation-{index}\n"
        barrier.wait()
        try:
            create_private_text(destination, content)
        except FileExistsError:
            return "existing", content
        return "created", content

    with ThreadPoolExecutor(max_workers=contenders) as executor:
        outcomes = tuple(executor.map(attempt, range(contenders)))

    created = [content for status, content in outcomes if status == "created"]
    assert len(created) == 1
    assert destination.read_text(encoding="utf-8") == created[0]
    assert list(tmp_path.glob(f".{destination.name}.*")) == []


def test_create_private_bytes_is_private_complete_and_exclusive(tmp_path: Path) -> None:
    destination = tmp_path / "nested" / "secrets.enc.env"
    ciphertext = bytearray(b"synthetic-ciphertext\x00\xff")

    create_private_bytes(destination, ciphertext)

    assert destination.read_bytes() == ciphertext
    if os.name != "nt":
        assert destination.stat().st_mode & 0o777 == 0o600
    assert list(destination.parent.glob(f".{destination.name}.*")) == []
    with pytest.raises(FileExistsError):
        create_private_bytes(destination, b"replacement")
    assert destination.read_bytes() == ciphertext


def test_ensure_private_directory_creates_hardens_and_rejects_unsafe_targets(
    tmp_path: Path,
) -> None:
    target = tmp_path / "state" / "operations"

    assert ensure_private_directory(target) == target
    if os.name != "nt":
        assert target.stat().st_mode & 0o777 == 0o700
        target.chmod(0o755)
        ensure_private_directory(target)
        assert target.stat().st_mode & 0o777 == 0o700

    occupied = tmp_path / "occupied"
    occupied.write_text("not a directory", encoding="utf-8")
    with pytest.raises(UnsafeOutputPathError):
        ensure_private_directory(occupied)

    link = tmp_path / "directory-link"
    link.symlink_to(target, target_is_directory=True)
    with pytest.raises(UnsafeOutputPathError):
        ensure_private_directory(link)


def test_ensure_private_directory_syncs_every_new_parent_entry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if os.name == "nt":
        pytest.skip("Windows does not expose directory fsync through this contract")
    synced: list[Path] = []
    target = tmp_path / "state" / "azurator" / "operations"
    monkeypatch.setattr(files_module, "_fsync_parent_directory", synced.append)

    ensure_private_directory(target)

    assert synced == [
        tmp_path,
        tmp_path / "state",
        tmp_path / "state" / "azurator",
    ]


def test_remove_private_text_removes_only_private_regular_files(tmp_path: Path) -> None:
    private = tmp_path / "operation.json"
    private.write_text("completed", encoding="utf-8")
    private.chmod(0o600)

    remove_private_text(private)

    assert not private.exists()

    target = tmp_path / "target.json"
    target.write_text("keep", encoding="utf-8")
    target.chmod(0o600)
    link = tmp_path / "operation-link.json"
    link.symlink_to(target)
    with pytest.raises(UnsafeOutputPathError):
        remove_private_text(link)
    assert target.read_text(encoding="utf-8") == "keep"

    if os.name != "nt":
        public = tmp_path / "public.json"
        public.write_text("keep", encoding="utf-8")
        public.chmod(0o644)
        with pytest.raises(UnsafeOutputPathError):
            remove_private_text(public)
        assert public.exists()


def test_remove_empty_private_directory_rejects_nonempty_and_unsafe_targets(
    tmp_path: Path,
) -> None:
    empty = tmp_path / "empty"
    empty.mkdir(mode=0o700)

    remove_empty_private_directory(empty)

    assert not empty.exists()

    nonempty = tmp_path / "nonempty"
    nonempty.mkdir(mode=0o700)
    (nonempty / "operation.json").write_text("keep", encoding="utf-8")
    with pytest.raises(OSError):
        remove_empty_private_directory(nonempty)
    assert nonempty.exists()

    target = tmp_path / "target-directory"
    target.mkdir(mode=0o700)
    link = tmp_path / "directory-link-for-removal"
    link.symlink_to(target, target_is_directory=True)
    with pytest.raises(UnsafeOutputPathError):
        remove_empty_private_directory(link)
    assert target.exists()


def test_write_private_text_refuses_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_text("unchanged", encoding="utf-8")
    link = tmp_path / "link"
    link.symlink_to(target)

    with pytest.raises(UnsafeOutputPathError):
        write_private_text(link, "replacement")

    assert target.read_text(encoding="utf-8") == "unchanged"


def test_write_private_text_refuses_directory(tmp_path: Path) -> None:
    with pytest.raises(UnsafeOutputPathError):
        write_private_text(tmp_path, "replacement")


def test_read_private_text_reads_a_private_regular_file(tmp_path: Path) -> None:
    source = tmp_path / "plan.json"
    source.write_bytes(b'{"schema_version":"1"}\n')
    source.chmod(0o600)

    assert read_private_text(source) == '{"schema_version":"1"}\n'


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits are unavailable on Windows")
@pytest.mark.parametrize(
    ("mode", "expected"),
    ((0o600, False), (0o640, True), (0o620, True), (0o611, False)),
)
def test_managed_plaintext_reports_only_broad_read_or_write_bits(
    tmp_path: Path,
    mode: int,
    expected: bool,
) -> None:
    source = tmp_path / "secrets.env"
    source.write_text("TOKEN=secret\n", encoding="utf-8")
    source.chmod(mode)

    assert managed_plaintext_permissions_are_broad(source) is expected


def test_managed_plaintext_replacement_preserves_existing_posix_metadata(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("Windows does not expose the reviewed POSIX metadata contract")
    source = tmp_path / "secrets.env"
    original = "TOKEN=old-secret\nUNRELATED=keep\n"
    replacement = "TOKEN=new-secret\nUNRELATED=keep\n"
    source.write_text(original, encoding="utf-8")
    source.chmod(0o664)
    before = source.stat()

    assert read_managed_plaintext(source) == original
    replace_managed_plaintext(source, original, replacement)

    after = source.stat()
    assert source.read_text(encoding="utf-8") == replacement
    assert stat.S_IMODE(after.st_mode) == 0o664
    assert (after.st_uid, after.st_gid) == (before.st_uid, before.st_gid)
    assert list(tmp_path.glob(".secrets.env.azurator.*")) == []


def test_managed_plaintext_replacement_refuses_concurrent_content_drift(tmp_path: Path) -> None:
    source = tmp_path / "secrets.env"
    current = "TOKEN=current-secret\n"
    source.write_text(current, encoding="utf-8")
    if os.name != "nt":
        source.chmod(0o644)

    with pytest.raises(UnsafeOutputPathError):
        replace_managed_plaintext(source, "TOKEN=stale-secret\n", "TOKEN=replacement-secret\n")

    assert source.read_text(encoding="utf-8") == current
    assert list(tmp_path.glob(".secrets.env.azurator.*")) == []


def test_read_private_text_preserves_crlf_bytes(tmp_path: Path) -> None:
    source = tmp_path / "secrets.env"
    source.write_bytes(b"# comment\r\nTOKEN=value\r\n")
    source.chmod(0o600)

    assert read_private_text(source) == "# comment\r\nTOKEN=value\r\n"


def test_read_private_text_refuses_symlink_and_public_permissions(tmp_path: Path) -> None:
    source = tmp_path / "plan.json"
    source.write_text("sensitive metadata", encoding="utf-8")
    source.chmod(0o600)
    link = tmp_path / "plan-link.json"
    link.symlink_to(source)

    with pytest.raises(UnsafeInputPathError):
        read_private_text(link)

    if os.name != "nt":
        source.chmod(0o644)
        with pytest.raises(UnsafeInputPathError):
            read_private_text(source)


def test_read_private_text_enforces_size_limit(tmp_path: Path) -> None:
    source = tmp_path / "large-plan.json"
    source.write_text("abcd", encoding="utf-8")
    source.chmod(0o600)

    with pytest.raises(UnsafeInputPathError):
        read_private_text(source, max_bytes=3)


def test_open_private_text_enforces_size_limit_if_file_grows_after_open(tmp_path: Path) -> None:
    source = tmp_path / "growing.env"
    original = "TOKEN=x\n"
    source.write_bytes(original.encode("utf-8"))
    source.chmod(0o600)

    with open_private_text(source, max_bytes=len(original.encode("utf-8"))) as stream:
        assert stream.readline() == original
        with source.open("a", encoding="utf-8") as destination:
            destination.write("EXTRA=must-not-render\n")

        with pytest.raises(UnsafeInputPathError) as caught:
            stream.readline()

    assert "must-not-render" not in str(caught.value)

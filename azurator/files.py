"""Restricted, atomic writes for sensitive operational metadata."""

from __future__ import annotations

import os
import stat
import tempfile
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from hashlib import sha256
from hmac import compare_digest
from io import BufferedReader, RawIOBase, TextIOWrapper
from pathlib import Path
from typing import Any, TextIO

MAX_OPERATION_ARTIFACT_BYTES = 8 * 1024 * 1024


class UnsafeOutputPathError(ValueError):
    """Raised when an output target is not a regular non-symlink path."""


class UnsafeInputPathError(ValueError):
    """Raised when sensitive operational metadata cannot be read safely."""


class PrivateFileExistsError(FileExistsError):
    """Raised when an exclusive private-file destination already exists."""


@dataclass(frozen=True)
class RegularFileSnapshot:
    """Identity and ciphertext digest bound to one managed regular file."""

    path: Path
    digest: str
    device: int
    inode: int
    size: int
    modified_ns: int
    mode: int
    owner: int
    group: int


def resolve_parent_path(path: Path) -> Path:
    """Resolve every parent component while preserving the final path component."""

    absolute = Path(os.path.abspath(path.expanduser()))
    return absolute.parent.resolve(strict=True) / absolute.name


class _BoundedRawReader(RawIOBase):
    """Expose at most one configured number of bytes from a binary stream."""

    def __init__(self, stream: RawIOBase, *, max_bytes: int, source: Path) -> None:
        super().__init__()
        self._stream = stream
        self._remaining = max_bytes
        self._max_bytes = max_bytes
        self._source = source

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any, /) -> int | None:
        view = memoryview(buffer).cast("B")
        readable = min(len(view), self._remaining + 1)
        count = self._stream.readinto(view[:readable])
        if count is None:
            return None
        if count > self._remaining:
            raise UnsafeInputPathError(f"input exceeds the {self._max_bytes}-byte safety limit: {self._source}")
        self._remaining -= count
        return count

    def close(self) -> None:
        try:
            self._stream.close()
        finally:
            super().close()


def _prepare_parent(destination: Path) -> Path:
    parent = destination.parent
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    return parent


def ensure_private_directory(path: Path) -> Path:
    """Create or harden one application-owned directory and persist new entries."""

    target = path.expanduser()
    missing_directories: list[Path] = []
    current = target
    while True:
        try:
            current.lstat()
        except FileNotFoundError:
            missing_directories.append(current)
            parent = current.parent
            if parent == current:
                break
            current = parent
            continue
        break
    try:
        target.mkdir(mode=0o700, parents=True, exist_ok=True)
    except FileExistsError:
        # Inspect the final component below so an occupied path is reported
        # through this helper's explicit unsafe-path contract.
        pass
    metadata = target.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise UnsafeOutputPathError(f"refusing non-directory or symlink private path: {target}")
    if os.name != "nt" and stat.S_IMODE(metadata.st_mode) != 0o700:
        os.chmod(target, 0o700)
    for directory in reversed(missing_directories):
        _fsync_parent_directory(directory.parent)
    return target


def _fsync_parent_directory(parent: Path) -> None:
    """Persist a directory-entry change on platforms with directory fsync."""

    if os.name == "nt":
        return
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    descriptor = os.open(parent, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _open_regular_input_descriptor(
    source: Path,
    *,
    max_bytes: int,
    require_private_permissions: bool,
    require_current_owner: bool,
) -> tuple[int, os.stat_result]:
    """Open and bind one bounded regular input without following its final component."""

    metadata = source.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise UnsafeInputPathError(f"refusing non-regular or symlink input path: {source}")
    if metadata.st_size > max_bytes:
        raise UnsafeInputPathError(f"input exceeds the {max_bytes}-byte safety limit: {source}")
    if os.name != "nt":
        if require_private_permissions and stat.S_IMODE(metadata.st_mode) & 0o077:
            raise UnsafeInputPathError(f"input must not be accessible by group or other users: {source}")
        if require_current_owner and metadata.st_uid != os.geteuid():
            raise UnsafeInputPathError(f"managed plaintext file must be owned by the current user: {source}")

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(source, flags)
    try:
        opened = os.fstat(descriptor)
        invalid = (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
            or opened.st_size > max_bytes
        )
        if os.name != "nt":
            invalid = (
                invalid
                or (require_private_permissions and bool(stat.S_IMODE(opened.st_mode) & 0o077))
                or (require_current_owner and opened.st_uid != os.geteuid())
            )
        if invalid:
            raise UnsafeInputPathError(f"input changed while it was being opened: {source}")
        return descriptor, opened
    except BaseException:
        os.close(descriptor)
        raise


@contextmanager
def _open_regular_text(
    path: Path,
    *,
    max_bytes: int,
    require_private_permissions: bool,
    require_current_owner: bool,
) -> Generator[TextIO]:
    source = path.expanduser()
    descriptor, _ = _open_regular_input_descriptor(
        source,
        max_bytes=max_bytes,
        require_private_permissions=require_private_permissions,
        require_current_owner=require_current_owner,
    )
    try:
        with os.fdopen(descriptor, "rb", buffering=0) as binary_stream:
            descriptor = -1
            bounded_stream = _BoundedRawReader(binary_stream, max_bytes=max_bytes, source=source)
            with TextIOWrapper(BufferedReader(bounded_stream), encoding="utf-8", newline="") as stream:
                yield stream
    finally:
        if descriptor >= 0:
            os.close(descriptor)


@contextmanager
def open_private_text(path: Path, *, max_bytes: int = 1_048_576) -> Generator[TextIO]:
    """Open a small private regular text file without following symlinks."""

    with _open_regular_text(
        path,
        max_bytes=max_bytes,
        require_private_permissions=True,
        require_current_owner=False,
    ) as stream:
        yield stream


@contextmanager
def open_managed_plaintext(path: Path, *, max_bytes: int = 1_048_576) -> Generator[TextIO]:
    """Open one user-owned managed plaintext file regardless of its POSIX access bits."""

    with _open_regular_text(
        path,
        max_bytes=max_bytes,
        require_private_permissions=False,
        require_current_owner=True,
    ) as stream:
        yield stream


def managed_plaintext_permissions_are_broad(path: Path, *, max_bytes: int = 1_048_576) -> bool:
    """Report whether POSIX mode bits grant group or other read/write access."""

    if os.name == "nt":
        return False
    source = path.expanduser()
    descriptor, opened = _open_regular_input_descriptor(
        source,
        max_bytes=max_bytes,
        require_private_permissions=False,
        require_current_owner=True,
    )
    os.close(descriptor)
    return bool(stat.S_IMODE(opened.st_mode) & 0o066)


def read_private_text(path: Path, *, max_bytes: int = 1_048_576) -> str:
    """Read a small private regular file without following symlinks."""

    source = path.expanduser()
    with open_private_text(source, max_bytes=max_bytes) as stream:
        content = stream.read(max_bytes + 1)
    if len(content.encode("utf-8")) > max_bytes:
        raise UnsafeInputPathError(f"input exceeds the {max_bytes}-byte safety limit: {source}")
    return content


def read_managed_plaintext(path: Path, *, max_bytes: int = 1_048_576) -> str:
    """Read one bounded user-owned plaintext file without enforcing its access policy."""

    source = path.expanduser()
    with open_managed_plaintext(source, max_bytes=max_bytes) as stream:
        content = stream.read(max_bytes + 1)
    if len(content.encode("utf-8")) > max_bytes:
        raise UnsafeInputPathError(f"input exceeds the {max_bytes}-byte safety limit: {source}")
    return content


@contextmanager
def temporary_regular_copy(
    path: Path,
    *,
    max_bytes: int,
    require_restricted_writes: bool = True,
) -> Generator[tuple[Path, RegularFileSnapshot]]:
    """Copy one user-owned regular file to a same-directory private temporary."""

    source = path.expanduser()
    content, metadata = _read_managed_regular_bytes(
        source,
        max_bytes=max_bytes,
        require_restricted_writes=require_restricted_writes,
    )
    snapshot = RegularFileSnapshot(
        path=source,
        digest=sha256(content).hexdigest(),
        device=metadata.st_dev,
        inode=metadata.st_ino,
        size=metadata.st_size,
        modified_ns=metadata.st_mtime_ns,
        mode=stat.S_IMODE(metadata.st_mode),
        owner=metadata.st_uid,
        group=metadata.st_gid,
    )
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{source.name}.azurator.", dir=source.parent)
    temporary = Path(temporary_name)
    try:
        if os.name != "nt":
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        content = b""
        yield temporary, snapshot
    finally:
        content = b""
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def commit_regular_copy(
    snapshot: RegularFileSnapshot,
    temporary: Path,
    *,
    max_bytes: int,
    require_restricted_writes: bool = True,
) -> None:
    """Replace a still-identical managed file with one durable same-directory regular temporary."""

    if temporary.parent != snapshot.path.parent:
        raise UnsafeOutputPathError("managed-file temporary is not in the destination directory")
    _, temporary_metadata = _read_managed_regular_bytes(temporary, max_bytes=max_bytes)

    flags = os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary, flags)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (temporary_metadata.st_dev, temporary_metadata.st_ino):
            raise UnsafeOutputPathError("managed-file temporary changed while it was being committed")
        if os.name != "nt":
            os.fchown(descriptor, snapshot.owner, snapshot.group)
            os.fchmod(descriptor, snapshot.mode)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)

    current, current_metadata = _read_managed_regular_bytes(
        snapshot.path,
        max_bytes=max_bytes,
        require_restricted_writes=require_restricted_writes,
    )
    unchanged = (
        (current_metadata.st_dev, current_metadata.st_ino) == (snapshot.device, snapshot.inode)
        and current_metadata.st_size == snapshot.size
        and current_metadata.st_mtime_ns == snapshot.modified_ns
        and stat.S_IMODE(current_metadata.st_mode) == snapshot.mode
        and current_metadata.st_uid == snapshot.owner
        and current_metadata.st_gid == snapshot.group
        and sha256(current).hexdigest() == snapshot.digest
    )
    current = b""
    if not unchanged:
        raise UnsafeOutputPathError("managed file changed concurrently and was not replaced")

    os.replace(temporary, snapshot.path)
    _fsync_parent_directory(snapshot.path.parent)


def _write_regular_temporary_bytes(path: Path, content: bytes) -> None:
    """Rewrite one controlled regular temporary and durably flush its content."""

    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise UnsafeOutputPathError("managed-file temporary is not a regular file")
    flags = os.O_WRONLY | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise UnsafeOutputPathError("managed-file temporary changed while it was being written")
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def replace_managed_plaintext(
    path: Path,
    expected_content: str,
    replacement_content: str,
    *,
    max_bytes: int = 1_048_576,
) -> None:
    """Atomically replace unchanged managed plaintext while preserving its POSIX metadata."""

    expected = expected_content.encode("utf-8")
    replacement = replacement_content.encode("utf-8")
    if len(replacement) > max_bytes:
        raise UnsafeOutputPathError(f"output exceeds the {max_bytes}-byte safety limit")
    try:
        with temporary_regular_copy(
            path,
            max_bytes=max_bytes,
            require_restricted_writes=False,
        ) as (temporary, snapshot):
            expected_digest = sha256(expected).hexdigest()
            if snapshot.size != len(expected) or not compare_digest(snapshot.digest, expected_digest):
                raise UnsafeOutputPathError("managed plaintext file changed concurrently and was not replaced")
            _write_regular_temporary_bytes(temporary, replacement)
            commit_regular_copy(
                snapshot,
                temporary,
                max_bytes=max_bytes,
                require_restricted_writes=False,
            )
    finally:
        expected = b""
        replacement = b""


def _read_managed_regular_bytes(
    path: Path,
    *,
    max_bytes: int,
    require_restricted_writes: bool = True,
) -> tuple[bytes, os.stat_result]:
    """Read one user-owned regular file through a descriptor-bound snapshot."""

    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise UnsafeInputPathError(f"refusing non-regular or symlink managed path: {path}")
    if metadata.st_size > max_bytes:
        raise UnsafeInputPathError(f"input exceeds the {max_bytes}-byte safety limit: {path}")
    if os.name != "nt":
        if require_restricted_writes and stat.S_IMODE(metadata.st_mode) & 0o022:
            raise UnsafeInputPathError(f"managed file must not be writable by group or other users: {path}")
        if metadata.st_uid != os.geteuid():
            raise UnsafeInputPathError(f"managed file must be owned by the current user: {path}")

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
            or opened.st_size > max_bytes
            or (os.name != "nt" and require_restricted_writes and bool(stat.S_IMODE(opened.st_mode) & 0o022))
            or (os.name != "nt" and opened.st_uid != os.geteuid())
        ):
            raise UnsafeInputPathError(f"managed file changed while it was being opened: {path}")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            content = stream.read(max_bytes + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(content) > max_bytes:
        raise UnsafeInputPathError(f"input exceeds the {max_bytes}-byte safety limit: {path}")
    return content, opened


def write_private_text(path: Path, content: str) -> None:
    """Atomically write UTF-8 text with mode 0600, refusing unsafe targets."""

    destination = path.expanduser()
    parent = _prepare_parent(destination)

    try:
        existing = destination.lstat()
    except FileNotFoundError:
        existing = None

    if existing is not None and (stat.S_ISLNK(existing.st_mode) or not stat.S_ISREG(existing.st_mode)):
        raise UnsafeOutputPathError(f"refusing non-regular or symlink output path: {destination}")

    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{destination.name}.", dir=parent)
    temporary = Path(temporary_name)
    try:
        if os.name != "nt":
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            descriptor = -1
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
        _fsync_parent_directory(parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def create_private_text(path: Path, content: str) -> None:
    """Atomically and exclusively create a durable private UTF-8 file."""

    destination = path.expanduser()
    parent = _prepare_parent(destination)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{destination.name}.", dir=parent)
    temporary = Path(temporary_name)
    try:
        if os.name != "nt":
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            descriptor = -1
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, destination)
        except FileExistsError as error:
            raise PrivateFileExistsError(f"refusing to replace existing private file: {destination}") from error
        temporary.unlink()
        _fsync_parent_directory(parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def create_private_bytes(path: Path, content: bytes | bytearray) -> None:
    """Atomically and exclusively create a durable private binary file."""

    destination = path.expanduser()
    parent = _prepare_parent(destination)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{destination.name}.", dir=parent)
    temporary = Path(temporary_name)
    try:
        if os.name != "nt":
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, destination)
        except FileExistsError as error:
            raise PrivateFileExistsError(f"refusing to replace existing private file: {destination}") from error
        temporary.unlink()
        _fsync_parent_directory(parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def remove_private_text(path: Path) -> None:
    """Remove one private regular non-symlink file and flush its parent."""

    target = path.expanduser()
    metadata = target.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise UnsafeOutputPathError(f"refusing non-regular or symlink removal target: {target}")
    if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077:
        raise UnsafeOutputPathError(f"refusing non-private removal target: {target}")
    target.unlink()
    _fsync_parent_directory(target.parent)


def remove_empty_private_directory(path: Path) -> None:
    """Remove one empty private directory and flush its parent."""

    target = path.expanduser()
    metadata = target.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise UnsafeOutputPathError(f"refusing non-directory or symlink removal target: {target}")
    if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077:
        raise UnsafeOutputPathError(f"refusing non-private directory removal target: {target}")
    target.rmdir()
    _fsync_parent_directory(target.parent)

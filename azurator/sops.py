"""Exact subprocess adapter for the supported SOPS 3.13.x dotenv contract."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Protocol, cast

from azurator.files import MAX_OPERATION_ARTIFACT_BYTES
from azurator.inputs import MAX_DOTENV_FILE_BYTES, SecretInputError, validate_dotenv_selector

_SUPPORTED_VERSION = re.compile(r"sops 3\.13\.\d+\s*")
_MAX_STATUS_BYTES = 4_096
MAX_SOPS_DOTENV_FILE_BYTES = MAX_OPERATION_ARTIFACT_BYTES


class SopsError(RuntimeError):
    """A SOPS command failed without exposing command output or decrypted data."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class SopsCommand(Protocol):
    """The exact SOPS operations used by the managed encrypted-dotenv provider."""

    def decrypt_dotenv(self, path: Path) -> str: ...

    def set_dotenv_value(self, path: Path, selector: str, value: str) -> None: ...


class SopsExportCommand(Protocol):
    """Exact in-memory SOPS operations used by encrypted dotenv export."""

    def validate(self) -> None: ...

    def encrypt_dotenv(self, destination: Path, plaintext: bytearray) -> bytearray: ...

    def decrypt_dotenv_ciphertext(self, destination: Path, ciphertext: bytearray) -> str: ...


class SopsCli:
    """Invoke one pinned SOPS command shape without a shell or secret arguments."""

    def __init__(self, executable: str | None = None) -> None:
        self._configured_executable = executable
        self._resolved_executable: str | None = None
        self._version_checked = False

    def validate(self) -> None:
        """Require the exact supported executable version without processing content."""

        executable = self._executable()
        self._ensure_version(executable)

    def encrypt_dotenv(self, destination: Path, plaintext: bytearray) -> bytearray:
        """Encrypt an in-memory dotenv document using the destination's creation rule."""

        if not plaintext or len(plaintext) > MAX_DOTENV_FILE_BYTES:
            raise SopsError(
                "sops-dotenv-input-invalid",
                "The generated dotenv content is outside the supported size contract.",
            )
        return self._capture_stdin(
            (
                "encrypt",
                "--filename-override",
                str(destination),
                "--input-type",
                "dotenv",
                "--output-type",
                "dotenv",
            ),
            plaintext,
            code="sops-encrypt-failed",
            message="SOPS could not encrypt the generated dotenv file with its configured creation rules.",
            max_bytes=MAX_SOPS_DOTENV_FILE_BYTES,
        )

    def decrypt_dotenv_ciphertext(self, destination: Path, ciphertext: bytearray) -> str:
        """Decrypt captured ciphertext from stdin for an in-memory export round trip."""

        if not ciphertext or len(ciphertext) > MAX_SOPS_DOTENV_FILE_BYTES:
            raise SopsError(
                "sops-ciphertext-invalid",
                "SOPS returned ciphertext outside the supported size contract.",
            )
        output = self._capture_stdin(
            (
                "decrypt",
                "--filename-override",
                str(destination),
                "--input-type",
                "dotenv",
                "--output-type",
                "dotenv",
            ),
            ciphertext,
            code="sops-export-verification-failed",
            message="SOPS could not decrypt the generated ciphertext for verification.",
            max_bytes=MAX_DOTENV_FILE_BYTES,
        )
        try:
            return output.decode("utf-8")
        except UnicodeError:
            raise SopsError(
                "sops-dotenv-output-invalid",
                "SOPS returned decrypted content outside the supported UTF-8 dotenv contract.",
            ) from None
        finally:
            output[:] = b"\x00" * len(output)

    def decrypt_dotenv(self, path: Path) -> str:
        """Decrypt one caller-owned safe temporary as strict dotenv in memory."""

        self._require_encrypted(path)
        output = self._capture(
            ("decrypt", "--input-type", "dotenv", "--output-type", "dotenv", str(path)),
            code="sops-decrypt-failed",
            message="SOPS could not decrypt the selected dotenv file with the available identities.",
            max_bytes=MAX_DOTENV_FILE_BYTES,
        )
        try:
            return output.decode("utf-8")
        except UnicodeError:
            raise SopsError(
                "sops-dotenv-output-invalid",
                "SOPS returned decrypted content outside the supported UTF-8 dotenv contract.",
            ) from None
        finally:
            output[:] = b"\x00" * len(output)

    def set_dotenv_value(self, path: Path, selector: str, value: str) -> None:
        """Set one top-level dotenv value, supplying its JSON string only over stdin."""

        try:
            validate_dotenv_selector(selector)
        except SecretInputError:
            raise SopsError(
                "sops-selector-invalid",
                "A SOPS dotenv selector does not satisfy the supported format.",
            ) from None
        if not value:
            raise SopsError(
                "sops-value-invalid",
                "A SOPS dotenv replacement value does not satisfy the supported format.",
            )

        executable = self._executable()
        self._ensure_version(executable)
        payload = bytearray(json.dumps(value, ensure_ascii=True).encode("utf-8"))
        process: subprocess.Popen[bytes] | None = None
        try:
            process = subprocess.Popen(
                (
                    executable,
                    "set",
                    "--input-type",
                    "dotenv",
                    "--output-type",
                    "dotenv",
                    "--value-stdin",
                    str(path),
                    json.dumps([selector], ensure_ascii=True, separators=(",", ":")),
                ),
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if process.stdin is None:
                raise OSError("SOPS stdin was unavailable")
            process.stdin.write(payload)
            process.stdin.close()
            return_code = process.wait()
        except BaseException:
            if process is not None and process.poll() is None:
                process.kill()
                process.wait()
            raise
        finally:
            payload[:] = b"\x00" * len(payload)
        if return_code != 0:
            raise SopsError("sops-update-failed", "SOPS could not update the encrypted dotenv file.")
        self._require_encrypted(path)

    def _require_encrypted(self, path: Path) -> None:
        output = self._capture(
            ("filestatus", "--input-type", "dotenv", str(path)),
            code="sops-file-status-failed",
            message="The selected file is not a valid SOPS-encrypted dotenv document.",
            max_bytes=_MAX_STATUS_BYTES,
        )
        try:
            status = json.loads(output)
        except (json.JSONDecodeError, UnicodeError):
            status = None
        finally:
            output[:] = b"\x00" * len(output)
        if status != {"encrypted": True}:
            raise SopsError(
                "sops-file-not-encrypted",
                "The selected file is not a valid SOPS-encrypted dotenv document.",
            )

    def _capture(
        self,
        arguments: tuple[str, ...],
        *,
        code: str,
        message: str,
        max_bytes: int,
    ) -> bytearray:
        executable = self._executable()
        self._ensure_version(executable)
        try:
            completed = subprocess.run(
                (executable, *arguments),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        except OSError:
            raise SopsError(
                "sops-unavailable",
                "SOPS 3.13.x is required for encrypted dotenv operations.",
            ) from None
        if completed.returncode != 0 or len(completed.stdout) > max_bytes:
            raise SopsError(code, message)
        return bytearray(completed.stdout)

    def _capture_stdin(
        self,
        arguments: tuple[str, ...],
        content: bytearray,
        *,
        code: str,
        message: str,
        max_bytes: int,
    ) -> bytearray:
        """Capture bounded command output while keeping input out of argv and stderr."""

        executable = self._executable()
        self._ensure_version(executable)
        raw_output = b""
        try:
            process = subprocess.Popen(
                (executable, *arguments),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
        except OSError:
            raise SopsError("sops-unavailable", "SOPS 3.13.x is required for encrypted dotenv operations.") from None
        try:
            raw_output, _ = process.communicate(input=cast(bytes, content))
        except OSError:
            if process.poll() is None:
                process.kill()
                process.wait()
            raise SopsError(code, message) from None
        except BaseException:
            if process.poll() is None:
                process.kill()
                process.wait()
            raise
        output = bytearray(raw_output)
        raw_output = b""
        if process.returncode != 0 or len(output) > max_bytes:
            output[:] = b"\x00" * len(output)
            raise SopsError(code, message)
        return output

    def _executable(self) -> str:
        if self._resolved_executable is not None:
            return self._resolved_executable
        executable = self._configured_executable or shutil.which("sops")
        if executable is None:
            raise SopsError("sops-unavailable", "SOPS 3.13.x is required for encrypted dotenv operations.")
        self._resolved_executable = executable
        return executable

    def _ensure_version(self, executable: str) -> None:
        if self._version_checked:
            return
        try:
            completed = subprocess.run(
                (executable, "--disable-version-check", "--version"),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        except OSError:
            raise SopsError("sops-unavailable", "SOPS 3.13.x is required for encrypted dotenv operations.") from None
        try:
            version = completed.stdout.decode("ascii")
        except UnicodeError:
            version = ""
        if completed.returncode != 0 or _SUPPORTED_VERSION.fullmatch(version) is None:
            raise SopsError(
                "sops-version-unsupported",
                "The installed SOPS version is outside the supported 3.13.x range.",
            )
        self._version_checked = True

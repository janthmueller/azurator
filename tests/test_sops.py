"""Tests for the exact SOPS 3.13 command adapter."""

from __future__ import annotations

import shutil
import subprocess
from io import BytesIO
from pathlib import Path

import pytest

from azurator.sops import SopsCli, SopsError


class _RecordingProcess:
    def __init__(self) -> None:
        self.stdin = BytesIO()
        self.returncode: int | None = None

    def wait(self) -> int:
        self.returncode = 0
        return 0

    def poll(self) -> int | None:
        return self.returncode

    def kill(self) -> None:
        self.returncode = -9


class _CommunicatingProcess:
    def __init__(self, output: bytes, *, returncode: int = 0) -> None:
        self._output = output
        self.returncode: int | None = returncode
        self.input = b""

    def communicate(self, input: bytearray) -> tuple[bytes, None]:
        self.input = bytes(input)
        return self._output, None

    def poll(self) -> int | None:
        return self.returncode

    def wait(self) -> int:
        if self.returncode is None:
            self.returncode = 0
        return self.returncode

    def kill(self) -> None:
        self.returncode = -9


def test_missing_sops_executable_fails_with_a_fixed_secret_free_error(tmp_path: Path) -> None:
    source = tmp_path / "secrets.enc.env"
    source.write_text("TOKEN=must-not-render\n", encoding="utf-8")

    with pytest.raises(SopsError) as caught:
        SopsCli(executable=str(tmp_path / "missing-sops")).decrypt_dotenv(source)

    assert caught.value.code == "sops-unavailable"
    assert "must-not-render" not in str(caught.value)
    assert str(source) not in str(caught.value)


def test_sops_set_sends_the_replacement_only_over_stdin(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "secrets.enc.env"
    source.write_text("synthetic-ciphertext\n", encoding="utf-8")
    replacement = "replacement-must-not-enter-argv"
    process = _RecordingProcess()
    recorded_arguments: tuple[str, ...] | None = None

    def popen(arguments: tuple[str, ...], **_kwargs: object) -> _RecordingProcess:
        nonlocal recorded_arguments
        recorded_arguments = arguments
        return process

    def accept_version(_executable: str) -> None:
        return None

    def accept_encrypted(_path: Path) -> None:
        return None

    command = SopsCli(executable="/synthetic/sops")
    monkeypatch.setattr(command, "_ensure_version", accept_version)
    monkeypatch.setattr(command, "_require_encrypted", accept_encrypted)
    monkeypatch.setattr(subprocess, "Popen", popen)

    command.set_dotenv_value(source, "AZURE_KEY", replacement)

    assert recorded_arguments is not None
    assert "--value-stdin" in recorded_arguments
    assert all(replacement not in argument for argument in recorded_arguments)
    assert process.stdin.closed


def test_sops_export_uses_filename_override_and_keeps_plaintext_out_of_argv(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "secrets.enc.env"
    plaintext = bytearray(b"TOKEN='plaintext-must-not-enter-argv'\n")
    process = _CommunicatingProcess(b"synthetic-ciphertext")
    recorded_arguments: tuple[str, ...] | None = None

    def popen(arguments: tuple[str, ...], **_kwargs: object) -> _CommunicatingProcess:
        nonlocal recorded_arguments
        recorded_arguments = arguments
        return process

    def accept_version(_executable: str) -> None:
        return None

    command = SopsCli(executable="/synthetic/sops")
    monkeypatch.setattr(command, "_ensure_version", accept_version)
    monkeypatch.setattr(subprocess, "Popen", popen)

    ciphertext = command.encrypt_dotenv(destination, plaintext)

    assert recorded_arguments == (
        "/synthetic/sops",
        "encrypt",
        "--filename-override",
        str(destination),
        "--input-type",
        "dotenv",
        "--output-type",
        "dotenv",
    )
    assert recorded_arguments is not None
    assert all("plaintext-must-not-enter-argv" not in argument for argument in recorded_arguments)
    assert process.input == plaintext
    assert ciphertext == b"synthetic-ciphertext"


def test_sops_export_verification_reads_ciphertext_from_stdin(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "secrets.enc.env"
    ciphertext = bytearray(b"ciphertext-must-not-enter-argv")
    process = _CommunicatingProcess(b"TOKEN=decrypted-value\n")
    recorded_arguments: tuple[str, ...] | None = None

    def popen(arguments: tuple[str, ...], **_kwargs: object) -> _CommunicatingProcess:
        nonlocal recorded_arguments
        recorded_arguments = arguments
        return process

    def accept_version(_executable: str) -> None:
        return None

    command = SopsCli(executable="/synthetic/sops")
    monkeypatch.setattr(command, "_ensure_version", accept_version)
    monkeypatch.setattr(subprocess, "Popen", popen)

    decrypted = command.decrypt_dotenv_ciphertext(destination, ciphertext)

    assert recorded_arguments == (
        "/synthetic/sops",
        "decrypt",
        "--filename-override",
        str(destination),
        "--input-type",
        "dotenv",
        "--output-type",
        "dotenv",
    )
    assert recorded_arguments is not None
    assert all("ciphertext-must-not-enter-argv" not in argument for argument in recorded_arguments)
    assert process.input == ciphertext
    assert decrypted == "TOKEN=decrypted-value\n"


@pytest.mark.skipif(
    shutil.which("sops") is None or shutil.which("age-keygen") is None,
    reason="the disposable SOPS contract test requires sops and age-keygen",
)
def test_real_sops_313_dotenv_decrypt_and_value_stdin_update(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exercise only generated fake data and never contact Azure."""

    key_file = tmp_path / "age-key.txt"
    subprocess.run(
        ("age-keygen", "-o", str(key_file)),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=True,
    )
    public_line = next(
        line for line in key_file.read_text(encoding="utf-8").splitlines() if line.startswith("# public key: ")
    )
    recipient = public_line.removeprefix("# public key: ")
    plaintext = tmp_path / "plain.env"
    encrypted = tmp_path / "secrets.enc.env"
    plaintext.write_text("FIRST=fake-old-value\nALIAS=fake-old-value\nUNCHANGED=fake-static-value\n", encoding="utf-8")
    with encrypted.open("wb") as output:
        subprocess.run(
            (
                "sops",
                "encrypt",
                "--input-type",
                "dotenv",
                "--output-type",
                "dotenv",
                "--age",
                recipient,
                str(plaintext),
            ),
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=subprocess.DEVNULL,
            check=True,
        )
    plaintext.unlink()
    monkeypatch.setenv("SOPS_AGE_KEY_FILE", str(key_file))
    command = SopsCli()

    assert "FIRST=fake-old-value" in command.decrypt_dotenv(encrypted)
    command.set_dotenv_value(encrypted, "FIRST", "fake-new-value")
    command.set_dotenv_value(encrypted, "ALIAS", "fake-new-value")
    decrypted = command.decrypt_dotenv(encrypted)

    assert "FIRST=fake-new-value" in decrypted
    assert "ALIAS=fake-new-value" in decrypted
    assert "UNCHANGED=fake-static-value" in decrypted
    ciphertext = encrypted.read_text(encoding="utf-8")
    assert "fake-old-value" not in ciphertext
    assert "fake-new-value" not in ciphertext
    assert "fake-static-value" not in ciphertext


@pytest.mark.skipif(
    shutil.which("sops") is None or shutil.which("age-keygen") is None,
    reason="the disposable SOPS export test requires sops and age-keygen",
)
def test_real_sops_313_in_memory_dotenv_export_round_trip(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exercise generated fake content only and never create a plaintext dotenv file."""

    key_file = tmp_path / "age-key.txt"
    subprocess.run(
        ("age-keygen", "-o", str(key_file)),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=True,
    )
    public_line = next(
        line for line in key_file.read_text(encoding="utf-8").splitlines() if line.startswith("# public key: ")
    )
    recipient = public_line.removeprefix("# public key: ")
    (tmp_path / ".sops.yaml").write_text(
        f"creation_rules:\n  - path_regex: secrets\\.enc\\.env$\n    age: {recipient}\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SOPS_AGE_KEY_FILE", str(key_file))
    destination = tmp_path / "secrets.enc.env"
    plaintext = bytearray(b"FIRST='fake-secret-one'\nSECOND='fake-secret-two'\n")
    command = SopsCli()

    ciphertext = command.encrypt_dotenv(destination, plaintext)
    decrypted = command.decrypt_dotenv_ciphertext(destination, ciphertext)

    assert not destination.exists()
    assert "FIRST='fake-secret-one'" in decrypted
    assert "SECOND='fake-secret-two'" in decrypted
    assert b"fake-secret-one" not in ciphertext
    assert b"fake-secret-two" not in ciphertext

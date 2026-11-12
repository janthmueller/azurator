"""Per-assignment confidentiality checks, including ciphertext-looking plaintext."""

from pathlib import Path

import pytest

from azurator.sops import SopsCli, SopsEncryptionError

_RECORD = "ENC[AES256_GCM,data:ZmFrZQ==,iv:ZmFrZQ==,tag:ZmFrZQ==,type:str]"


@pytest.mark.parametrize(
    ("ciphertext", "plaintext"),
    [
        ("TOKEN=dummy-private-value\n", "TOKEN=dummy-private-value\n"),
        (f"TOKEN={_RECORD}\n", f"TOKEN={_RECORD}\n"),
        (f"TOKEN='{_RECORD}'\n", "TOKEN=dummy-private-value\n"),
        (f"TOKEN={_RECORD.replace('AES256_GCM', 'UNKNOWN')}\n", "TOKEN=dummy-private-value\n"),
        (f"TOKEN={_RECORD}\nTOKEN={_RECORD}\n", "TOKEN=dummy-private-value\n"),
        (f"OTHER={_RECORD}\n", "TOKEN=dummy-private-value\n"),
        (f"TOKEN={_RECORD}\n", "TOKEN=\n"),
        (f"TOKEN={_RECORD}\n", "TOKEN=one\nTOKEN=two\n"),
    ],
)
def test_export_rejects_unencrypted_ambiguous_or_unrecognized_values(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    ciphertext: str,
    plaintext: str,
) -> None:
    command = SopsCli()
    decrypted = bytearray(plaintext.encode("utf-8"))

    def capture(*_args: object, **_kwargs: object) -> bytearray:
        return decrypted

    monkeypatch.setattr(command, "_capture_stdin", capture)

    with pytest.raises(SopsEncryptionError) as caught:
        command.decrypt_dotenv_ciphertext(tmp_path / "keys.enc.env", bytearray(ciphertext.encode("utf-8")))

    assert caught.value.code == "sops-values-not-encrypted"
    assert "encryption rules" in str(caught.value)
    assert "dummy-private-value" not in str(caught.value)
    assert _RECORD not in str(caught.value)
    assert not any(decrypted)


def test_selected_encrypted_values_allow_unrelated_plaintext(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "keys.enc.env"
    source.write_text(f"TOKEN={_RECORD}\nPUBLIC=visible\n", encoding="utf-8")
    command = SopsCli()

    def accept_encrypted(_path: Path) -> None:
        return None

    def capture(*_args: object, **_kwargs: object) -> bytearray:
        return bytearray(b"TOKEN=secret\nPUBLIC=visible\n")

    monkeypatch.setattr(command, "_require_encrypted", accept_encrypted)
    monkeypatch.setattr(command, "_capture", capture)

    assert command.decrypt_dotenv(source, encrypted_selectors=("TOKEN",)) == "TOKEN=secret\nPUBLIC=visible\n"
    with pytest.raises(SopsEncryptionError):
        command.decrypt_dotenv(source, encrypted_selectors=("TOKEN", "PUBLIC"))

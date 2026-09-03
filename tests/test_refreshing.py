"""Atomic plaintext and SOPS dotenv refresh contract tests."""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from io import StringIO
from pathlib import Path

import pytest

from azurator.inputs import consume_dotenv
from azurator.models import DiscoveredResource, DotenvKeyAssignment, KeyAuthentication, KeySlot
from azurator.refreshing import (
    PlaintextDotenvRefreshService,
    RefreshError,
    SopsDotenvRefreshService,
)
from azurator.sops import SopsCli
from tests.sops_test_support import FakeSopsCommand, write_fake_sops_file

SELECTORS = ("PRIMARY_KEY", "PRIMARY_ALIAS", "SECONDARY_KEY")
CURRENT_DOTENV = (
    "PRIMARY_KEY='current-primary-secret'\n"
    "PRIMARY_ALIAS='current-primary-secret'\n"
    "SECONDARY_KEY='current-secondary-secret'\n"
)


RESOURCE = DiscoveredResource(
    resource_id=(
        "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg/"
        "providers/Microsoft.Storage/storageAccounts/accountone"
    ),
    name="accountone",
    resource_type="Microsoft.Storage/storageAccounts",
    location="westeurope",
    kind="StorageV2",
    provider="azure-storage",
    key_authentication=KeyAuthentication.enabled,
    key_slots=(
        KeySlot(name="key1", values_retrievable=True, rotatable=True),
        KeySlot(name="key2", values_retrievable=True, rotatable=True),
    ),
)
ASSIGNMENTS = tuple(
    DotenvKeyAssignment(
        resource=RESOURCE,
        resource_group="rg",
        key_slot="key2" if selector == "SECONDARY_KEY" else "key1",
        selector=selector,
    )
    for selector in SELECTORS
)


def _plaintext_target(path: Path) -> None:
    path.write_text(
        "# application configuration\r\n"
        "export PRIMARY_KEY = stale-primary-secret\r\n"
        "UNRELATED='preserve-me'\n"
        "PRIMARY_ALIAS='current-primary-secret'\n"
        "SECONDARY_KEY=\n",
        encoding="utf-8",
        newline="",
    )
    if os.name != "nt":
        path.chmod(0o640)


def _sops_target(path: Path) -> None:
    write_fake_sops_file(
        path,
        "PRIMARY_KEY=stale-primary-secret\n"
        "UNRELATED=preserve-me\n"
        "PRIMARY_ALIAS=current-primary-secret\n"
        "SECONDARY_KEY=\n",
    )


def _generate_age_identity(path: Path) -> str:
    subprocess.run(
        ("age-keygen", "-o", str(path)),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=True,
    )
    public_line = next(
        line for line in path.read_text(encoding="utf-8").splitlines() if line.startswith("# public key: ")
    )
    return public_line.removeprefix("# public key: ")


def _dotenv_mapping(content: str) -> dict[str, str]:
    values: dict[str, str] = {}
    result = consume_dotenv(
        StringIO(content, newline=""),
        lambda selector, value: values.__setitem__(selector, value),
    )
    assert result.skipped_empty_selectors == ()
    return values


def test_plaintext_refresh_updates_only_changed_mapped_values_in_one_replacement(tmp_path: Path) -> None:
    target = tmp_path / "secrets.env"
    _plaintext_target(target)
    service = PlaintextDotenvRefreshService()

    service.validate_target(target, SELECTORS)
    result = service.refresh(target, ASSIGNMENTS, CURRENT_DOTENV)

    assert result.assignment_count == 3
    assert result.changed_assignment_count == 2
    assert result.already_current_count == 1
    assert target.read_bytes().decode("utf-8") == (
        "# application configuration\r\n"
        "export PRIMARY_KEY ='current-primary-secret'\r\n"
        "UNRELATED='preserve-me'\n"
        "PRIMARY_ALIAS='current-primary-secret'\n"
        "SECONDARY_KEY='current-secondary-secret'\n"
    )
    if os.name != "nt":
        assert stat.S_IMODE(target.stat().st_mode) == 0o640
    assert list(tmp_path.glob(".secrets.env.azurator.*")) == []


def test_plaintext_refresh_does_not_rewrite_an_already_current_file(tmp_path: Path) -> None:
    target = tmp_path / "secrets.env"
    target.write_text("# keep formatting\n" + CURRENT_DOTENV + "UNRELATED=keep\n", encoding="utf-8")
    before = target.read_bytes()
    before_stat = target.stat()

    result = PlaintextDotenvRefreshService().refresh(target, ASSIGNMENTS, CURRENT_DOTENV)

    assert result.changed_assignment_count == 0
    assert result.already_current_count == 3
    assert target.read_bytes() == before
    assert (target.stat().st_dev, target.stat().st_ino) == (before_stat.st_dev, before_stat.st_ino)


def test_plaintext_refresh_treats_a_non_ascii_existing_value_as_stale(tmp_path: Path) -> None:
    target = tmp_path / "secrets.env"
    target.write_text(
        "PRIMARY_KEY='älterer-wert'\n"
        "PRIMARY_ALIAS='current-primary-secret'\n"
        "SECONDARY_KEY='current-secondary-secret'\n",
        encoding="utf-8",
    )

    result = PlaintextDotenvRefreshService().refresh(target, ASSIGNMENTS, CURRENT_DOTENV)

    assert result.changed_assignment_count == 1
    assert target.read_text(encoding="utf-8") == CURRENT_DOTENV


def test_plaintext_refresh_preserves_an_existing_storage_connection_string(tmp_path: Path) -> None:
    target = tmp_path / "secrets.env"
    target.write_text(
        "PRIMARY_KEY='DefaultEndpointsProtocol=https;AccountName=accountone;"
        "AccountKey=stale-primary-secret;EndpointSuffix=core.windows.net'\n"
        "PRIMARY_ALIAS=current-primary-secret\n"
        "SECONDARY_KEY=current-secondary-secret\n",
        encoding="utf-8",
    )

    result = PlaintextDotenvRefreshService().refresh(target, ASSIGNMENTS, CURRENT_DOTENV)

    assert result.changed_assignment_count == 1
    assert target.read_text(encoding="utf-8") == (
        "PRIMARY_KEY='DefaultEndpointsProtocol=https;AccountName=accountone;"
        "AccountKey=current-primary-secret;EndpointSuffix=core.windows.net'\n"
        "PRIMARY_ALIAS=current-primary-secret\n"
        "SECONDARY_KEY=current-secondary-secret\n"
    )


def test_plaintext_refresh_rejects_a_connection_string_for_another_account(tmp_path: Path) -> None:
    target = tmp_path / "secrets.env"
    content = (
        "PRIMARY_KEY='DefaultEndpointsProtocol=https;AccountName=accounttwo;"
        "AccountKey=stale-primary-secret;EndpointSuffix=core.windows.net'\n"
        "PRIMARY_ALIAS=current-primary-secret\n"
        "SECONDARY_KEY=current-secondary-secret\n"
    )
    target.write_text(content, encoding="utf-8")

    with pytest.raises(RefreshError, match="different Azure key resource"):
        PlaintextDotenvRefreshService().refresh(target, ASSIGNMENTS, CURRENT_DOTENV)

    assert target.read_text(encoding="utf-8") == content


def test_plaintext_refresh_rejects_a_missing_mapped_selector_without_adding_it(tmp_path: Path) -> None:
    target = tmp_path / "secrets.env"
    target.write_text("PRIMARY_KEY=old-secret\nPRIMARY_ALIAS=old-secret\nUNRELATED=keep\n", encoding="utf-8")
    original = target.read_bytes()
    service = PlaintextDotenvRefreshService()

    with pytest.raises(RefreshError, match="SECONDARY_KEY"):
        service.validate_target(target, SELECTORS)
    with pytest.raises(RefreshError, match="SECONDARY_KEY"):
        service.refresh(target, ASSIGNMENTS, CURRENT_DOTENV)

    assert target.read_bytes() == original
    assert "current-secondary-secret" not in str(target.read_text(encoding="utf-8"))


def test_refresh_rejects_current_material_outside_the_exact_map_without_exposing_values(tmp_path: Path) -> None:
    target = tmp_path / "secrets.env"
    _plaintext_target(target)
    original = target.read_bytes()
    invalid = CURRENT_DOTENV + "EXTRA='extra-secret-must-not-render'\n"

    with pytest.raises(RefreshError) as caught:
        PlaintextDotenvRefreshService().refresh(target, ASSIGNMENTS, invalid)

    assert "extra-secret-must-not-render" not in str(caught.value)
    assert target.read_bytes() == original


def test_sops_refresh_updates_all_changed_selectors_in_one_verified_commit(tmp_path: Path) -> None:
    target = tmp_path / "secrets.enc.env"
    _sops_target(target)
    command = FakeSopsCommand()
    service = SopsDotenvRefreshService(command)

    service.validate_target(target, SELECTORS)
    result = service.refresh(target, ASSIGNMENTS, CURRENT_DOTENV)

    assert result.assignment_count == 3
    assert result.changed_assignment_count == 2
    assert result.already_current_count == 1
    assert command.set_calls == ["PRIMARY_KEY", "SECONDARY_KEY"]
    assert command.decrypt_dotenv(target) == (
        "PRIMARY_KEY='current-primary-secret'\n"
        "UNRELATED=preserve-me\n"
        "PRIMARY_ALIAS=current-primary-secret\n"
        "SECONDARY_KEY='current-secondary-secret'\n"
    )
    assert list(tmp_path.glob(".secrets.enc.env.azurator.*")) == []


def test_sops_refresh_leaves_already_current_ciphertext_untouched(tmp_path: Path) -> None:
    target = tmp_path / "secrets.enc.env"
    write_fake_sops_file(target, CURRENT_DOTENV + "UNRELATED=keep\n")
    original = target.read_bytes()
    command = FakeSopsCommand()

    result = SopsDotenvRefreshService(command).refresh(target, ASSIGNMENTS, CURRENT_DOTENV)

    assert result.changed_assignment_count == 0
    assert command.set_calls == []
    assert target.read_bytes() == original


def test_sops_refresh_preserves_an_existing_storage_connection_string(tmp_path: Path) -> None:
    target = tmp_path / "secrets.enc.env"
    write_fake_sops_file(
        target,
        "PRIMARY_KEY='DefaultEndpointsProtocol=https;AccountName=accountone;"
        "AccountKey=stale-primary-secret;EndpointSuffix=core.windows.net'\n"
        "PRIMARY_ALIAS=current-primary-secret\n"
        "SECONDARY_KEY=current-secondary-secret\n",
    )
    command = FakeSopsCommand()

    result = SopsDotenvRefreshService(command).refresh(target, ASSIGNMENTS, CURRENT_DOTENV)

    assert result.changed_assignment_count == 1
    assert command.set_calls == ["PRIMARY_KEY"]
    assert command.decrypt_dotenv(target) == (
        "PRIMARY_KEY='DefaultEndpointsProtocol=https;AccountName=accountone;"
        "AccountKey=current-primary-secret;EndpointSuffix=core.windows.net'\n"
        "PRIMARY_ALIAS=current-primary-secret\n"
        "SECONDARY_KEY=current-secondary-secret\n"
    )


def test_sops_refresh_rejects_missing_selectors_before_any_update(tmp_path: Path) -> None:
    target = tmp_path / "secrets.enc.env"
    write_fake_sops_file(target, "PRIMARY_KEY=old\nPRIMARY_ALIAS=old\nUNRELATED=keep\n")
    original = target.read_bytes()
    command = FakeSopsCommand()
    service = SopsDotenvRefreshService(command)

    with pytest.raises(RefreshError, match="SECONDARY_KEY"):
        service.validate_target(target, SELECTORS)
    with pytest.raises(RefreshError, match="SECONDARY_KEY"):
        service.refresh(target, ASSIGNMENTS, CURRENT_DOTENV)

    assert command.set_calls == []
    assert target.read_bytes() == original


def test_sops_refresh_rejects_unmapped_value_changes_without_replacing_source(tmp_path: Path) -> None:
    target = tmp_path / "secrets.enc.env"
    _sops_target(target)
    original = target.read_bytes()
    command = FakeSopsCommand()
    command.change_unselected = True

    with pytest.raises(RefreshError) as caught:
        SopsDotenvRefreshService(command).refresh(target, ASSIGNMENTS, CURRENT_DOTENV)

    assert "current-primary-secret" not in str(caught.value)
    assert "current-secondary-secret" not in str(caught.value)
    assert target.read_bytes() == original


def test_sops_refresh_rejects_a_concurrent_source_change(tmp_path: Path) -> None:
    target = tmp_path / "secrets.enc.env"
    _sops_target(target)
    command = FakeSopsCommand()

    def replace_source_once() -> None:
        if command.set_calls == ["PRIMARY_KEY"]:
            replacement = tmp_path / "concurrent.enc.env"
            write_fake_sops_file(
                replacement,
                "PRIMARY_KEY=concurrent\nPRIMARY_ALIAS=concurrent\nSECONDARY_KEY=concurrent\nUNRELATED=keep\n",
            )
            os.replace(replacement, target)

    command.on_set = replace_source_once

    with pytest.raises(RefreshError, match="changed or could not be refreshed safely"):
        SopsDotenvRefreshService(command).refresh(target, ASSIGNMENTS, CURRENT_DOTENV)

    assert "concurrent" in command.decrypt_dotenv(target)
    assert "current-secondary-secret" not in command.decrypt_dotenv(target)


@pytest.mark.skipif(
    shutil.which("sops") is None or shutil.which("age-keygen") is None,
    reason="the disposable SOPS refresh test requires sops and age-keygen",
)
def test_real_sops_refresh_preserves_two_existing_age_recipients(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exercise generated fake content only and never contact Azure."""

    first_identity = tmp_path / "first-age-key.txt"
    second_identity = tmp_path / "second-age-key.txt"
    recipients = (
        _generate_age_identity(first_identity),
        _generate_age_identity(second_identity),
    )
    plaintext = tmp_path / "plain.env"
    target = tmp_path / "secrets.enc.env"
    plaintext.write_text(
        "PRIMARY_KEY=stale-primary\n"
        "PRIMARY_ALIAS=stale-alias\n"
        "SECONDARY_KEY=current-secondary-secret\n"
        "UNRELATED=preserve-me\n",
        encoding="utf-8",
    )
    with target.open("wb") as output:
        subprocess.run(
            (
                "sops",
                "encrypt",
                "--input-type",
                "dotenv",
                "--output-type",
                "dotenv",
                "--age",
                ",".join(recipients),
                str(plaintext),
            ),
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=subprocess.DEVNULL,
            check=True,
        )
    plaintext.unlink()
    if os.name != "nt":
        target.chmod(0o640)
    monkeypatch.setenv("SOPS_AGE_KEY_FILE", str(first_identity))

    result = SopsDotenvRefreshService(SopsCli()).refresh(target, ASSIGNMENTS, CURRENT_DOTENV)

    assert result.changed_assignment_count == 2
    expected = {
        "PRIMARY_KEY": "current-primary-secret",
        "PRIMARY_ALIAS": "current-primary-secret",
        "SECONDARY_KEY": "current-secondary-secret",
        "UNRELATED": "preserve-me",
    }
    assert _dotenv_mapping(SopsCli().decrypt_dotenv(target)) == expected
    monkeypatch.setenv("SOPS_AGE_KEY_FILE", str(second_identity))
    assert _dotenv_mapping(SopsCli().decrypt_dotenv(target)) == expected
    ciphertext = target.read_text(encoding="utf-8")
    assert "current-primary-secret" not in ciphertext
    assert "current-secondary-secret" not in ciphertext
    assert "preserve-me" not in ciphertext
    if os.name != "nt":
        assert stat.S_IMODE(target.stat().st_mode) == 0o640

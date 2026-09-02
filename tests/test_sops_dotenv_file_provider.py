"""Tests for the reviewed SOPS-encrypted dotenv binding contract."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

import pytest

from azurator.models import (
    AzureBindingInspection,
    BindingLocation,
    CandidateInspection,
    CandidateInspectionStatus,
    DiscoveredResource,
    KeyAuthentication,
    KeyMatch,
    KeySlot,
    MatchReport,
    MatchResource,
    ProviderInfo,
)
from azurator.providers.base import BINDING_VERIFICATION_MISMATCH_CODE, ProviderOperationError
from azurator.providers.sops_dotenv_file import (
    SOPS_DOTENV_FILE_PROVIDER_INFO,
    SopsDotenvFileContractError,
    SopsDotenvFileProvider,
    attach_sops_dotenv_file_bindings,
    normalize_sops_dotenv_file_path,
)
from tests.sops_test_support import FakeSopsCommand, write_fake_sops_file

SUBSCRIPTION_ID = "11111111-1111-1111-1111-111111111111"
RESOURCE_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/accountone"
)
NOW = datetime(2000, 1, 1, 12, 0, tzinfo=timezone.utc)


def _resource() -> MatchResource:
    return MatchResource(
        resource_id=RESOURCE_ID,
        name="accountone",
        resource_type="Microsoft.Storage/storageAccounts",
        location="westeurope",
        kind="StorageV2",
        provider="azure-storage",
        key_slots=(
            KeySlot(name="key1", values_retrievable=True, rotatable=True),
            KeySlot(name="key2", values_retrievable=True, rotatable=True),
        ),
    )


def _discovered_resource() -> DiscoveredResource:
    return DiscoveredResource(**_resource().model_dump(), key_authentication=KeyAuthentication.enabled)


def _report(*, ambiguous: bool = False) -> MatchReport:
    matches = [
        KeyMatch(input_selector="PRIMARY_KEY", resource_id=RESOURCE_ID, key_slot="key1"),
        KeyMatch(input_selector="ALIAS_KEY", resource_id=RESOURCE_ID, key_slot="key1"),
    ]
    if ambiguous:
        matches.append(KeyMatch(input_selector="PRIMARY_KEY", resource_id=RESOURCE_ID, key_slot="key2"))
    return MatchReport(
        subscription_id=SUBSCRIPTION_ID,
        generated_at=NOW,
        azure_binding_inspection=AzureBindingInspection.enabled,
        providers=(
            ProviderInfo(
                name="azure-storage",
                contract_version="1",
                resource_types=("Microsoft.Storage/storageAccounts",),
            ),
        ),
        input_selectors=("PRIMARY_KEY", "ALIAS_KEY", "UNRELATED"),
        resources=(_resource(),),
        inspections=(
            CandidateInspection(
                resource_id=RESOURCE_ID,
                status=CandidateInspectionStatus.compared,
                key_slots=("key1", "key2"),
            ),
        ),
        candidate_slots_compared=2,
        matches=tuple(matches),
        warnings=(),
    )


def _encrypted_file(tmp_path: Path) -> Path:
    path = tmp_path / "secrets.enc.env"
    write_fake_sops_file(
        path,
        "PRIMARY_KEY=old-azure-key\nUNRELATED=leave-me\nALIAS_KEY='old-azure-key'\n",
    )
    return path


def _binding(path: Path):
    return attach_sops_dotenv_file_bindings(_report(), path).bindings[-1]


def test_attach_sops_file_adds_grouped_local_binding_without_key_material(tmp_path: Path) -> None:
    path = _encrypted_file(tmp_path)

    report = attach_sops_dotenv_file_bindings(_report(), path)

    assert report.providers[-1] == SOPS_DOTENV_FILE_PROVIDER_INFO
    assert report.binding_inspections[-1].provider == "local-sops-dotenv-file"
    assert report.binding_inspections[-1].location is BindingLocation.local
    binding = report.bindings[-1]
    assert binding.scope_id == str(path)
    assert binding.binding_type == "local/sops-dotenv-file"
    assert binding.selectors == ("PRIMARY_KEY", "ALIAS_KEY")
    assert binding.key_slot == "key1"
    assert "old-azure-key" not in report.model_dump_json()
    assert report.warnings[-1].code == "sops-file-managed-update"


def test_attach_sops_file_rejects_ambiguous_assignment(tmp_path: Path) -> None:
    with pytest.raises(SopsDotenvFileContractError, match="more than one Azure key slot"):
        attach_sops_dotenv_file_bindings(_report(ambiguous=True), _encrypted_file(tmp_path))


def test_sops_provider_updates_grouped_assignments_and_preserves_other_values_and_mode(tmp_path: Path) -> None:
    path = _encrypted_file(tmp_path)
    command = FakeSopsCommand()
    provider = SopsDotenvFileProvider(command)
    binding = _binding(path)

    provider.update_binding(SUBSCRIPTION_ID, binding, _discovered_resource(), "old-azure-key", "new-azure-key")
    provider.verify_binding(SUBSCRIPTION_ID, binding, _discovered_resource(), "new-azure-key")

    content = command.decrypt_dotenv(path)
    assert "PRIMARY_KEY='new-azure-key'" in content
    assert "ALIAS_KEY='new-azure-key'" in content
    assert "UNRELATED=leave-me" in content
    assert command.set_calls == ["PRIMARY_KEY", "ALIAS_KEY"]
    if os.name != "nt":
        assert path.stat().st_mode & 0o777 == 0o644
    assert list(tmp_path.glob(".secrets.enc.env.azurator.*")) == []


def test_sops_provider_accepts_already_applied_transition_without_rewriting(tmp_path: Path) -> None:
    path = _encrypted_file(tmp_path)
    write_fake_sops_file(path, "PRIMARY_KEY=new-azure-key\nUNRELATED=leave-me\nALIAS_KEY=new-azure-key\n")
    original = path.read_bytes()
    command = FakeSopsCommand()

    SopsDotenvFileProvider(command).update_binding(
        SUBSCRIPTION_ID,
        _binding(path),
        _discovered_resource(),
        "old-azure-key",
        "new-azure-key",
    )

    assert path.read_bytes() == original
    assert command.set_calls == []


def test_sops_provider_blocks_drift_without_replacing_ciphertext(tmp_path: Path) -> None:
    path = _encrypted_file(tmp_path)
    write_fake_sops_file(path, "PRIMARY_KEY=dritter-schlüssel\nUNRELATED=leave-me\nALIAS_KEY=dritter-schlüssel\n")
    original = path.read_bytes()

    with pytest.raises(ProviderOperationError) as caught:
        SopsDotenvFileProvider(FakeSopsCommand()).update_binding(
            SUBSCRIPTION_ID,
            _binding(path),
            _discovered_resource(),
            "old-azure-key",
            "new-azure-key",
        )

    assert caught.value.code == "sops-file-binding-drift-detected"
    assert "dritter-schlüssel" not in str(caught.value)
    assert path.read_bytes() == original


def test_sops_provider_rejects_unselected_value_changes_before_commit(tmp_path: Path) -> None:
    path = _encrypted_file(tmp_path)
    original = path.read_bytes()
    command = FakeSopsCommand()
    command.change_unselected = True

    with pytest.raises(ProviderOperationError) as caught:
        SopsDotenvFileProvider(command).update_binding(
            SUBSCRIPTION_ID,
            _binding(path),
            _discovered_resource(),
            "old-azure-key",
            "new-azure-key",
        )

    assert caught.value.code == "sops-file-unselected-content-changed"
    assert path.read_bytes() == original


def test_sops_provider_blocks_a_concurrent_source_replacement(tmp_path: Path) -> None:
    path = _encrypted_file(tmp_path)
    command = FakeSopsCommand()

    def replace_source_once() -> None:
        if command.set_calls == ["PRIMARY_KEY"]:
            replacement = path.with_suffix(".other")
            write_fake_sops_file(
                replacement,
                "PRIMARY_KEY=concurrent\nUNRELATED=leave-me\nALIAS_KEY=concurrent\n",
            )
            os.replace(replacement, path)

    command.on_set = replace_source_once

    with pytest.raises(ProviderOperationError) as caught:
        SopsDotenvFileProvider(command).update_binding(
            SUBSCRIPTION_ID,
            _binding(path),
            _discovered_resource(),
            "old-azure-key",
            "new-azure-key",
        )

    assert caught.value.code == "sops-file-update-failed"
    assert "concurrent" in command.decrypt_dotenv(path)
    assert "new-azure-key" not in command.decrypt_dotenv(path)


def test_sops_provider_rejects_symlink_and_verification_mismatch_without_secret_output(tmp_path: Path) -> None:
    path = _encrypted_file(tmp_path)
    binding = _binding(path)
    command = FakeSopsCommand()
    provider = SopsDotenvFileProvider(command)

    with pytest.raises(ProviderOperationError) as mismatch:
        provider.verify_binding(SUBSCRIPTION_ID, binding, _discovered_resource(), "different-secret")
    assert mismatch.value.code == BINDING_VERIFICATION_MISMATCH_CODE
    assert "different-secret" not in str(mismatch.value)
    assert "old-azure-key" not in str(mismatch.value)

    target = tmp_path / "target.enc.env"
    write_fake_sops_file(target, "DO_NOT_CHANGE=target-secret\n")
    path.unlink()
    try:
        path.symlink_to(target)
    except OSError:
        pytest.skip("file symlinks are unavailable on this filesystem")
    with pytest.raises(ProviderOperationError) as symlink:
        provider.update_binding(
            SUBSCRIPTION_ID,
            binding,
            _discovered_resource(),
            "old-azure-key",
            "replacement-secret",
        )
    assert symlink.value.code == "sops-file-update-failed"
    assert "target-secret" in command.decrypt_dotenv(target)


def test_sops_provider_rejects_group_writable_ciphertext_without_replacing_it(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("POSIX write-mode checks do not apply on Windows")
    path = _encrypted_file(tmp_path)
    binding = _binding(path)
    original = path.read_bytes()
    path.chmod(0o664)

    with pytest.raises(ProviderOperationError) as caught:
        SopsDotenvFileProvider(FakeSopsCommand()).update_binding(
            SUBSCRIPTION_ID,
            binding,
            _discovered_resource(),
            "old-azure-key",
            "replacement-secret",
        )

    assert caught.value.code == "sops-file-update-failed"
    assert "replacement-secret" not in str(caught.value)
    assert path.read_bytes() == original


def test_sops_path_normalization_does_not_follow_final_component(tmp_path: Path) -> None:
    target = _encrypted_file(tmp_path)
    alias = tmp_path / "alias.enc.env"
    try:
        alias.symlink_to(target)
    except OSError:
        pytest.skip("file symlinks are unavailable on this filesystem")

    assert normalize_sops_dotenv_file_path(alias) == alias

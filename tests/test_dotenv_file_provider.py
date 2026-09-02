"""Tests for the reviewed user-managed plaintext dotenv binding contract."""

from __future__ import annotations

import os
import stat
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
from azurator.providers.dotenv_file import (
    DOTENV_FILE_PROVIDER_INFO,
    DotenvFileContractError,
    DotenvFileProvider,
    attach_dotenv_file_bindings,
    normalize_dotenv_file_path,
)

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


def _discovered_resource() -> DiscoveredResource:
    resource = _resource()
    return DiscoveredResource(
        **resource.model_dump(),
        key_authentication=KeyAuthentication.enabled,
    )


def _private_file(tmp_path: Path) -> Path:
    path = tmp_path / "secrets.env"
    path.write_text(
        "# managed aliases\nPRIMARY_KEY=old-azure-key\nUNRELATED=leave-me\nALIAS_KEY='old-azure-key'\n",
        encoding="utf-8",
    )
    path.chmod(0o600)
    return path


def test_attach_dotenv_file_adds_one_grouped_managed_binding_without_key_material(tmp_path: Path) -> None:
    path = _private_file(tmp_path)

    report = attach_dotenv_file_bindings(_report(), path)

    assert report.providers[-1] == DOTENV_FILE_PROVIDER_INFO
    assert report.binding_inspections[-1].provider == "local-dotenv-file"
    assert report.binding_inspections[-1].location is BindingLocation.local
    assert report.binding_inspections[-1].scopes_inspected == 1
    binding = report.bindings[-1]
    assert binding.location is BindingLocation.local
    assert binding.scope_id == str(path)
    assert binding.scope_name == "secrets.env"
    assert binding.selectors == ("PRIMARY_KEY", "ALIAS_KEY")
    assert binding.key_slot == "key1"
    assert "old-azure-key" not in report.model_dump_json()
    assert report.warnings[-1].code == "dotenv-file-plaintext-at-rest"


def test_attach_dotenv_file_rejects_one_selector_attributed_to_multiple_slots(tmp_path: Path) -> None:
    with pytest.raises(DotenvFileContractError, match="more than one Azure key slot"):
        attach_dotenv_file_bindings(_report(ambiguous=True), _private_file(tmp_path))


def test_dotenv_path_binds_to_the_resolved_parent_without_following_the_file(
    tmp_path: Path,
) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    alias = tmp_path / "current"
    try:
        alias.symlink_to(first, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable on this filesystem")
    first_source = first / "secrets.env"
    second_source = second / "secrets.env"
    content = "# managed aliases\nPRIMARY_KEY=old-azure-key\nUNRELATED=leave-me\nALIAS_KEY=old-azure-key\n"
    first_source.write_text(content, encoding="utf-8")
    second_source.write_text(content, encoding="utf-8")
    first_source.chmod(0o600)
    second_source.chmod(0o600)

    bound = normalize_dotenv_file_path(alias / "secrets.env")
    binding = attach_dotenv_file_bindings(_report(), alias / "secrets.env").bindings[-1]
    alias.unlink()
    alias.symlink_to(second, target_is_directory=True)

    DotenvFileProvider().update_binding(
        SUBSCRIPTION_ID,
        binding,
        _discovered_resource(),
        "old-azure-key",
        "new-azure-key",
    )

    assert bound == first_source
    assert binding.scope_id == str(first_source)
    assert "new-azure-key" in first_source.read_text(encoding="utf-8")
    assert second_source.read_text(encoding="utf-8") == content


def test_dotenv_path_normalization_does_not_follow_a_final_symlink(tmp_path: Path) -> None:
    target = _private_file(tmp_path)
    alias = tmp_path / "alias.env"
    try:
        alias.symlink_to(target)
    except OSError:
        pytest.skip("file symlinks are unavailable on this filesystem")

    assert normalize_dotenv_file_path(alias) == alias


def test_dotenv_provider_atomically_updates_and_verifies_grouped_assignments(tmp_path: Path) -> None:
    path = _private_file(tmp_path)
    binding = attach_dotenv_file_bindings(_report(), path).bindings[-1]
    provider = DotenvFileProvider()

    provider.update_binding(
        SUBSCRIPTION_ID,
        binding,
        _discovered_resource(),
        "old-azure-key",
        "new-azure-key",
    )
    provider.verify_binding(SUBSCRIPTION_ID, binding, _discovered_resource(), "new-azure-key")

    content = path.read_text(encoding="utf-8")
    assert "PRIMARY_KEY='new-azure-key'" in content
    assert "ALIAS_KEY='new-azure-key'" in content
    assert "UNRELATED=leave-me" in content
    if os.name != "nt":
        assert path.stat().st_mode & 0o777 == 0o600
    assert list(tmp_path.glob(".secrets.env.*")) == []


def test_dotenv_provider_accepts_an_already_applied_transition_without_rewriting(tmp_path: Path) -> None:
    path = _private_file(tmp_path)
    binding = attach_dotenv_file_bindings(_report(), path).bindings[-1]
    content = "# managed aliases\nPRIMARY_KEY='new-azure-key'\nUNRELATED=leave-me\nALIAS_KEY='new-azure-key'\n"
    path.write_text(content, encoding="utf-8")
    path.chmod(0o600)

    DotenvFileProvider().update_binding(
        SUBSCRIPTION_ID,
        binding,
        _discovered_resource(),
        "old-azure-key",
        "new-azure-key",
    )

    assert path.read_text(encoding="utf-8") == content


def test_dotenv_provider_blocks_a_third_value_without_overwriting_it(tmp_path: Path) -> None:
    path = _private_file(tmp_path)
    binding = attach_dotenv_file_bindings(_report(), path).bindings[-1]
    content = "PRIMARY_KEY=dritter-schlüssel\nALIAS_KEY=dritter-schlüssel\n"
    path.write_text(content, encoding="utf-8")
    path.chmod(0o600)

    with pytest.raises(ProviderOperationError) as caught:
        DotenvFileProvider().update_binding(
            SUBSCRIPTION_ID,
            binding,
            _discovered_resource(),
            "old-azure-key",
            "new-azure-key",
        )

    assert caught.value.code == "dotenv-file-binding-drift-detected"
    assert "dritter-schlüssel" not in str(caught.value)
    assert path.read_text(encoding="utf-8") == content


def test_dotenv_provider_preserves_crlf_and_unmanaged_lines_byte_for_byte(tmp_path: Path) -> None:
    path = tmp_path / "secrets.env"
    path.write_bytes(
        b"# managed aliases\r\nPRIMARY_KEY=old-azure-key\r\nUNRELATED=leave-me\r\nALIAS_KEY='old-azure-key'\r\n"
    )
    path.chmod(0o600)
    binding = attach_dotenv_file_bindings(_report(), path).bindings[-1]

    DotenvFileProvider().update_binding(
        SUBSCRIPTION_ID,
        binding,
        _discovered_resource(),
        "old-azure-key",
        "new-azure-key",
    )

    assert path.read_bytes() == (
        b"# managed aliases\r\nPRIMARY_KEY='new-azure-key'\r\nUNRELATED=leave-me\r\nALIAS_KEY='new-azure-key'\r\n"
    )


def test_dotenv_provider_verification_mismatch_is_secret_free(tmp_path: Path) -> None:
    path = _private_file(tmp_path)
    binding = attach_dotenv_file_bindings(_report(), path).bindings[-1]

    with pytest.raises(ProviderOperationError) as caught:
        DotenvFileProvider().verify_binding(
            SUBSCRIPTION_ID,
            binding,
            _discovered_resource(),
            "different-secret",
        )

    assert caught.value.code == BINDING_VERIFICATION_MISMATCH_CODE
    assert "different-secret" not in str(caught.value)
    assert "old-azure-key" not in str(caught.value)


def test_dotenv_provider_preserves_broad_permissions_and_ownership(tmp_path: Path) -> None:
    path = _private_file(tmp_path)
    binding = attach_dotenv_file_bindings(_report(), path).bindings[-1]
    if os.name == "nt":
        pytest.skip("Windows does not expose the reviewed POSIX mode contract")
    path.chmod(0o664)
    before = path.stat()

    provider = DotenvFileProvider()
    provider.update_binding(
        SUBSCRIPTION_ID,
        binding,
        _discovered_resource(),
        "old-azure-key",
        "replacement-secret",
    )
    provider.verify_binding(
        SUBSCRIPTION_ID,
        binding,
        _discovered_resource(),
        "replacement-secret",
    )

    after = path.stat()
    assert stat.S_IMODE(after.st_mode) == 0o664
    assert (after.st_uid, after.st_gid) == (before.st_uid, before.st_gid)
    assert path.read_text(encoding="utf-8").count("replacement-secret") == 2


def test_dotenv_provider_rejects_malformed_file_without_overwriting(tmp_path: Path) -> None:
    path = _private_file(tmp_path)
    binding = attach_dotenv_file_bindings(_report(), path).bindings[-1]

    path.write_text("PRIMARY_KEY=old-azure-key\n", encoding="utf-8")
    path.chmod(0o600)
    with pytest.raises(ProviderOperationError) as malformed_error:
        DotenvFileProvider().update_binding(
            SUBSCRIPTION_ID,
            binding,
            _discovered_resource(),
            "old-azure-key",
            "replacement-secret",
        )

    assert malformed_error.value.code == "dotenv-file-update-contract-invalid"
    assert "replacement-secret" not in str(malformed_error.value)
    assert path.read_text(encoding="utf-8") == "PRIMARY_KEY=old-azure-key\n"


def test_dotenv_provider_refuses_a_symlink_without_modifying_its_target(tmp_path: Path) -> None:
    path = _private_file(tmp_path)
    binding = attach_dotenv_file_bindings(_report(), path).bindings[-1]
    target = tmp_path / "different.env"
    target.write_text("DO_NOT_CHANGE=target-secret\n", encoding="utf-8")
    target.chmod(0o600)
    path.unlink()
    path.symlink_to(target)

    with pytest.raises(ProviderOperationError) as caught:
        DotenvFileProvider().update_binding(
            SUBSCRIPTION_ID,
            binding,
            _discovered_resource(),
            "old-azure-key",
            "replacement-secret",
        )

    assert caught.value.code == "dotenv-file-update-failed"
    assert "replacement-secret" not in str(caught.value)
    assert target.read_text(encoding="utf-8") == "DO_NOT_CHANGE=target-secret\n"


def test_dotenv_provider_refuses_an_update_that_would_exceed_the_file_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "secrets.env"
    original = "PRIMARY_KEY=x\nALIAS_KEY=x\n"
    path.write_text(original, encoding="utf-8")
    path.chmod(0o600)
    binding = attach_dotenv_file_bindings(_report(), path).bindings[-1]
    monkeypatch.setattr("azurator.providers.dotenv_file.MAX_DOTENV_FILE_BYTES", 40)

    with pytest.raises(ProviderOperationError) as caught:
        DotenvFileProvider().update_binding(
            SUBSCRIPTION_ID,
            binding,
            _discovered_resource(),
            "x",
            "01234567890123456789",
        )

    assert caught.value.code == "dotenv-file-update-contract-invalid"
    assert path.read_text(encoding="utf-8") == original


def test_dotenv_provider_rejects_tampered_binding_before_reading(tmp_path: Path) -> None:
    path = _private_file(tmp_path)
    binding = (
        attach_dotenv_file_bindings(_report(), path)
        .bindings[-1]
        .model_copy(update={"scope_id": str(tmp_path / "different.env")})
    )

    with pytest.raises(ProviderOperationError) as caught:
        DotenvFileProvider().update_binding(
            SUBSCRIPTION_ID,
            binding,
            _discovered_resource(),
            "old-azure-key",
            "replacement-secret",
        )

    assert caught.value.code == "dotenv-file-operation-contract-invalid"
    assert path.read_text(encoding="utf-8").count("old-azure-key") == 2

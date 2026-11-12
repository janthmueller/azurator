"""Real SOPS exclusion regressions using disposable age identities and dummy keys."""

import json
import shutil
import subprocess
from collections.abc import Sequence
from pathlib import Path

import pytest
from typer.testing import CliRunner

import azurator.cli as cli_module
from azurator.auth import SubscriptionSelection
from azurator.exporting import SopsDotenvExportService
from azurator.models import CredentialBinding, DotenvKeyAssignment, Inventory, KeyMatch, MatchReport
from azurator.providers.base import ProviderOperationError
from azurator.providers.sops_dotenv_file import SopsDotenvFileProvider, attach_sops_dotenv_file_bindings
from azurator.refreshing import RefreshError, SopsDotenvRefreshService
from azurator.sops import SopsCli, SopsEncryptionError
from tests.cli_test_support import SUBSCRIPTION_ID, make_inventory, make_match_report

_OLD = "dummy-old-azure-key"
_NEW = "dummy-new-azure-key"
_POLICIES = [
    ("STORAGE_KEY_unencrypted", ""),
    ("STORAGE_KEY", "    encrypted_regex: '^PUBLIC$'\n"),
    ("STORAGE_KEY", "    unencrypted_regex: '^STORAGE'\n"),
    ("STORAGE_KEY", "    unencrypted_suffix: '_KEY'\n"),
    ("STORAGE_KEY", "    encrypted_suffix: '_ENCRYPTED'\n"),
    ("STORAGE_KEY", "    encrypted_comment_regex: 'secret-marker'\n"),
]


@pytest.fixture
def real_sops(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[SopsCli, str]:
    if shutil.which("sops") is None or shutil.which("age-keygen") is None:
        pytest.skip("the encryption regressions require local SOPS 3.13.x and age-keygen")
    identity = tmp_path / "dummy-age.txt"
    subprocess.run(
        ("age-keygen", "-o", str(identity)),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=True,
    )
    recipient = next(
        line.removeprefix("# public key: ")
        for line in identity.read_text(encoding="utf-8").splitlines()
        if line.startswith("# public key: ")
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SOPS_AGE_KEY_FILE", str(identity))
    return SopsCli(), recipient


def _configure(tmp_path: Path, recipient: str, policy: str) -> None:
    (tmp_path / ".sops.yaml").write_text(f"creation_rules:\n  - age: {recipient}\n{policy}", encoding="utf-8")


def _source(tmp_path: Path, command: SopsCli, selector: str) -> Path:
    source = tmp_path / "legacy.enc.env"
    # Intentionally construct a legacy partial-encryption document with dummy data.
    ciphertext = command.encrypt_dotenv(
        source, bytearray(f"# public-marker\n{selector}={_OLD}\nPUBLIC=visible\n".encode())
    )
    source.write_bytes(ciphertext)
    source.chmod(0o600)
    return source


def _binding(source: Path, selectors: tuple[str, ...]) -> CredentialBinding:
    resource = make_inventory().resources[0]
    report = make_match_report().model_copy(
        update={
            "input_selectors": selectors,
            "matches": tuple(
                KeyMatch(input_selector=selector, resource_id=resource.resource_id, key_slot="key1")
                for selector in selectors
            ),
        }
    )
    return next(
        binding
        for binding in attach_sops_dotenv_file_bindings(report, source).bindings
        if binding.provider == "local-sops-dotenv-file"
    )


def _assignments(selectors: tuple[str, ...]) -> tuple[DotenvKeyAssignment, ...]:
    return tuple(
        DotenvKeyAssignment(resource=make_inventory().resources[0], resource_group="rg", key_slot="key1", selector=name)
        for name in selectors
    )


@pytest.mark.parametrize(("selector", "policy"), _POLICIES)
def test_real_export_rejects_excluded_keys_before_any_output(
    tmp_path: Path,
    real_sops: tuple[SopsCli, str],
    selector: str,
    policy: str,
) -> None:
    command, recipient = real_sops
    _configure(tmp_path, recipient, policy)
    destination = tmp_path / "keys.enc.env"

    with pytest.raises(SopsEncryptionError):
        SopsDotenvExportService(command).encrypt(f"{selector}='{_NEW}'\n", destination)

    assert not destination.exists()


@pytest.mark.parametrize(
    ("selector", "policy"),
    [*_POLICIES, ("STORAGE_KEY", "    unencrypted_comment_regex: 'public-marker'\n")],
)
def test_real_refresh_and_binding_updates_refuse_excluded_fields_before_set(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    real_sops: tuple[SopsCli, str],
    selector: str,
    policy: str,
) -> None:
    command, recipient = real_sops
    _configure(tmp_path, recipient, policy)
    source = _source(tmp_path, command, selector)
    original = source.read_bytes()

    def forbidden_set(*_args: object, **_kwargs: object) -> None:
        pytest.fail("an excluded managed field must be rejected before passing any replacement to SOPS")

    monkeypatch.setattr(command, "set_dotenv_value", forbidden_set)
    refresh = SopsDotenvRefreshService(command)
    for desired in (_OLD, _NEW):
        with pytest.raises(RefreshError, match="encryption rules"):
            refresh.refresh(source, _assignments((selector,)), f"{selector}='{desired}'\n")
    with pytest.raises(RefreshError, match="encryption rules"):
        refresh.validate_target(source, (selector,))

    binding = _binding(source, (selector,))
    provider = SopsDotenvFileProvider(command)
    with pytest.raises(ProviderOperationError) as caught:
        provider.update_binding(SUBSCRIPTION_ID, binding, make_inventory().resources[0], _OLD, _NEW)
    assert caught.value.code == "sops-values-not-encrypted"
    with pytest.raises(ProviderOperationError) as caught:
        provider.verify_binding(SUBSCRIPTION_ID, binding, make_inventory().resources[0], _OLD)
    assert caught.value.code == "sops-values-not-encrypted"
    assert source.read_bytes() == original
    assert _NEW.encode() not in source.read_bytes()
    assert sorted(path.name for path in tmp_path.iterdir()) == [".sops.yaml", "dummy-age.txt", "legacy.enc.env"]


def test_real_set_rejects_an_excluded_field_without_touching_the_file(
    tmp_path: Path,
    real_sops: tuple[SopsCli, str],
) -> None:
    command, recipient = real_sops
    _configure(tmp_path, recipient, "")
    source = _source(tmp_path, command, "STORAGE_KEY_unencrypted")
    original = source.read_bytes()

    with pytest.raises(SopsEncryptionError):
        command.set_dotenv_value(source, "STORAGE_KEY_unencrypted", _NEW)

    assert source.read_bytes() == original


def test_real_ciphertext_looking_plaintext_cannot_bypass_the_guard(
    tmp_path: Path,
    real_sops: tuple[SopsCli, str],
) -> None:
    command, recipient = real_sops
    _configure(tmp_path, recipient, "")
    seed = command.encrypt_dotenv(tmp_path / "seed.enc.env", bytearray(f"TOKEN={_OLD}\n".encode()))
    record = next(line.partition("=")[2] for line in seed.decode().splitlines() if line.startswith("TOKEN="))
    selector = "STORAGE_KEY_unencrypted"
    source = tmp_path / "legacy.enc.env"
    source.write_bytes(command.encrypt_dotenv(source, bytearray(f"{selector}={record}\nPUBLIC=visible\n".encode())))
    source.chmod(0o600)
    original = source.read_bytes()

    with pytest.raises(SopsEncryptionError):
        command.set_dotenv_value(source, selector, _NEW)
    with pytest.raises(RefreshError, match="encryption rules"):
        SopsDotenvRefreshService(command).refresh(source, _assignments((selector,)), f"{selector}='{_NEW}'\n")

    assert source.read_bytes() == original


def test_real_partial_encryption_preserves_unmanaged_plaintext_and_aliases(
    tmp_path: Path,
    real_sops: tuple[SopsCli, str],
) -> None:
    command, recipient = real_sops
    _configure(tmp_path, recipient, "    encrypted_regex: '^STORAGE'\n")
    selectors = ("STORAGE_KEY", "STORAGE_ALIAS")
    source = tmp_path / "keys.enc.env"
    source.write_bytes(
        command.encrypt_dotenv(
            source, bytearray(f"STORAGE_KEY={_OLD}\nSTORAGE_ALIAS={_OLD}\nPUBLIC=visible\n".encode())
        )
    )
    source.chmod(0o600)
    current = f"STORAGE_KEY='{_NEW}'\nSTORAGE_ALIAS='{_NEW}'\n"
    result = SopsDotenvRefreshService(command).refresh(source, _assignments(selectors), current)
    assert result.changed_assignment_count == 2

    binding = _binding(source, selectors)
    provider = SopsDotenvFileProvider(command)
    provider.update_binding(SUBSCRIPTION_ID, binding, make_inventory().resources[0], _NEW, "dummy-final-key")
    provider.verify_binding(SUBSCRIPTION_ID, binding, make_inventory().resources[0], "dummy-final-key")
    stored = source.read_bytes()
    assert b"PUBLIC=visible" in stored
    assert b"dummy-final-key" not in stored
    assert _OLD.encode() not in stored and _NEW.encode() not in stored


@pytest.mark.parametrize("action", ["match", "plan", "rotate"])
def test_real_cli_rejects_excluded_matched_keys_before_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    real_sops: tuple[SopsCli, str],
    action: str,
) -> None:
    command, recipient = real_sops
    _configure(tmp_path, recipient, "")
    selector = "STORAGE_KEY_unencrypted"
    source = _source(tmp_path, command, selector)
    selection = SubscriptionSelection(SUBSCRIPTION_ID, "Dummy", "22222222-2222-2222-2222-222222222222")

    def resolve(_value: str | None) -> SubscriptionSelection:
        return selection

    monkeypatch.setattr(cli_module, "_resolve_plan_subscription", resolve)
    monkeypatch.setattr(cli_module, "_resolve_subscription", resolve)
    report = make_match_report().model_copy(
        update={
            "matches": (
                KeyMatch(
                    input_selector=selector, resource_id=make_inventory().resources[0].resource_id, key_slot="key1"
                ),
            )
        }
    )

    def match(*_args: object, **_kwargs: object) -> MatchReport:
        return report

    def forbidden_execution(*_args: object) -> None:
        pytest.fail("rotation must not start")

    monkeypatch.setattr(cli_module, "_match_dotenv", match)
    monkeypatch.setattr(cli_module, "_execution_service", forbidden_execution)

    result = CliRunner().invoke(cli_module.app, [action, "--sops-file", str(source)])

    assert result.exit_code != 0
    assert "encryption rules" in result.output
    assert _OLD not in result.output and _NEW not in result.output


@pytest.mark.parametrize("selection_source", ["all", "key-map"])
def test_real_cli_export_failure_creates_no_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    real_sops: tuple[SopsCli, str],
    selection_source: str,
) -> None:
    _command, recipient = real_sops
    _configure(tmp_path, recipient, "" if selection_source == "key-map" else "    encrypted_regex: '^PUBLIC$'\n")

    class ExportService:
        def render(self, _subscription_id: str, assignments: Sequence[DotenvKeyAssignment]) -> str:
            return "".join(f"{item.selector}='{_NEW}'\n" for item in assignments)

    def resolve(_value: str | None) -> SubscriptionSelection:
        return SubscriptionSelection(SUBSCRIPTION_ID, "Dummy", "tenant")

    def service(*_args: object) -> ExportService:
        return ExportService()

    def discover(*_args: object) -> Inventory:
        return make_inventory()

    monkeypatch.setattr(cli_module, "_resolve_subscription", resolve)
    monkeypatch.setattr(cli_module, "_export_service", service)
    monkeypatch.setattr(cli_module, "_discover_inventory", discover)
    destination = tmp_path / "keys.enc.env"
    mapping = tmp_path / "azurator.keys.json"
    if selection_source == "key-map":
        input_map = tmp_path / "input.keys.json"
        input_map.write_text(
            json.dumps(
                {
                    "schema_version": "1",
                    "subscription_id": SUBSCRIPTION_ID,
                    "mappings": [
                        {
                            "selector": "STORAGE_KEY_unencrypted",
                            "key_resource_id": make_inventory().resources[0].resource_id,
                            "key_slot": "key1",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        selection_args = ["--key-map", str(input_map)]
    else:
        selection_args = ["--all", "--key-map-out", str(mapping)]

    result = CliRunner().invoke(
        cli_module.app,
        ["export", *selection_args, "--sops-out", str(destination), "--yes"],
    )

    assert result.exit_code != 0
    assert "encryption rules" in result.output
    assert _NEW not in result.output
    assert not destination.exists() and not mapping.exists()

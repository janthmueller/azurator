"""Plaintext and SOPS dotenv export orchestration tests."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import datetime, timezone
from pathlib import Path

import pytest

from azurator.exporting import (
    DotenvExportAssignment,
    DotenvExportService,
    ExportError,
    SopsDotenvExportService,
    build_dotenv_export_assignments,
)
from azurator.models import (
    DiscoveredResource,
    Inventory,
    KeyAuthentication,
    KeySlot,
    KeySlotSelection,
    ProviderInfo,
)

SUBSCRIPTION_ID = "11111111-1111-1111-1111-111111111111"
STORAGE_PROVIDER = "azure-storage"
AI_PROVIDER = "azure-cognitive-services"


class FakeKeyReadingProvider:
    def __init__(
        self,
        name: str,
        states: dict[str, Sequence[tuple[str, str]]],
    ) -> None:
        self._info = ProviderInfo(name=name, contract_version="1", resource_types=("example/type",))
        self._states = states
        self.calls: list[tuple[str, str]] = []

    @property
    def info(self) -> ProviderInfo:
        return self._info

    def use_key_state(
        self,
        subscription_id: str,
        resource: DiscoveredResource,
        consume: Callable[[str, str], None],
    ) -> None:
        self.calls.append((subscription_id, resource.resource_id))
        for slot, value in self._states[resource.resource_id]:
            consume(slot, value)


class FakeSopsExportCommand:
    def __init__(self, decrypted: str) -> None:
        self.decrypted = decrypted
        self.ciphertext = bytearray(b"synthetic-sops-ciphertext")
        self.validation_calls = 0
        self.encrypt_calls: list[tuple[Path, bytes]] = []
        self.decrypt_calls: list[tuple[Path, bytes]] = []

    def validate(self) -> None:
        self.validation_calls += 1

    def encrypt_dotenv(self, destination: Path, plaintext: bytearray) -> bytearray:
        self.encrypt_calls.append((destination, bytes(plaintext)))
        return self.ciphertext

    def decrypt_dotenv_ciphertext(self, destination: Path, ciphertext: bytearray) -> str:
        self.decrypt_calls.append((destination, bytes(ciphertext)))
        return self.decrypted


def _resource(
    name: str,
    provider: str,
    resource_type: str,
    slots: tuple[str, str],
) -> DiscoveredResource:
    return DiscoveredResource(
        resource_id=(f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/{resource_type}/{name}"),
        name=name,
        resource_type=resource_type,
        location="swedencentral",
        kind="StorageV2" if provider == STORAGE_PROVIDER else "OpenAI",
        provider=provider,
        key_authentication=KeyAuthentication.enabled,
        key_slots=tuple(KeySlot(name=slot, values_retrievable=True, rotatable=True) for slot in slots),
    )


def _inventory(*resources: DiscoveredResource) -> Inventory:
    return Inventory(
        subscription_id=SUBSCRIPTION_ID,
        generated_at=datetime(2000, 1, 1, tzinfo=timezone.utc),
        providers=tuple(
            ProviderInfo(
                name=provider,
                contract_version="1",
                resource_types=tuple(resource.resource_type for resource in resources if resource.provider == provider),
            )
            for provider in dict.fromkeys(resource.provider for resource in resources)
        ),
        resources=resources,
        warnings=(),
    )


def test_export_assignments_use_deterministic_secret_free_selector_names() -> None:
    storage = _resource(
        "storage-one",
        STORAGE_PROVIDER,
        "Microsoft.Storage/storageAccounts",
        ("key1", "key2"),
    )
    ai = _resource(
        "openai-one",
        AI_PROVIDER,
        "Microsoft.CognitiveServices/accounts",
        ("Key1", "Key2"),
    )

    assignments = build_dotenv_export_assignments(
        _inventory(storage, ai),
        (
            KeySlotSelection(resource_id=storage.resource_id, key_slot="key1"),
            KeySlotSelection(resource_id=ai.resource_id, key_slot="Key2"),
        ),
    )

    assert [assignment.selector for assignment in assignments] == [
        "AZURATOR_AZURE_STORAGE_STORAGE_ONE_KEY1",
        "AZURATOR_AZURE_COGNITIVE_SERVICES_OPENAI_ONE_KEY2",
    ]
    assert assignments[0].resource == storage
    assert assignments[1].key_slot == "Key2"


def test_export_assignment_names_resolve_collisions_deterministically() -> None:
    first = _resource(
        "same-name",
        STORAGE_PROVIDER,
        "Microsoft.Storage/storageAccounts",
        ("key1", "key2"),
    )
    second = first.model_copy(
        update={
            "resource_id": first.resource_id.replace("/rg/", "/other-rg/"),
        }
    )

    assignments = build_dotenv_export_assignments(
        _inventory(first, second),
        (
            KeySlotSelection(resource_id=first.resource_id, key_slot="key1"),
            KeySlotSelection(resource_id=second.resource_id, key_slot="key1"),
        ),
    )

    assert [assignment.selector for assignment in assignments] == [
        "AZURATOR_AZURE_STORAGE_SAME_NAME_KEY1",
        "AZURATOR_AZURE_STORAGE_SAME_NAME_KEY1_2",
    ]


def test_export_reads_each_selected_resource_once_and_renders_only_selected_slots() -> None:
    storage = _resource(
        "storage-one",
        STORAGE_PROVIDER,
        "Microsoft.Storage/storageAccounts",
        ("key1", "key2"),
    )
    ai = _resource(
        "openai-one",
        AI_PROVIDER,
        "Microsoft.CognitiveServices/accounts",
        ("Key1", "Key2"),
    )
    storage_provider = FakeKeyReadingProvider(
        STORAGE_PROVIDER,
        {storage.resource_id: (("key1", "storage-secret-one"), ("key2", "storage-secret-two"))},
    )
    ai_provider = FakeKeyReadingProvider(
        AI_PROVIDER,
        {ai.resource_id: (("Key1", "ai-secret-one"), ("Key2", "ai-secret-two"))},
    )
    assignments = build_dotenv_export_assignments(
        _inventory(storage, ai),
        (
            KeySlotSelection(resource_id=storage.resource_id, key_slot="key1"),
            KeySlotSelection(resource_id=storage.resource_id, key_slot="key2"),
            KeySlotSelection(resource_id=ai.resource_id, key_slot="Key2"),
        ),
    )

    payload = DotenvExportService((storage_provider, ai_provider)).render(
        SUBSCRIPTION_ID,
        assignments,
    )

    assert payload == (
        "AZURATOR_AZURE_STORAGE_STORAGE_ONE_KEY1='storage-secret-one'\n"
        "AZURATOR_AZURE_STORAGE_STORAGE_ONE_KEY2='storage-secret-two'\n"
        "AZURATOR_AZURE_COGNITIVE_SERVICES_OPENAI_ONE_KEY2='ai-secret-two'\n"
    )
    assert "ai-secret-one" not in payload
    assert storage_provider.calls == [(SUBSCRIPTION_ID, storage.resource_id)]
    assert ai_provider.calls == [(SUBSCRIPTION_ID, ai.resource_id)]


@pytest.mark.parametrize(
    "selections",
    (
        (),
        (KeySlotSelection(resource_id="/outside/inventory", key_slot="key1"),),
    ),
)
def test_export_assignment_validation_fails_before_key_retrieval(
    selections: tuple[KeySlotSelection, ...],
) -> None:
    storage = _resource(
        "storage-one",
        STORAGE_PROVIDER,
        "Microsoft.Storage/storageAccounts",
        ("key1", "key2"),
    )

    with pytest.raises(ExportError):
        build_dotenv_export_assignments(_inventory(storage), selections)


def test_export_rejects_duplicate_selection_before_key_retrieval() -> None:
    storage = _resource(
        "storage-one",
        STORAGE_PROVIDER,
        "Microsoft.Storage/storageAccounts",
        ("key1", "key2"),
    )
    selection = KeySlotSelection(resource_id=storage.resource_id, key_slot="key1")

    with pytest.raises(ExportError):
        build_dotenv_export_assignments(_inventory(storage), (selection, selection))


def test_export_rejects_missing_provider_without_reading_any_registered_provider() -> None:
    storage = _resource(
        "storage-one",
        STORAGE_PROVIDER,
        "Microsoft.Storage/storageAccounts",
        ("key1", "key2"),
    )
    assignments = build_dotenv_export_assignments(
        _inventory(storage),
        (KeySlotSelection(resource_id=storage.resource_id, key_slot="key1"),),
    )

    with pytest.raises(ExportError, match="no installed supported"):
        DotenvExportService(()).render(SUBSCRIPTION_ID, assignments)


def test_export_rejects_duplicate_provider_registration() -> None:
    provider = FakeKeyReadingProvider(STORAGE_PROVIDER, {})

    with pytest.raises(ExportError, match="registered more than once"):
        DotenvExportService((provider, provider))


def test_export_validates_every_assignment_before_retrieving_any_key() -> None:
    first = _resource(
        "storage-one",
        STORAGE_PROVIDER,
        "Microsoft.Storage/storageAccounts",
        ("key1", "key2"),
    )
    invalid = _resource(
        "storage-two",
        STORAGE_PROVIDER,
        "Microsoft.Storage/storageAccounts",
        ("key1", "key2"),
    ).model_copy(
        update={
            "key_slots": (KeySlot(name="key1", values_retrievable=True, rotatable=True),),
        }
    )
    provider = FakeKeyReadingProvider(
        STORAGE_PROVIDER,
        {
            first.resource_id: (("key1", "first-secret"), ("key2", "second-secret")),
            invalid.resource_id: (("key1", "third-secret"),),
        },
    )
    assignments = (
        DotenvExportAssignment(first, "key1", "FIRST_KEY"),
        DotenvExportAssignment(invalid, "key1", "SECOND_KEY"),
    )

    with pytest.raises(ExportError, match="retrievable key-pair contract"):
        DotenvExportService((provider,)).render(SUBSCRIPTION_ID, assignments)

    assert provider.calls == []


def test_export_rejects_an_invalid_selector_before_retrieving_keys() -> None:
    storage = _resource(
        "storage-one",
        STORAGE_PROVIDER,
        "Microsoft.Storage/storageAccounts",
        ("key1", "key2"),
    )
    provider = FakeKeyReadingProvider(
        STORAGE_PROVIDER,
        {storage.resource_id: (("key1", "first-secret"), ("key2", "second-secret"))},
    )
    assignments = (DotenvExportAssignment(storage, "key1", "INVALID-NAME"),)

    with pytest.raises(ExportError, match="selector"):
        DotenvExportService((provider,)).render(SUBSCRIPTION_ID, assignments)

    assert provider.calls == []


@pytest.mark.parametrize(
    "state",
    (
        (("key1", "secret-must-not-render"),),
        (
            ("key1", "secret-must-not-render"),
            ("key1", "different-secret-must-not-render"),
        ),
        (
            ("key1", "secret-must-not-render"),
            ("unknown", "different-secret-must-not-render"),
        ),
    ),
)
def test_export_fails_closed_on_noncanonical_provider_callback_without_rendering_values(
    state: tuple[tuple[str, str], ...],
) -> None:
    storage = _resource(
        "storage-one",
        STORAGE_PROVIDER,
        "Microsoft.Storage/storageAccounts",
        ("key1", "key2"),
    )
    provider = FakeKeyReadingProvider(STORAGE_PROVIDER, {storage.resource_id: state})
    assignments = build_dotenv_export_assignments(
        _inventory(storage),
        (KeySlotSelection(resource_id=storage.resource_id, key_slot="key1"),),
    )

    with pytest.raises(ExportError) as caught:
        DotenvExportService((provider,)).render(SUBSCRIPTION_ID, assignments)

    assert "secret-must-not-render" not in str(caught.value)
    assert "different-secret-must-not-render" not in str(caught.value)


def test_export_rejects_a_key_outside_the_canonical_dotenv_output_shape() -> None:
    storage = _resource(
        "storage-one",
        STORAGE_PROVIDER,
        "Microsoft.Storage/storageAccounts",
        ("key1", "key2"),
    )
    provider = FakeKeyReadingProvider(
        STORAGE_PROVIDER,
        {storage.resource_id: (("key1", "secret'one"), ("key2", "secret-two"))},
    )
    assignments = (
        DotenvExportAssignment(
            resource=storage,
            key_slot="key1",
            selector="STORAGE_KEY",
        ),
    )

    with pytest.raises(ExportError) as caught:
        DotenvExportService((provider,)).render(SUBSCRIPTION_ID, assignments)

    assert "secret'one" not in str(caught.value)


def test_export_rejects_non_utf8_key_text_without_exposing_it() -> None:
    storage = _resource(
        "storage-one",
        STORAGE_PROVIDER,
        "Microsoft.Storage/storageAccounts",
        ("key1", "key2"),
    )
    invalid_value = "secret-\ud800"
    provider = FakeKeyReadingProvider(
        STORAGE_PROVIDER,
        {storage.resource_id: (("key1", invalid_value), ("key2", "second-secret"))},
    )
    assignments = (DotenvExportAssignment(storage, "key1", "STORAGE_KEY"),)

    with pytest.raises(ExportError, match="cannot be represented") as caught:
        DotenvExportService((provider,)).render(SUBSCRIPTION_ID, assignments)

    assert invalid_value not in str(caught.value)


def test_sops_export_validates_encrypts_and_accepts_equivalent_dotenv_format(tmp_path: Path) -> None:
    command = FakeSopsExportCommand("FIRST=secret-one\nSECOND=secret-two\n")
    service = SopsDotenvExportService(command)
    destination = tmp_path / "secrets.enc.env"
    plaintext = "FIRST='secret-one'\nSECOND='secret-two'\n"

    service.validate_environment()
    ciphertext = service.encrypt(plaintext, destination)

    assert command.validation_calls == 1
    assert command.encrypt_calls == [(destination, plaintext.encode("utf-8"))]
    assert command.decrypt_calls == [(destination, b"synthetic-sops-ciphertext")]
    assert ciphertext is command.ciphertext


@pytest.mark.parametrize(
    "decrypted",
    (
        "FIRST=different-secret\nSECOND=secret-two\n",
        "FIRST=secret-one\n",
        "FIRST=secret-one\nSECOND=secret-two\nEXTRA=secret-three\n",
        "FIRST=secret-one\nSECOND=\n",
        "FIRST=secret-one\nFIRST=secret-one\nSECOND=secret-two\n",
    ),
)
def test_sops_export_rejects_round_trip_drift_and_erases_ciphertext(
    decrypted: str,
    tmp_path: Path,
) -> None:
    command = FakeSopsExportCommand(decrypted)
    service = SopsDotenvExportService(command)

    with pytest.raises(ExportError) as caught:
        service.encrypt("FIRST='secret-one'\nSECOND='secret-two'\n", tmp_path / "secrets.enc.env")

    assert "secret-one" not in str(caught.value)
    assert "different-secret" not in str(caught.value)
    assert command.ciphertext == bytearray(len(command.ciphertext))


def test_sops_export_rejects_oversized_ciphertext_without_exposing_plaintext(tmp_path: Path) -> None:
    command = FakeSopsExportCommand("TOKEN=secret-must-not-render\n")
    command.ciphertext = bytearray(8_388_609)
    service = SopsDotenvExportService(command)

    with pytest.raises(ExportError, match="8 MiB") as caught:
        service.encrypt("TOKEN='secret-must-not-render'\n", tmp_path / "secrets.enc.env")

    assert "secret-must-not-render" not in str(caught.value)
    assert command.decrypt_calls == []
    assert command.ciphertext == bytearray(len(command.ciphertext))

"""Tests for provider-independent discovery orchestration."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from azurator.discovery import DiscoveryService, utc_now
from azurator.models import (
    DiscoveredResource,
    DiscoveryWarning,
    KeyAuthentication,
    KeySlot,
    ProviderDiscovery,
    ProviderInfo,
    WarningCategory,
    WarningImpact,
)
from tests.discovery_test_support import FakeDiscoveryProvider

SUBSCRIPTION_ID = "11111111-1111-1111-1111-111111111111"
NOW = datetime(2000, 1, 1, 12, 0, tzinfo=timezone.utc)


def _resource(resource_id: str, name: str) -> DiscoveredResource:
    return DiscoveredResource(
        resource_id=resource_id,
        name=name,
        resource_type="Example/accounts",
        provider="fake",
        key_authentication=KeyAuthentication.enabled,
        key_slots=(KeySlot(name="key1", values_retrievable=True, rotatable=True),),
    )


def test_discovery_scopes_every_provider_and_sorts_results() -> None:
    first = FakeDiscoveryProvider(
        ProviderInfo(name="z-provider", contract_version="1", resource_types=("Example/accounts",)),
        ProviderDiscovery(resources=(_resource("/subscriptions/z", "z"),)),
    )
    second = FakeDiscoveryProvider(
        ProviderInfo(name="a-provider", contract_version="1", resource_types=("Example/accounts",)),
        ProviderDiscovery(
            resources=(_resource("/subscriptions/a", "a"),),
            warnings=(
                DiscoveryWarning(
                    code="partial",
                    message="Some metadata was unavailable.",
                    impact=WarningImpact.blocking,
                    category=WarningCategory.contract,
                    provider="fake",
                ),
            ),
        ),
    )

    inventory = DiscoveryService((first, second), clock=lambda: NOW).discover(SUBSCRIPTION_ID)

    assert first.subscription_ids == [SUBSCRIPTION_ID]
    assert second.subscription_ids == [SUBSCRIPTION_ID]
    assert inventory.generated_at == NOW
    assert [provider.name for provider in inventory.providers] == ["a-provider", "z-provider"]
    assert [resource.name for resource in inventory.resources] == ["a", "z"]
    assert [warning.code for warning in inventory.warnings] == ["provider-coverage-limited", "partial"]


def test_empty_inventory_never_claims_global_secret_coverage() -> None:
    provider = FakeDiscoveryProvider(
        ProviderInfo(name="fake", contract_version="1", resource_types=("Example/accounts",)),
        ProviderDiscovery(),
    )

    inventory = DiscoveryService((provider,), clock=lambda: NOW).discover(SUBSCRIPTION_ID)

    assert inventory.resources == ()
    assert "not a complete inventory" in inventory.warnings[0].message


def test_default_clock_is_timezone_aware() -> None:
    assert utc_now().tzinfo is timezone.utc


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("coverage", "supported"),
        ("bindings_inspected", True),
        ("warnings", ("obsolete-warning",)),
    ),
)
def test_discovered_resource_rejects_removed_speculative_fields(field: str, value: object) -> None:
    payload = _resource("/subscriptions/a", "a").model_dump()
    payload[field] = value

    with pytest.raises(ValidationError):
        DiscoveredResource.model_validate(payload)


@pytest.mark.parametrize("state", ("potential", "supported", "no-local-keys"))
def test_key_authentication_rejects_unknown_state(state: str) -> None:
    with pytest.raises(ValueError):
        KeyAuthentication(state)

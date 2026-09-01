"""Provider orchestration for metadata-only discovery."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import datetime, timezone

from azurator.models import (
    DiscoveredResource,
    DiscoveryWarning,
    Inventory,
    ProviderInfo,
    WarningCategory,
    WarningImpact,
)
from azurator.providers.base import DiscoveryProvider

_COVERAGE_WARNING = DiscoveryWarning(
    code="provider-coverage-limited",
    message=(
        "This inventory covers only the key-resource types supported by this Azurator build; "
        "it is not a complete inventory of every secret in Azure."
    ),
    impact=WarningImpact.advisory,
    category=WarningCategory.coverage,
)


def utc_now() -> datetime:
    """Return an aware UTC timestamp."""

    return datetime.now(timezone.utc)


class DiscoveryService:
    """Combine independent provider results without retrieving key values."""

    def __init__(
        self,
        providers: Sequence[DiscoveryProvider],
        *,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self._providers = tuple(providers)
        self._clock = clock

    def discover(self, subscription_id: str) -> Inventory:
        """Discover metadata in exactly one subscription."""

        resources: list[DiscoveredResource] = []
        warnings: list[DiscoveryWarning] = [_COVERAGE_WARNING]
        provider_info: list[ProviderInfo] = []

        for provider in self._providers:
            provider_info.append(provider.info)
            result = provider.discover(subscription_id)
            resources.extend(result.resources)
            warnings.extend(result.warnings)

        return Inventory(
            subscription_id=subscription_id,
            generated_at=self._clock(),
            providers=tuple(sorted(provider_info, key=lambda item: item.name)),
            resources=tuple(sorted(resources, key=lambda item: item.resource_id.casefold())),
            warnings=tuple(warnings),
        )

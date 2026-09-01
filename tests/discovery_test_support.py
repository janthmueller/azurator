"""Test-only discovery provider fakes."""

from __future__ import annotations

from azurator.models import ProviderDiscovery, ProviderInfo


class FakeDiscoveryProvider:
    """Return a predefined result while recording the selected subscription."""

    def __init__(self, info: ProviderInfo, result: ProviderDiscovery) -> None:
        self._info = info
        self._result = result
        self.subscription_ids: list[str] = []

    @property
    def info(self) -> ProviderInfo:
        return self._info

    def discover(self, subscription_id: str) -> ProviderDiscovery:
        self.subscription_ids.append(subscription_id)
        return self._result

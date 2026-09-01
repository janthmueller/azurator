"""Provider contracts kept independent from generated Azure SDK models."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Protocol

from azurator.models import (
    BindingLocation,
    CredentialBinding,
    DiscoveredResource,
    ProviderBindingResult,
    ProviderCandidateResult,
    ProviderDiscovery,
    ProviderInfo,
)

CandidateSink = Callable[[str, str, str], None]
CandidateIdentifier = Callable[[str, str], str | None]
SecretSink = Callable[[str], None]
KeyStateSink = Callable[[str, str], None]

BINDING_VERIFICATION_MISMATCH_CODE = "binding-verification-mismatch"


class ProviderOperationError(RuntimeError):
    """A supported provider operation failed without exposing an Azure response."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class DiscoveryProvider(Protocol):
    """A supported, metadata-only resource discovery provider."""

    @property
    def info(self) -> ProviderInfo: ...

    def discover(self, subscription_id: str) -> ProviderDiscovery: ...


class MatchingProvider(DiscoveryProvider, Protocol):
    """A supported provider that can stream raw key slots into a trusted sink."""

    def inspect_candidates(
        self,
        subscription_id: str,
        resources: Sequence[DiscoveredResource],
        consume: CandidateSink,
    ) -> ProviderCandidateResult: ...


class BindingProvider(Protocol):
    """A supported provider that identifies bindings of selected key resources."""

    @property
    def info(self) -> ProviderInfo: ...

    @property
    def location(self) -> BindingLocation: ...

    @property
    def key_resource_types(self) -> tuple[str, ...]: ...

    def inspect_bindings(
        self,
        subscription_id: str,
        resources: Sequence[DiscoveredResource],
        selected_resource_ids: frozenset[str],
        identify: CandidateIdentifier,
    ) -> ProviderBindingResult: ...


class KeyReadingProvider(Protocol):
    """A supported key provider permitted to stream one exact declared key state."""

    @property
    def info(self) -> ProviderInfo: ...

    def use_key_state(
        self,
        subscription_id: str,
        resource: DiscoveredResource,
        consume: KeyStateSink,
    ) -> None:
        """Stream the provider's exact supported key pair into a trusted callback."""
        ...


class RotationProvider(KeyReadingProvider, Protocol):
    """A supported key provider permitted to read and regenerate one declared slot."""

    def use_key_slot(
        self,
        subscription_id: str,
        resource: DiscoveredResource,
        key_slot: str,
        consume: SecretSink,
    ) -> None: ...

    def regenerate_key(
        self,
        subscription_id: str,
        resource: DiscoveredResource,
        key_slot: str,
    ) -> None: ...


class ManagedBindingProvider(BindingProvider, Protocol):
    """A supported binding provider permitted to update and verify one binding."""

    def update_binding(
        self,
        subscription_id: str,
        binding: CredentialBinding,
        resource: DiscoveredResource,
        expected_key: str,
        replacement_key: str,
    ) -> None: ...

    def verify_binding(
        self,
        subscription_id: str,
        binding: CredentialBinding,
        resource: DiscoveredResource,
        expected_key: str,
    ) -> None: ...

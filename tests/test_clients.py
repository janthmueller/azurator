"""Tests for the official SDK client factory boundary."""

from __future__ import annotations

from typing import Any

import pytest
from azure.core.credentials import AccessToken, TokenCredential

import azurator.clients as clients_module
from azurator.clients import SdkAzureClientFactory


class FakeCredential(TokenCredential):
    def get_token(
        self,
        *scopes: str,
        claims: str | None = None,
        tenant_id: str | None = None,
        enable_cae: bool = False,
        **kwargs: Any,
    ) -> AccessToken:
        del scopes, claims, tenant_id, enable_cae, kwargs
        return AccessToken("fake", 4_102_444_800)


class FakeStorageClient:
    pass


class FakeCognitiveServicesClient:
    pass


class FakeAIProjectClient:
    pass


class FakeWebSiteManagementClient:
    pass


def test_sdk_client_factory_builds_storage_client(monkeypatch: pytest.MonkeyPatch) -> None:
    credential = FakeCredential()
    client = FakeStorageClient()
    arguments: list[dict[str, object]] = []

    def build_client(**kwargs: object) -> FakeStorageClient:
        arguments.append(kwargs)
        return client

    monkeypatch.setattr(clients_module, "StorageManagementClient", build_client)

    result = SdkAzureClientFactory(credential).storage_management("subscription-id")

    assert result is client
    assert arguments == [
        {
            "credential": credential,
            "subscription_id": "subscription-id",
            "api_version": "2025-08-01",
        }
    ]


def test_sdk_client_factory_builds_cognitive_services_client(monkeypatch: pytest.MonkeyPatch) -> None:
    credential = FakeCredential()
    client = FakeCognitiveServicesClient()
    arguments: list[dict[str, object]] = []

    def build_client(**kwargs: object) -> FakeCognitiveServicesClient:
        arguments.append(kwargs)
        return client

    monkeypatch.setattr(clients_module, "CognitiveServicesManagementClient", build_client)

    result = SdkAzureClientFactory(credential).cognitive_services_management("subscription-id")

    assert result is client
    assert arguments == [
        {
            "credential": credential,
            "subscription_id": "subscription-id",
            "api_version": "2025-06-01",
        }
    ]


def test_sdk_client_factory_builds_foundry_management_client(monkeypatch: pytest.MonkeyPatch) -> None:
    credential = FakeCredential()
    client = FakeCognitiveServicesClient()
    arguments: list[dict[str, object]] = []

    def build_client(**kwargs: object) -> FakeCognitiveServicesClient:
        arguments.append(kwargs)
        return client

    monkeypatch.setattr(clients_module, "CognitiveServicesManagementClient", build_client)

    result = SdkAzureClientFactory(credential).foundry_management("subscription-id")

    assert result is client
    assert arguments == [
        {
            "credential": credential,
            "subscription_id": "subscription-id",
            "api_version": "2025-06-01",
        }
    ]


def test_sdk_client_factory_builds_foundry_project_client_with_logging_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    credential = FakeCredential()
    client = FakeAIProjectClient()
    arguments: list[dict[str, object]] = []

    def build_client(**kwargs: object) -> FakeAIProjectClient:
        arguments.append(kwargs)
        return client

    monkeypatch.setattr(clients_module, "AIProjectClient", build_client)

    result = SdkAzureClientFactory(credential).ai_project("https://example.services.ai.azure.com/api/projects/example")

    assert result is client
    assert arguments == [
        {
            "endpoint": "https://example.services.ai.azure.com/api/projects/example",
            "credential": credential,
            "api_version": "v1",
            "logging_enable": False,
        }
    ]


def test_sdk_client_factory_builds_app_service_client_with_pinned_api_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    credential = FakeCredential()
    client = FakeWebSiteManagementClient()
    arguments: list[dict[str, object]] = []

    def build_client(**kwargs: object) -> FakeWebSiteManagementClient:
        arguments.append(kwargs)
        return client

    monkeypatch.setattr(clients_module, "WebSiteManagementClient", build_client)

    result = SdkAzureClientFactory(credential).web_site_management("subscription-id")

    assert result is client
    assert arguments == [
        {
            "credential": credential,
            "subscription_id": "subscription-id",
            "api_version": "2025-05-01",
        }
    ]

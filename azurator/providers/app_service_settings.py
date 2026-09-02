"""Exact-value App Service application-settings credential bindings."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from enum import Enum
from typing import cast

from azure.core.exceptions import HttpResponseError, ServiceRequestError, ServiceResponseError
from azure.mgmt.web.models import StringDictionary

from azurator.clients import AppSettingsLike, AzureClientFactory, WebAppLike, WebAppOperations
from azurator.fingerprints import secret_values_equal
from azurator.models import (
    BindingInspection,
    BindingInspectionStatus,
    BindingLocation,
    BindingManagement,
    CredentialBinding,
    DiscoveredResource,
    DiscoveryWarning,
    KeyAuthentication,
    ProviderBindingResult,
    ProviderInfo,
    WarningCategory,
    WarningImpact,
)
from azurator.providers.base import (
    BINDING_VERIFICATION_MISMATCH_CODE,
    CandidateIdentifier,
    ProviderOperationError,
)
from azurator.providers.resource_ids import ResourceCoordinates, ResourceIdError, resource_coordinates

_PROVIDER_NAME = "azure-app-service-settings"
_PROVIDER_CONTRACT_VERSION = "1"
_BINDING_RESOURCE_TYPE = "Microsoft.Web/sites/config/appsettings"
_SITE_RESOURCE_TYPE = "Microsoft.Web/sites"
_STORAGE_RESOURCE_TYPE = "Microsoft.Storage/storageAccounts"
_COGNITIVE_RESOURCE_TYPE = "Microsoft.CognitiveServices/accounts"
_KEY_RESOURCE_TYPES = (_STORAGE_RESOURCE_TYPE, _COGNITIVE_RESOURCE_TYPE)

APP_SERVICE_SETTINGS_PROVIDER_INFO = ProviderInfo(
    name=_PROVIDER_NAME,
    contract_version=_PROVIDER_CONTRACT_VERSION,
    resource_types=(_BINDING_RESOURCE_TYPE,),
)


class _TransitionState(str, Enum):
    expected = "expected"
    replacement = "replacement"


class AppServiceSettingsProvider:
    """Inspect and manage whole-value key copies in top-level App Service apps."""

    def __init__(self, clients: AzureClientFactory) -> None:
        self._clients = clients

    @property
    def info(self) -> ProviderInfo:
        return APP_SERVICE_SETTINGS_PROVIDER_INFO

    @property
    def location(self) -> BindingLocation:
        return BindingLocation.azure

    @property
    def key_resource_types(self) -> tuple[str, ...]:
        return _KEY_RESOURCE_TYPES

    def inspect_bindings(
        self,
        subscription_id: str,
        resources: Sequence[DiscoveredResource],
        selected_resource_ids: frozenset[str],
        identify: CandidateIdentifier,
    ) -> ProviderBindingResult:
        """Inspect every visible top-level site's complete application-settings dictionary."""

        key_resources = {
            resource.resource_id: resource
            for resource in resources
            if resource.resource_type in _KEY_RESOURCE_TYPES and resource.resource_id in selected_resource_ids
        }
        if not key_resources:
            return ProviderBindingResult()

        warnings: list[DiscoveryWarning] = [_coverage_warning()]
        bindings: list[CredentialBinding] = []
        scopes_inspected = 0
        failed_scopes = 0
        seen_sites: set[str] = set()
        client = self._clients.web_site_management(subscription_id)
        try:
            try:
                sites = client.web_apps.list(logging_enable=False)
                for site in sites:
                    identity = _site_identity(site, subscription_id)
                    if identity is None:
                        failed_scopes += 1
                        warnings.append(
                            _warning(
                                "app-service-site-metadata-invalid",
                                "Azure returned App Service site metadata outside the supported top-level contract.",
                            )
                        )
                        continue
                    site_id, site_name, coordinates = identity
                    normalized_site_id = _normalized_id(site_id)
                    if normalized_site_id in seen_sites:
                        failed_scopes += 1
                        warnings.append(
                            _warning(
                                "app-service-site-metadata-invalid",
                                "Azure returned duplicate App Service site metadata.",
                                site_id,
                            )
                        )
                        continue
                    seen_sites.add(normalized_site_id)

                    try:
                        response = client.web_apps.list_application_settings(
                            coordinates.resource_group,
                            coordinates.resource_name,
                            logging_enable=False,
                        )
                    except HttpResponseError as error:
                        failed_scopes += 1
                        warnings.append(_http_warning("app-service-settings-list", site_id, error.status_code))
                        continue
                    except ServiceRequestError:
                        failed_scopes += 1
                        warnings.append(_transport_warning("app-service-settings-list", site_id, "request"))
                        continue
                    except ServiceResponseError:
                        failed_scopes += 1
                        warnings.append(_transport_warning("app-service-settings-list", site_id, "response"))
                        continue

                    settings = _settings_dictionary(response)
                    if settings is None:
                        failed_scopes += 1
                        warnings.append(
                            _warning(
                                "app-service-settings-response-invalid",
                                "App Service returned application settings outside the supported dictionary contract.",
                                site_id,
                            )
                        )
                        continue

                    site_failed = False
                    grouped: dict[tuple[str, str], list[str]] = {}
                    try:
                        for setting_name in sorted(settings):
                            raw_value = settings[setting_name]
                            matches: list[tuple[str, str]] = []
                            try:
                                if not raw_value:
                                    continue
                                for resource_id in sorted(key_resources, key=str.casefold):
                                    key_slot = identify(resource_id, raw_value)
                                    if key_slot is not None:
                                        matches.append((resource_id, key_slot))
                            finally:
                                raw_value = ""
                            if len(matches) > 1:
                                site_failed = True
                                warnings.append(
                                    _warning(
                                        "app-service-setting-key-ambiguous",
                                        "One App Service setting matched more than one selected Azure key resource.",
                                        site_id,
                                    )
                                )
                                continue
                            if matches:
                                grouped.setdefault(matches[0], []).append(setting_name)
                    finally:
                        settings.clear()
                        del response

                    scopes_inspected += 1
                    if site_failed:
                        failed_scopes += 1
                    site_bindings = tuple(
                        _binding(site_id, site_name, resource_id, key_slot, tuple(selectors))
                        for (resource_id, key_slot), selectors in sorted(
                            grouped.items(),
                            key=lambda item: (item[0][0].casefold(), item[0][1].casefold()),
                        )
                    )
                    bindings.extend(site_bindings)
                    if site_bindings:
                        warnings.append(_restart_and_concurrency_warning(site_id, site_name))
            except HttpResponseError as error:
                failed_scopes += 1
                warnings.append(_http_warning("app-service-site-list", None, error.status_code))
            except ServiceRequestError:
                failed_scopes += 1
                warnings.append(_transport_warning("app-service-site-list", None, "request"))
            except ServiceResponseError:
                failed_scopes += 1
                warnings.append(_transport_warning("app-service-site-list", None, "response"))
        finally:
            client.close()

        status = (
            BindingInspectionStatus.partial
            if failed_scopes and scopes_inspected
            else BindingInspectionStatus.unavailable
            if failed_scopes
            else BindingInspectionStatus.inspected
        )
        inspections = tuple(
            BindingInspection(
                resource_id=resource.resource_id,
                provider=_PROVIDER_NAME,
                location=BindingLocation.azure,
                status=status,
                scopes_inspected=scopes_inspected,
            )
            for resource in sorted(key_resources.values(), key=lambda item: item.resource_id.casefold())
        )
        return ProviderBindingResult(
            inspections=inspections,
            bindings=tuple(
                sorted(
                    bindings,
                    key=lambda item: (
                        item.scope_name.casefold(),
                        item.name.casefold(),
                        item.key_resource_id.casefold(),
                    ),
                )
            ),
            warnings=tuple(warnings),
        )

    def update_binding(
        self,
        subscription_id: str,
        binding: CredentialBinding,
        resource: DiscoveredResource,
        expected_key: str,
        replacement_key: str,
    ) -> None:
        """Replace selected settings only when every alias has one supported transition state."""

        if not expected_key or not replacement_key:
            raise ProviderOperationError(
                "app-service-settings-update-contract-invalid",
                "An App Service binding did not match the expected update shape.",
            )
        coordinates = self._operation_coordinates(subscription_id, binding, resource)
        client = self._clients.web_site_management(subscription_id)
        settings: dict[str, str] | None = None
        replacement_settings: dict[str, str] | None = None
        request: StringDictionary | None = None
        try:
            response = self._read_settings(client.web_apps, coordinates)
            settings = _settings_dictionary(response)
            if settings is None:
                raise ProviderOperationError(
                    "app-service-settings-update-contract-invalid",
                    "App Service returned settings outside the supported update contract.",
                )
            state = _transition_state(settings, binding.selectors, expected_key, replacement_key)
            if state is _TransitionState.replacement:
                return
            replacement_settings = dict(settings)
            for selector in binding.selectors:
                replacement_settings[selector] = replacement_key
            request = StringDictionary(properties=replacement_settings)
            try:
                client.web_apps.update_application_settings(
                    coordinates.resource_group,
                    coordinates.resource_name,
                    request,
                    logging_enable=False,
                )
            except HttpResponseError as error:
                raise _operation_http_error("app-service-settings-update", error.status_code) from None
            except ServiceRequestError:
                raise _operation_transport_error("app-service-settings-update", "request") from None
            except ServiceResponseError:
                raise _operation_transport_error("app-service-settings-update", "response") from None
        finally:
            if settings is not None:
                settings.clear()
            if replacement_settings is not None:
                replacement_settings.clear()
            if request is not None:
                request.properties = None
            expected_key = ""
            replacement_key = ""
            client.close()

    def verify_binding(
        self,
        subscription_id: str,
        binding: CredentialBinding,
        resource: DiscoveredResource,
        expected_key: str,
    ) -> None:
        """Re-read every grouped setting and compare it with one expected key."""

        if not expected_key:
            raise ProviderOperationError(
                "app-service-settings-verification-contract-invalid",
                "An App Service binding did not match the expected verification shape.",
            )
        coordinates = self._operation_coordinates(subscription_id, binding, resource)
        client = self._clients.web_site_management(subscription_id)
        settings: dict[str, str] | None = None
        try:
            response = self._read_settings(client.web_apps, coordinates)
            settings = _settings_dictionary(response)
            if settings is None:
                raise ProviderOperationError(
                    "app-service-settings-verification-contract-invalid",
                    "App Service returned settings outside the supported verification contract.",
                )
            if not _selectors_equal(settings, binding.selectors, expected_key):
                raise ProviderOperationError(
                    BINDING_VERIFICATION_MISMATCH_CODE,
                    "The App Service settings did not retain the expected Azure key.",
                )
        finally:
            if settings is not None:
                settings.clear()
            expected_key = ""
            client.close()

    @staticmethod
    def _read_settings(operations: WebAppOperations, coordinates: ResourceCoordinates) -> AppSettingsLike:
        try:
            return operations.list_application_settings(
                coordinates.resource_group,
                coordinates.resource_name,
                logging_enable=False,
            )
        except HttpResponseError as error:
            raise _operation_http_error("app-service-settings-read", error.status_code) from None
        except ServiceRequestError:
            raise _operation_transport_error("app-service-settings-read", "request") from None
        except ServiceResponseError:
            raise _operation_transport_error("app-service-settings-read", "response") from None

    @staticmethod
    def _operation_coordinates(
        subscription_id: str,
        binding: CredentialBinding,
        resource: DiscoveredResource,
    ) -> ResourceCoordinates:
        valid_resource = (
            resource.provider in {"azure-storage", "azure-cognitive-services"}
            and resource.resource_type in _KEY_RESOURCE_TYPES
            and resource.key_authentication is KeyAuthentication.enabled
            and binding.key_resource_id.casefold() == resource.resource_id.casefold()
            and binding.key_slot in {slot.name for slot in resource.key_slots}
        )
        valid_binding = (
            binding.provider == _PROVIDER_NAME
            and binding.binding_type == _BINDING_RESOURCE_TYPE
            and binding.location is BindingLocation.azure
            and binding.management is BindingManagement.update_and_verify
            and binding.target == binding.scope_id
            and bool(binding.selectors)
            and len(binding.selectors) == len(set(binding.selectors))
            and binding.name == ", ".join(binding.selectors)
            and binding.binding_id
            == _binding_id(binding.scope_id, resource.resource_id, binding.key_slot or "", binding.selectors)
        )
        if not valid_resource or not valid_binding:
            raise ProviderOperationError(
                "app-service-settings-operation-contract-invalid",
                "An App Service settings operation did not match the expected binding shape.",
            )
        try:
            return resource_coordinates(
                binding.scope_id,
                subscription_id=subscription_id,
                expected_resource_type=_SITE_RESOURCE_TYPE,
                expected_name=binding.scope_name,
            )
        except ResourceIdError:
            raise ProviderOperationError(
                "app-service-settings-operation-contract-invalid",
                "An App Service settings operation did not match the expected binding shape.",
            ) from None


def _site_identity(
    site: WebAppLike,
    subscription_id: str,
) -> tuple[str, str, ResourceCoordinates] | None:
    site_id = site.id
    site_name = site.name
    site_type = site.type
    if (
        not isinstance(site_id, str)
        or not site_id
        or not isinstance(site_name, str)
        or not site_name
        or not isinstance(site_type, str)
        or site_type.casefold() != _SITE_RESOURCE_TYPE.casefold()
    ):
        return None
    try:
        coordinates = resource_coordinates(
            site_id,
            subscription_id=subscription_id,
            expected_resource_type=_SITE_RESOURCE_TYPE,
            expected_name=site_name,
        )
    except ResourceIdError:
        return None
    return site_id, site_name, coordinates


def _settings_dictionary(response: AppSettingsLike) -> dict[str, str] | None:
    properties = response.properties
    if not isinstance(properties, dict):
        return None
    raw_properties = cast(dict[object, object], properties)
    if any(
        not isinstance(name, str) or not name or not isinstance(value, str) for name, value in raw_properties.items()
    ):
        properties.clear()
        return None
    return cast(dict[str, str], raw_properties)


def _transition_state(
    settings: dict[str, str],
    selectors: tuple[str, ...],
    expected_key: str,
    replacement_key: str,
) -> _TransitionState:
    if _selectors_equal(settings, selectors, replacement_key):
        return _TransitionState.replacement
    if _selectors_equal(settings, selectors, expected_key):
        return _TransitionState.expected
    raise ProviderOperationError(
        "app-service-settings-binding-drift-detected",
        "The App Service settings changed after planning; they were not updated.",
    )


def _selectors_equal(settings: dict[str, str], selectors: tuple[str, ...], expected_key: str) -> bool:
    return all(selector in settings and secret_values_equal(settings[selector], expected_key) for selector in selectors)


def _binding(
    site_id: str,
    site_name: str,
    resource_id: str,
    key_slot: str,
    selectors: tuple[str, ...],
) -> CredentialBinding:
    return CredentialBinding(
        binding_id=_binding_id(site_id, resource_id, key_slot, selectors),
        name=", ".join(selectors),
        binding_type=_BINDING_RESOURCE_TYPE,
        provider=_PROVIDER_NAME,
        location=BindingLocation.azure,
        scope_id=site_id,
        scope_name=site_name,
        key_resource_id=resource_id,
        key_slot=key_slot,
        target=site_id,
        selectors=selectors,
        management=BindingManagement.update_and_verify,
    )


def _binding_id(site_id: str, resource_id: str, key_slot: str, selectors: tuple[str, ...]) -> str:
    payload = json.dumps(
        ("azurator-app-service-settings-binding-v1", site_id, resource_id, key_slot, selectors),
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"app-service-settings:{hashlib.sha256(payload).hexdigest()}"


def _coverage_warning() -> DiscoveryWarning:
    return _warning(
        "app-service-settings-binding-coverage-limited",
        (
            "App Service binding scope: exact whole application-setting values on visible top-level apps in the "
            "selected subscription. Deployment slots, connection strings, embedded keys, Key Vault references, "
            "and running workloads were not inspected."
        ),
    )


def _restart_and_concurrency_warning(site_id: str, site_name: str) -> DiscoveryWarning:
    return _warning(
        "app-service-settings-restart-and-concurrency",
        (
            f"App Service {site_name} requires complete application-settings replacement, which restarts the app. "
            "No settings deployment or edit may run concurrently, and workload health is not checked."
        ),
        site_id,
    )


def _warning(code: str, message: str, resource_id: str | None = None) -> DiscoveryWarning:
    return DiscoveryWarning(
        code=code,
        message=message,
        impact=WarningImpact.confirmation,
        category=WarningCategory.credential_binding,
        provider=_PROVIDER_NAME,
        resource_id=resource_id,
    )


def _http_warning(prefix: str, resource_id: str | None, status: int | None) -> DiscoveryWarning:
    suffix = "forbidden" if status == 403 else "failed"
    status_text = f"HTTP {status}" if status is not None else "an Azure HTTP error"
    return _warning(
        f"{prefix}-{suffix}",
        f"App Service inspection failed with {status_text}.",
        resource_id,
    )


def _transport_warning(prefix: str, resource_id: str | None, phase: str) -> DiscoveryWarning:
    return _warning(
        f"{prefix}-{phase}-failed",
        f"App Service inspection failed during Azure {phase} handling.",
        resource_id,
    )


def _operation_http_error(operation: str, status: int | None) -> ProviderOperationError:
    suffix = "forbidden" if status == 403 else "failed"
    status_text = f"HTTP {status}" if status is not None else "an Azure HTTP error"
    return ProviderOperationError(
        f"{operation}-{suffix}",
        f"The supported App Service settings operation failed with {status_text}.",
    )


def _operation_transport_error(operation: str, phase: str) -> ProviderOperationError:
    return ProviderOperationError(
        f"{operation}-{phase}-failed",
        f"The supported App Service settings operation failed during Azure {phase} handling.",
    )


def _normalized_id(value: str) -> str:
    return value.rstrip("/").casefold()

"""Inspection and managed credential operations for supported Foundry key connections."""

from __future__ import annotations

import re
from collections.abc import Mapping, MutableMapping, Sequence
from enum import Enum
from typing import cast
from urllib.parse import SplitResult, quote, urlsplit

from azure.core.exceptions import HttpResponseError, ServiceRequestError, ServiceResponseError
from azure.mgmt.cognitiveservices.models import (
    AccountKeyAuthTypeConnectionProperties,
    ApiKeyAuthConnectionProperties,
    ConnectionAccountKey,
    ConnectionApiKey,
    ConnectionCategory,
    ConnectionUpdateContent,
)

from azurator.clients import (
    AzureClientFactory,
    FoundryConnectionLike,
    FoundryConnectionOperations,
    FoundryProjectLike,
)
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
from azurator.providers.resource_ids import (
    ProjectConnectionCoordinates,
    ResourceIdError,
    project_connection_coordinates,
    resource_coordinates,
)

_PROVIDER_NAME = "azure-foundry-connections"
_PROVIDER_CONTRACT_VERSION = "1"
_BINDING_RESOURCE_TYPE = "Microsoft.CognitiveServices/accounts/projects/connections"
_PROJECT_RESOURCE_TYPE = "Microsoft.CognitiveServices/accounts/projects"
_COGNITIVE_RESOURCE_TYPE = "Microsoft.CognitiveServices/accounts"
_STORAGE_RESOURCE_TYPE = "Microsoft.Storage/storageAccounts"
_FOUNDRY_ACCOUNT_KIND = "AIServices"
_STORAGE_CONNECTION_TYPE = "AzureStorageAccount"
_COGNITIVE_CONNECTION_TYPE = "AzureOpenAI"
_REVIEWED_CONNECTION_TYPES = (_STORAGE_CONNECTION_TYPE, _COGNITIVE_CONNECTION_TYPE)
_MANAGEMENT_API_VERSION = "2025-06-01"
_PUBLIC_BLOB_HOST_SUFFIX = ".blob.core.windows.net"
_ACCOUNT_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{1,63}$")
_PROJECT_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{1,63}$")
_CONNECTION_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{2,32}$")
_STORAGE_ACCOUNT_NAME_PATTERN = re.compile(r"^[a-z0-9]{3,24}$")

FOUNDRY_CONNECTIONS_PROVIDER_INFO = ProviderInfo(
    name=_PROVIDER_NAME,
    contract_version=_PROVIDER_CONTRACT_VERSION,
    resource_types=(_BINDING_RESOURCE_TYPE,),
)


class _BindingTransitionState(str, Enum):
    expected = "expected"
    replacement = "replacement"


class FoundryConnectionsProvider:
    """Identify and manage supported Foundry connections to selected Azure keys."""

    def __init__(self, clients: AzureClientFactory) -> None:
        self._clients = clients

    @property
    def info(self) -> ProviderInfo:
        return FOUNDRY_CONNECTIONS_PROVIDER_INFO

    @property
    def location(self) -> BindingLocation:
        return BindingLocation.azure

    @property
    def key_resource_types(self) -> tuple[str, ...]:
        return (_STORAGE_RESOURCE_TYPE, _COGNITIVE_RESOURCE_TYPE)

    def inspect_bindings(
        self,
        subscription_id: str,
        resources: Sequence[DiscoveredResource],
        selected_resource_ids: frozenset[str],
        identify: CandidateIdentifier,
    ) -> ProviderBindingResult:
        """Inspect supported project connections and attribute credentials ephemerally."""

        key_resources = {
            _normalized_id(resource.resource_id): resource
            for resource in resources
            if resource.resource_type.casefold()
            in {_STORAGE_RESOURCE_TYPE.casefold(), _COGNITIVE_RESOURCE_TYPE.casefold()}
        }
        selected = {
            _normalized_id(resource_id): key_resources[_normalized_id(resource_id)]
            for resource_id in selected_resource_ids
            if _normalized_id(resource_id) in key_resources
        }
        if not selected:
            return ProviderBindingResult()

        connection_types = tuple(
            connection_type
            for connection_type, resource_type in (
                (_STORAGE_CONNECTION_TYPE, _STORAGE_RESOURCE_TYPE),
                (_COGNITIVE_CONNECTION_TYPE, _COGNITIVE_RESOURCE_TYPE),
            )
            if any(resource.resource_type.casefold() == resource_type.casefold() for resource in selected.values())
        )
        if connection_types == (_STORAGE_CONNECTION_TYPE,):
            coverage_message = (
                "Azure binding scope: public-cloud, project-level Foundry AzureStorageAccount/AccountKey "
                "connections targeting the selected Storage Accounts. Other Storage binding categories were not "
                "inspected. Running workloads were not tested."
            )
        elif connection_types == (_COGNITIVE_CONNECTION_TYPE,):
            coverage_message = (
                "Azure binding scope: public-cloud, project-level Foundry AzureOpenAI/ApiKey connections targeting "
                "the selected Azure AI accounts. Other AI binding categories were not inspected. Running "
                "workloads were not tested."
            )
        elif connection_types == (_STORAGE_CONNECTION_TYPE, _COGNITIVE_CONNECTION_TYPE):
            coverage_message = (
                "Azure binding scope: public-cloud, project-level Foundry AzureStorageAccount/AccountKey and "
                "AzureOpenAI/ApiKey connections targeting the selected resources. Other Azure binding categories "
                "were not inspected. Running workloads were not tested."
            )
        else:
            raise ValueError("selected resources do not map to the supported Foundry connection types")

        warnings: list[DiscoveryWarning] = [
            DiscoveryWarning(
                code="foundry-binding-coverage-limited",
                message=coverage_message,
                impact=WarningImpact.confirmation,
                category=WarningCategory.credential_binding,
                provider=_PROVIDER_NAME,
            )
        ]
        bindings: list[CredentialBinding] = []
        scopes_inspected = 0
        failed_scopes = 0
        seen_projects: set[str] = set()
        seen_bindings: set[str] = set()
        accounts = tuple(
            resource
            for resource in resources
            if resource.resource_type.casefold() == _COGNITIVE_RESOURCE_TYPE.casefold()
            and resource.kind == _FOUNDRY_ACCOUNT_KIND
        )
        if accounts:
            management_client = self._clients.foundry_management(subscription_id)
            try:
                for account in accounts:
                    try:
                        coordinates = resource_coordinates(
                            account.resource_id,
                            subscription_id=subscription_id,
                            expected_resource_type=_COGNITIVE_RESOURCE_TYPE,
                            expected_name=account.name,
                        )
                    except ResourceIdError:
                        failed_scopes += 1
                        warnings.append(
                            _warning(
                                "foundry-account-scope-invalid",
                                "A Foundry account ID could not safely scope project inspection.",
                                account.resource_id,
                            )
                        )
                        continue

                    try:
                        projects = management_client.projects.list(
                            coordinates.resource_group,
                            coordinates.resource_name,
                            api_version=_MANAGEMENT_API_VERSION,
                            logging_enable=False,
                        )
                        for project in projects:
                            outcome = self._inspect_project(
                                account,
                                project,
                                selected,
                                connection_types,
                                identify,
                                seen_projects,
                                seen_bindings,
                            )
                            scopes_inspected += outcome.scopes_inspected
                            failed_scopes += outcome.failed_scopes
                            bindings.extend(outcome.bindings)
                            warnings.extend(outcome.warnings)
                    except HttpResponseError as error:
                        failed_scopes += 1
                        warnings.append(
                            _http_warning(
                                "foundry-project-list",
                                "Foundry project enumeration",
                                account.resource_id,
                                error.status_code,
                            )
                        )
                    except ServiceRequestError:
                        failed_scopes += 1
                        warnings.append(
                            _transport_warning(
                                "foundry-project-list",
                                "Foundry project enumeration",
                                account.resource_id,
                                "request",
                            )
                        )
                    except ServiceResponseError:
                        failed_scopes += 1
                        warnings.append(
                            _transport_warning(
                                "foundry-project-list",
                                "Foundry project enumeration",
                                account.resource_id,
                                "response",
                            )
                        )
            finally:
                management_client.close()

        if failed_scopes:
            status = BindingInspectionStatus.partial if scopes_inspected else BindingInspectionStatus.unavailable
        else:
            status = BindingInspectionStatus.inspected

        inspections = tuple(
            BindingInspection(
                resource_id=resource.resource_id,
                provider=_PROVIDER_NAME,
                location=BindingLocation.azure,
                status=status,
                scopes_inspected=scopes_inspected,
            )
            for resource in sorted(selected.values(), key=lambda item: item.resource_id.casefold())
        )
        ordered_bindings = tuple(
            sorted(
                bindings,
                key=lambda item: (item.scope_name.casefold(), item.name.casefold(), item.key_resource_id.casefold()),
            )
        )
        return ProviderBindingResult(
            inspections=inspections,
            bindings=ordered_bindings,
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
        """Move one exact supported Foundry credential to its replacement key."""

        if not expected_key or not replacement_key:
            raise ProviderOperationError(
                "foundry-update-contract-invalid",
                "A Foundry binding did not match the expected update shape.",
            )
        coordinates = self._managed_operation_coordinates(subscription_id, binding, resource)
        state = self._binding_transition_state(
            coordinates,
            binding,
            resource,
            expected_key,
            replacement_key,
        )
        if state is _BindingTransitionState.replacement:
            return
        connection_type = _connection_type_for_resource(resource)
        if connection_type == _STORAGE_CONNECTION_TYPE:
            storage_credential = ConnectionAccountKey(key=replacement_key)
            credential: ConnectionAccountKey | ConnectionApiKey = storage_credential
            properties: AccountKeyAuthTypeConnectionProperties | ApiKeyAuthConnectionProperties = (
                AccountKeyAuthTypeConnectionProperties(
                    category=ConnectionCategory.AZURE_STORAGE_ACCOUNT,
                    target=binding.target,
                    credentials=storage_credential,
                )
            )
        else:
            api_credential = ConnectionApiKey(key=replacement_key)
            credential = api_credential
            properties = ApiKeyAuthConnectionProperties(
                category=ConnectionCategory.AZURE_OPEN_AI,
                target=binding.target,
                credentials=api_credential,
            )
        request = ConnectionUpdateContent(properties=properties)
        client = self._clients.foundry_management(subscription_id)
        try:
            try:
                client.project_connections.update(
                    coordinates.resource_group,
                    coordinates.account_name,
                    coordinates.project_name,
                    coordinates.connection_name,
                    request,
                    logging_enable=False,
                )
            except HttpResponseError as error:
                raise _operation_http_error("foundry-connection-update", error.status_code) from None
            except ServiceRequestError:
                raise _operation_transport_error("foundry-connection-update", "request") from None
            except ServiceResponseError:
                raise _operation_transport_error("foundry-connection-update", "response") from None
        finally:
            credential.key = None
            properties.credentials = None
            request.properties = None
            expected_key = ""
            replacement_key = ""
            client.close()

    def _binding_transition_state(
        self,
        coordinates: ProjectConnectionCoordinates,
        binding: CredentialBinding,
        resource: DiscoveredResource,
        expected_key: str,
        replacement_key: str,
    ) -> _BindingTransitionState:
        try:
            project_client = self._clients.ai_project(
                _project_endpoint(coordinates.account_name, coordinates.project_name)
            )
        except ValueError:
            raise ProviderOperationError(
                "foundry-transition-contract-invalid",
                "A Foundry binding did not match the expected transition shape.",
            ) from None

        raw_key: str | None = None
        credentials: object = None
        try:
            try:
                detailed = project_client.connections.get(
                    coordinates.connection_name,
                    include_credentials=True,
                    logging_enable=False,
                )
            except HttpResponseError as error:
                raise _operation_http_error("foundry-connection-transition-check", error.status_code) from None
            except ServiceRequestError:
                raise _operation_transport_error("foundry-connection-transition-check", "request") from None
            except ServiceResponseError:
                raise _operation_transport_error("foundry-connection-transition-check", "response") from None

            credentials = detailed.credentials
            connection_type = _connection_type_for_resource(resource)
            target = _resolve_key_resource(detailed, {resource.resource_id: resource})
            if (
                detailed.name != binding.name
                or detailed.type != connection_type
                or detailed.target != binding.target
                or target is None
                or _normalized_id(target.resource_id) != _normalized_id(resource.resource_id)
            ):
                raise ProviderOperationError(
                    "foundry-connection-drift-detected",
                    "The Foundry connection metadata changed after planning; it was not updated.",
                )
            raw_key = _foundry_v1_key_value(credentials, connection_type)
            if raw_key is None:
                raise ProviderOperationError(
                    "foundry-transition-contract-invalid",
                    "Foundry returned credentials outside the supported connection transition contract.",
                )
            if secret_values_equal(raw_key, replacement_key):
                return _BindingTransitionState.replacement
            if secret_values_equal(raw_key, expected_key):
                return _BindingTransitionState.expected
            raise ProviderOperationError(
                "foundry-connection-drift-detected",
                "The Foundry connection credential changed after planning; it was not updated.",
            )
        finally:
            _drop_foundry_v1_key_reference(credentials)
            raw_key = ""
            expected_key = ""
            replacement_key = ""
            project_client.close()

    def verify_binding(
        self,
        subscription_id: str,
        binding: CredentialBinding,
        resource: DiscoveredResource,
        expected_key: str,
    ) -> None:
        """Re-read one managed credential and compare it without retaining its value."""

        if not expected_key:
            raise ProviderOperationError(
                "foundry-verification-contract-invalid",
                "A Foundry binding did not match the expected verification shape.",
            )
        coordinates = self._managed_operation_coordinates(subscription_id, binding, resource)
        try:
            project_client = self._clients.ai_project(
                _project_endpoint(coordinates.account_name, coordinates.project_name)
            )
        except ValueError:
            raise ProviderOperationError(
                "foundry-verification-contract-invalid",
                "A Foundry binding did not match the expected verification shape.",
            ) from None

        raw_key: str | None = None
        credentials: object = None
        try:
            try:
                detailed = project_client.connections.get(
                    coordinates.connection_name,
                    include_credentials=True,
                    logging_enable=False,
                )
            except HttpResponseError as error:
                raise _operation_http_error("foundry-connection-verification", error.status_code) from None
            except ServiceRequestError:
                raise _operation_transport_error("foundry-connection-verification", "request") from None
            except ServiceResponseError:
                raise _operation_transport_error("foundry-connection-verification", "response") from None

            credentials = detailed.credentials
            connection_type = _connection_type_for_resource(resource)
            target = _resolve_key_resource(detailed, {resource.resource_id: resource})
            metadata_matches = (
                detailed.name == binding.name
                and detailed.type == connection_type
                and detailed.target == binding.target
                and target is not None
                and _normalized_id(target.resource_id) == _normalized_id(resource.resource_id)
            )
            if not metadata_matches:
                raise ProviderOperationError(
                    "foundry-connection-drift-detected",
                    "The Foundry connection metadata changed after planning; verification was blocked.",
                )
            raw_key = _foundry_v1_key_value(credentials, connection_type)
            if raw_key is None:
                raise ProviderOperationError(
                    "foundry-verification-contract-invalid",
                    "Foundry returned credentials outside the supported connection verification contract.",
                )
            if not secret_values_equal(raw_key, expected_key):
                raise ProviderOperationError(
                    BINDING_VERIFICATION_MISMATCH_CODE,
                    "The Foundry connection did not retain the expected Azure key.",
                )
        finally:
            _drop_foundry_v1_key_reference(credentials)
            raw_key = ""
            expected_key = ""
            project_client.close()

    @staticmethod
    def _managed_operation_coordinates(
        subscription_id: str,
        binding: CredentialBinding,
        resource: DiscoveredResource,
    ) -> ProjectConnectionCoordinates:
        valid_binding = (
            binding.provider == _PROVIDER_NAME
            and binding.binding_type.casefold() == _BINDING_RESOURCE_TYPE.casefold()
            and binding.location is BindingLocation.azure
            and binding.management is BindingManagement.update_and_verify
            and _normalized_id(binding.key_resource_id) == _normalized_id(resource.resource_id)
            and _CONNECTION_NAME_PATTERN.fullmatch(binding.name) is not None
            and isinstance(binding.target, str)
            and bool(binding.target)
        )
        connection_type = _connection_type_for_resource(resource)
        if connection_type == _STORAGE_CONNECTION_TYPE:
            valid_resource = (
                resource.provider == "azure-storage"
                and resource.resource_type.casefold() == _STORAGE_RESOURCE_TYPE.casefold()
                and resource.key_authentication is KeyAuthentication.enabled
                and _storage_account_name_from_target(binding.target or "") == resource.name.casefold()
            )
            expected_resource_type = _STORAGE_RESOURCE_TYPE
        else:
            valid_resource = (
                connection_type == _COGNITIVE_CONNECTION_TYPE
                and resource.provider == "azure-cognitive-services"
                and resource.resource_type.casefold() == _COGNITIVE_RESOURCE_TYPE.casefold()
                and resource.key_authentication is KeyAuthentication.enabled
                and _normalized_service_endpoint(binding.target or "")
                == _normalized_service_endpoint(resource.endpoint or "")
                and _normalized_service_endpoint(resource.endpoint or "") is not None
            )
            expected_resource_type = _COGNITIVE_RESOURCE_TYPE
        if not valid_binding or not valid_resource:
            raise ProviderOperationError(
                "foundry-operation-contract-invalid",
                "A Foundry connection operation did not match the expected binding shape.",
            )
        try:
            resource_coordinates(
                resource.resource_id,
                subscription_id=subscription_id,
                expected_resource_type=expected_resource_type,
                expected_name=resource.name,
            )
            return project_connection_coordinates(
                binding.binding_id,
                subscription_id=subscription_id,
                expected_project_id=binding.scope_id,
                expected_connection_name=binding.name,
            )
        except ResourceIdError:
            raise ProviderOperationError(
                "foundry-operation-contract-invalid",
                "A Foundry connection operation did not match the expected binding shape.",
            ) from None

    def _inspect_project(
        self,
        account: DiscoveredResource,
        project: FoundryProjectLike,
        selected_key_resources: Mapping[str, DiscoveredResource],
        connection_types: tuple[str, ...],
        identify: CandidateIdentifier,
        seen_projects: set[str],
        seen_bindings: set[str],
    ) -> _ProjectOutcome:
        identity = _project_identity(account, project)
        if identity is None:
            return _ProjectOutcome.failed(
                _warning(
                    "foundry-project-metadata-invalid",
                    (
                        "A returned Foundry project's ARM ID or resource type did not match its parent account, "
                        "so its connections were not inspected."
                    ),
                    account.resource_id,
                )
            )
        project_id, project_name = identity
        if _normalized_id(project_id) in seen_projects:
            return _ProjectOutcome.failed(
                _warning(
                    "foundry-project-metadata-invalid",
                    "Azure returned duplicate Foundry project metadata, so its connections were not inspected twice.",
                    account.resource_id,
                )
            )
        seen_projects.add(_normalized_id(project_id))

        try:
            endpoint = _project_endpoint(account.name, project_name)
            project_client = self._clients.ai_project(endpoint)
        except ValueError:
            return _ProjectOutcome.failed(
                _warning(
                    "foundry-project-endpoint-invalid",
                    "A Foundry project endpoint could not initialize the supported data-plane client.",
                    project_id,
                )
            )

        bindings: list[CredentialBinding] = []
        warnings: list[DiscoveryWarning] = []
        failed = 0
        listed_types = 0
        try:
            for connection_type in connection_types:
                try:
                    connections = project_client.connections.list(
                        connection_type=connection_type,
                        logging_enable=False,
                    )
                    listed_types += 1
                    for connection in connections:
                        outcome = self._inspect_connection(
                            project_client.connections,
                            project_id,
                            project_name,
                            connection,
                            selected_key_resources,
                            identify,
                            seen_bindings,
                        )
                        failed += outcome.failed_scopes
                        bindings.extend(outcome.bindings)
                        warnings.extend(outcome.warnings)
                except HttpResponseError as error:
                    failed += 1
                    warnings.append(
                        _http_warning(
                            "foundry-connection-list",
                            f"Foundry {connection_type} connection enumeration",
                            project_id,
                            error.status_code,
                        )
                    )
                except ServiceRequestError:
                    failed += 1
                    warnings.append(
                        _transport_warning(
                            "foundry-connection-list",
                            f"Foundry {connection_type} connection enumeration",
                            project_id,
                            "request",
                        )
                    )
                except ServiceResponseError:
                    failed += 1
                    warnings.append(
                        _transport_warning(
                            "foundry-connection-list",
                            f"Foundry {connection_type} connection enumeration",
                            project_id,
                            "response",
                        )
                    )
        finally:
            project_client.close()

        return _ProjectOutcome(
            scopes_inspected=1 if listed_types else 0,
            failed_scopes=failed,
            bindings=tuple(bindings),
            warnings=tuple(warnings),
        )

    @staticmethod
    def _inspect_connection(
        operations: FoundryConnectionOperations,
        project_id: str,
        project_name: str,
        connection: FoundryConnectionLike,
        selected_key_resources: Mapping[str, DiscoveredResource],
        identify: CandidateIdentifier,
        seen_bindings: set[str],
    ) -> _ProjectOutcome:
        connection_type = connection.type
        if not isinstance(connection_type, str) or connection_type not in _REVIEWED_CONNECTION_TYPES:
            return _ProjectOutcome.failed(
                _warning(
                    "foundry-connection-metadata-invalid",
                    "Foundry returned malformed supported key-connection metadata.",
                    project_id,
                )
            )

        target_identity = _connection_target_identity(connection)
        if target_identity is None:
            warning_code = (
                "foundry-storage-target-unresolved"
                if connection_type == _STORAGE_CONNECTION_TYPE
                else "foundry-cognitive-target-unresolved"
            )
            return _ProjectOutcome.failed(
                _warning(
                    warning_code,
                    "A supported Foundry key connection returned an invalid or ambiguous target.",
                    project_id,
                )
            )

        target = _resolve_key_resource(connection, selected_key_resources)
        if target is None:
            selected_target_identities = {
                identity
                for resource in selected_key_resources.values()
                if (identity := _key_resource_target_identity(resource, connection_type)) is not None
            }
            if target_identity not in selected_target_identities:
                return _ProjectOutcome()
            warning_code = (
                "foundry-storage-target-unresolved"
                if connection_type == _STORAGE_CONNECTION_TYPE
                else "foundry-cognitive-target-unresolved"
            )
            return _ProjectOutcome.failed(
                _warning(
                    warning_code,
                    "A supported Foundry key connection target was ambiguous for the selected key resources.",
                    project_id,
                )
            )

        connection_name = connection.name
        if (
            not isinstance(connection_name, str)
            or not connection_name
            or _CONNECTION_NAME_PATTERN.fullmatch(connection_name) is None
        ):
            return _ProjectOutcome.failed(
                _warning(
                    "foundry-connection-metadata-invalid",
                    "Foundry returned malformed supported key-connection metadata.",
                    project_id,
                )
            )

        encoded_connection_name = quote(connection_name, safe="-._~")
        binding_id = f"{project_id.rstrip('/')}/connections/{encoded_connection_name}"
        normalized_binding_id = _normalized_id(binding_id)
        if normalized_binding_id in seen_bindings:
            return _ProjectOutcome.failed(
                _warning(
                    "foundry-connection-metadata-invalid",
                    "Foundry returned duplicate supported key-connection metadata.",
                    project_id,
                )
            )
        seen_bindings.add(normalized_binding_id)

        key_slot: str | None = None
        warning: DiscoveryWarning | None = None
        try:
            detailed = operations.get(
                connection_name,
                include_credentials=True,
                logging_enable=False,
            )
        except HttpResponseError as error:
            warning = _http_warning(
                "foundry-connection-credential",
                "Foundry connection credential inspection",
                binding_id,
                error.status_code,
            )
        except ServiceRequestError:
            warning = _transport_warning(
                "foundry-connection-credential",
                "Foundry connection credential inspection",
                binding_id,
                "request",
            )
        except ServiceResponseError:
            warning = _transport_warning(
                "foundry-connection-credential",
                "Foundry connection credential inspection",
                binding_id,
                "response",
            )
        else:
            detailed_name = detailed.name
            detailed_type = detailed.type
            detailed_target = _resolve_key_resource(detailed, selected_key_resources)
            credentials = detailed.credentials
            raw_key = _foundry_v1_key_value(credentials, connection_type)
            try:
                if (
                    detailed_name != connection_name
                    or not isinstance(detailed_type, str)
                    or detailed_type != connection_type
                    or detailed.target != connection.target
                    or detailed_target is None
                    or _normalized_id(detailed_target.resource_id) != _normalized_id(target.resource_id)
                    or not isinstance(raw_key, str)
                    or not raw_key
                ):
                    warning = _warning(
                        "foundry-connection-credential-unavailable",
                        "Foundry did not return the expected credential for a supported key connection.",
                        binding_id,
                    )
                else:
                    key_slot = identify(target.resource_id, raw_key)
                    if key_slot is None:
                        warning = _warning(
                            "foundry-connection-key-unmatched",
                            "A Foundry connection credential did not match either current key slot of its linked "
                            "Azure resource.",
                            binding_id,
                        )
            finally:
                _drop_foundry_v1_key_reference(credentials)
                raw_key = ""
                del detailed

        binding = CredentialBinding(
            binding_id=binding_id,
            name=connection_name,
            binding_type=_BINDING_RESOURCE_TYPE,
            provider=_PROVIDER_NAME,
            location=BindingLocation.azure,
            scope_id=project_id,
            scope_name=project_name,
            key_resource_id=target.resource_id,
            key_slot=key_slot,
            target=cast(str, connection.target),
            selectors=(),
            management=(
                BindingManagement.update_and_verify
                if warning is None and key_slot is not None
                else BindingManagement.observed_only
            ),
        )
        return _ProjectOutcome(
            failed_scopes=1 if warning is not None else 0,
            bindings=(binding,),
            warnings=(warning,) if warning is not None else (),
        )


class _ProjectOutcome:
    def __init__(
        self,
        *,
        scopes_inspected: int = 0,
        failed_scopes: int = 0,
        bindings: tuple[CredentialBinding, ...] = (),
        warnings: tuple[DiscoveryWarning, ...] = (),
    ) -> None:
        self.scopes_inspected = scopes_inspected
        self.failed_scopes = failed_scopes
        self.bindings = bindings
        self.warnings = warnings

    @classmethod
    def failed(cls, warning: DiscoveryWarning) -> _ProjectOutcome:
        return cls(failed_scopes=1, warnings=(warning,))


def _project_endpoint(account_name: str, project_name: str) -> str:
    if not _ACCOUNT_NAME_PATTERN.fullmatch(account_name) or not _PROJECT_NAME_PATTERN.fullmatch(project_name):
        raise ValueError("Foundry account or project name violates the supported endpoint contract")
    encoded_account = quote(account_name, safe="-._~")
    encoded_project = quote(project_name, safe="-._~")
    return f"https://{encoded_account}.services.ai.azure.com/api/projects/{encoded_project}"


def _project_identity(
    account: DiscoveredResource,
    project: FoundryProjectLike,
) -> tuple[str, str] | None:
    project_id = project.id
    project_type = project.type
    if (
        not isinstance(project_id, str)
        or not project_id
        or not isinstance(project_type, str)
        or project_type.casefold() != _PROJECT_RESOURCE_TYPE.casefold()
        or not _ACCOUNT_NAME_PATTERN.fullmatch(account.name)
    ):
        return None

    project_prefix = f"{account.resource_id.rstrip('/')}/projects/"
    if not project_id.casefold().startswith(project_prefix.casefold()):
        return None
    project_name = project_id[len(project_prefix) :]
    if not _PROJECT_NAME_PATTERN.fullmatch(project_name):
        return None
    return project_id, project_name


def _resolve_key_resource(
    connection: FoundryConnectionLike,
    resources: Mapping[str, DiscoveredResource],
) -> DiscoveredResource | None:
    connection_type = connection.type
    target_identity = _connection_target_identity(connection)
    if not isinstance(connection_type, str) or target_identity is None:
        return None
    matches = [
        resource
        for resource in resources.values()
        if _key_resource_target_identity(resource, connection_type) == target_identity
    ]
    return matches[0] if len(matches) == 1 else None


def _connection_target_identity(connection: FoundryConnectionLike) -> str | None:
    target = connection.target
    if not isinstance(target, str):
        return None
    if connection.type == _STORAGE_CONNECTION_TYPE:
        return _storage_account_name_from_target(target)
    if connection.type == _COGNITIVE_CONNECTION_TYPE:
        return _normalized_service_endpoint(target)
    return None


def _key_resource_target_identity(resource: DiscoveredResource, connection_type: str) -> str | None:
    if connection_type == _STORAGE_CONNECTION_TYPE:
        if resource.resource_type.casefold() != _STORAGE_RESOURCE_TYPE.casefold():
            return None
        return resource.name.casefold()
    if connection_type != _COGNITIVE_CONNECTION_TYPE:
        return None
    if resource.resource_type.casefold() != _COGNITIVE_RESOURCE_TYPE.casefold() or not isinstance(
        resource.endpoint, str
    ):
        return None
    return _normalized_service_endpoint(resource.endpoint)


def _storage_account_name_from_target(target: str) -> str | None:
    parsed = _split_url(target)
    if parsed is None:
        return None
    try:
        hostname = parsed.hostname
        port = parsed.port
        username = parsed.username
        password = parsed.password
    except ValueError:
        return None
    if (
        parsed.scheme.casefold() != "https"
        or not hostname
        or port is not None
        or username
        or password
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        return None
    normalized_hostname = hostname.casefold()
    if not normalized_hostname.endswith(_PUBLIC_BLOB_HOST_SUFFIX):
        return None
    account_name = normalized_hostname[: -len(_PUBLIC_BLOB_HOST_SUFFIX)]
    if not _STORAGE_ACCOUNT_NAME_PATTERN.fullmatch(account_name):
        return None
    return account_name


def _normalized_service_endpoint(target: str) -> str | None:
    parsed = _split_url(target)
    if parsed is None:
        return None
    try:
        hostname = parsed.hostname
        port = parsed.port
        username = parsed.username
        password = parsed.password
    except ValueError:
        return None
    if (
        parsed.scheme.casefold() != "https"
        or not hostname
        or port is not None
        or username
        or password
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        return None
    return f"https://{hostname.casefold()}"


def _split_url(value: str) -> SplitResult | None:
    try:
        return urlsplit(value)
    except ValueError:
        return None


def _foundry_v1_key_value(credentials: object, connection_type: str) -> str | None:
    if not isinstance(credentials, MutableMapping):
        return None
    fields = cast(MutableMapping[object, object], credentials)
    expected_credential_type = {
        _STORAGE_CONNECTION_TYPE: "AccountKey",
        _COGNITIVE_CONNECTION_TYPE: "ApiKey",
    }.get(connection_type)
    if (
        expected_credential_type is None
        or set(fields) != {"type", "key"}
        or fields.get("type") != expected_credential_type
    ):
        return None
    value = fields.get("key")
    return value if isinstance(value, str) and value else None


def _drop_foundry_v1_key_reference(credentials: object) -> None:
    if isinstance(credentials, MutableMapping):
        fields = cast(MutableMapping[object, object], credentials)
        fields.clear()


def _connection_type_for_resource(resource: DiscoveredResource) -> str:
    if resource.provider == "azure-storage" and resource.resource_type.casefold() == _STORAGE_RESOURCE_TYPE.casefold():
        return _STORAGE_CONNECTION_TYPE
    if (
        resource.provider == "azure-cognitive-services"
        and resource.resource_type.casefold() == _COGNITIVE_RESOURCE_TYPE.casefold()
    ):
        return _COGNITIVE_CONNECTION_TYPE
    raise ProviderOperationError(
        "foundry-operation-contract-invalid",
        "A Foundry connection operation did not match the expected binding shape.",
    )


def _normalized_id(value: str) -> str:
    return value.rstrip("/").casefold()


def _warning(code: str, message: str, resource_id: str) -> DiscoveryWarning:
    return DiscoveryWarning(
        code=code,
        message=message,
        impact=WarningImpact.confirmation,
        category=WarningCategory.credential_binding,
        provider=_PROVIDER_NAME,
        resource_id=resource_id,
    )


def _http_warning(prefix: str, operation: str, resource_id: str, status: int | None) -> DiscoveryWarning:
    forbidden = status == 403
    status_text = f"HTTP {status}" if status is not None else "an Azure HTTP error"
    return _warning(
        f"{prefix}-forbidden" if forbidden else f"{prefix}-failed",
        f"{operation} failed with {status_text}.",
        resource_id,
    )


def _transport_warning(
    prefix: str,
    operation: str,
    resource_id: str,
    phase: str,
) -> DiscoveryWarning:
    return _warning(
        f"{prefix}-{phase}-failed",
        f"{operation} failed during Azure {phase} handling.",
        resource_id,
    )


def _operation_http_error(operation: str, status: int | None) -> ProviderOperationError:
    suffix = "forbidden" if status == 403 else "failed"
    status_text = f"HTTP {status}" if status is not None else "an Azure HTTP error"
    return ProviderOperationError(
        f"{operation}-{suffix}",
        f"The supported Foundry connection operation failed with {status_text}.",
    )


def _operation_transport_error(operation: str, phase: str) -> ProviderOperationError:
    return ProviderOperationError(
        f"{operation}-{phase}-failed",
        f"The supported Foundry connection operation failed during Azure {phase} handling.",
    )

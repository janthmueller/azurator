"""Reviewed provider for ``Microsoft.Storage/storageAccounts`` key pairs."""

from __future__ import annotations

from collections.abc import Sequence

from azure.core.exceptions import HttpResponseError, ServiceRequestError, ServiceResponseError
from azure.mgmt.storage.models import StorageAccountRegenerateKeyParameters

from azurator.clients import AzureClientFactory, StorageAccountLike, StorageAccountListKeysResultLike
from azurator.models import (
    CandidateInspection,
    CandidateInspectionStatus,
    DiscoveredResource,
    DiscoveryWarning,
    KeyAuthentication,
    KeySlot,
    ProviderCandidateResult,
    ProviderDiscovery,
    ProviderInfo,
    WarningCategory,
    WarningImpact,
)
from azurator.providers.base import (
    CandidateSink,
    KeyStateSink,
    ProviderOperationError,
    SecretSink,
)
from azurator.providers.resource_ids import ResourceCoordinates, ResourceIdError, resource_coordinates

_RESOURCE_TYPE = "Microsoft.Storage/storageAccounts"
_PROVIDER_NAME = "azure-storage"
_PROVIDER_CONTRACT_VERSION = "1"
STORAGE_KEY_SLOTS = ("key1", "key2")
STORAGE_PROVIDER_INFO = ProviderInfo(
    name=_PROVIDER_NAME,
    contract_version=_PROVIDER_CONTRACT_VERSION,
    resource_types=(_RESOURCE_TYPE,),
)
_BINDING_WARNING = "Metadata-only discovery did not inspect credential bindings containing these Storage keys."
_PERMISSION_WARNING = (
    "This read-only command did not call key retrieval or rotation APIs, so it did not test whether your account "
    "has permission to use them."
)


class StorageProvider:
    """Discover and operate the supported Storage Account two-key contract."""

    def __init__(self, clients: AzureClientFactory) -> None:
        self._clients = clients

    @property
    def info(self) -> ProviderInfo:
        return STORAGE_PROVIDER_INFO

    def discover(self, subscription_id: str) -> ProviderDiscovery:
        client = self._clients.storage_management(subscription_id)
        resources: list[DiscoveredResource] = []
        warnings: list[DiscoveryWarning] = []
        try:
            for account in client.storage_accounts.list():
                resource = self._map_account(account)
                if resource is None:
                    warnings.append(
                        DiscoveryWarning(
                            code="malformed-storage-metadata",
                            message=(
                                "Azure returned a Storage Account without the required ID, name, or exact resource "
                                "type; it was skipped."
                            ),
                            impact=WarningImpact.blocking,
                            category=WarningCategory.contract,
                            provider=_PROVIDER_NAME,
                        )
                    )
                else:
                    resources.append(resource)
        except HttpResponseError as error:
            status = error.status_code
            code = "storage-discovery-forbidden" if status == 403 else "storage-discovery-failed"
            status_text = f"HTTP {status}" if status is not None else "an Azure HTTP error"
            warnings.append(
                DiscoveryWarning(
                    code=code,
                    message=(
                        f"Storage Account discovery failed with {status_text}. "
                        "No Storage key-returning operation was attempted."
                    ),
                    impact=WarningImpact.blocking,
                    category=WarningCategory.contract,
                    provider=_PROVIDER_NAME,
                )
            )
        except ServiceRequestError:
            warnings.append(self._discovery_transport_warning("request"))
        except ServiceResponseError:
            warnings.append(self._discovery_transport_warning("response"))
        finally:
            client.close()

        warnings.append(
            DiscoveryWarning(
                code="storage-bindings-not-inspected",
                message=_BINDING_WARNING,
                impact=WarningImpact.confirmation,
                category=WarningCategory.credential_binding,
                provider=_PROVIDER_NAME,
            )
        )
        warnings.append(
            DiscoveryWarning(
                code="storage-key-permissions-not-tested",
                message=_PERMISSION_WARNING,
                impact=WarningImpact.advisory,
                category=WarningCategory.permission,
                provider=_PROVIDER_NAME,
            )
        )
        return ProviderDiscovery(resources=tuple(resources), warnings=tuple(warnings))

    def inspect_candidates(
        self,
        subscription_id: str,
        resources: Sequence[DiscoveredResource],
        consume: CandidateSink,
    ) -> ProviderCandidateResult:
        """Read declared Storage key slots and stream values directly to ``consume``."""

        client = self._clients.storage_management(subscription_id)
        inspections: list[CandidateInspection] = []
        warnings: list[DiscoveryWarning] = []
        try:
            for resource in resources:
                if not self._is_candidate_target(resource):
                    inspections.append(
                        CandidateInspection(
                            resource_id=resource.resource_id,
                            status=CandidateInspectionStatus.unavailable,
                        )
                    )
                    warnings.append(
                        DiscoveryWarning(
                            code="storage-candidate-target-invalid",
                            message="A Storage resource returned unexpected metadata and could not be inspected safely.",
                            impact=WarningImpact.blocking,
                            category=WarningCategory.contract,
                            provider=_PROVIDER_NAME,
                            resource_id=resource.resource_id,
                        )
                    )
                    continue

                try:
                    coordinates = resource_coordinates(
                        resource.resource_id,
                        subscription_id=subscription_id,
                        expected_resource_type=_RESOURCE_TYPE,
                        expected_name=resource.name,
                    )
                except ResourceIdError:
                    inspections.append(
                        CandidateInspection(
                            resource_id=resource.resource_id,
                            status=CandidateInspectionStatus.unavailable,
                        )
                    )
                    warnings.append(
                        DiscoveryWarning(
                            code="malformed-storage-resource-id",
                            message="A Storage Account resource ID could not safely scope key inspection.",
                            impact=WarningImpact.blocking,
                            category=WarningCategory.contract,
                            provider=_PROVIDER_NAME,
                            resource_id=resource.resource_id,
                        )
                    )
                    continue

                try:
                    response = client.storage_accounts.list_keys(
                        coordinates.resource_group,
                        coordinates.resource_name,
                        expand=None,
                        logging_enable=False,
                    )
                except HttpResponseError as error:
                    inspections.append(
                        CandidateInspection(
                            resource_id=resource.resource_id,
                            status=CandidateInspectionStatus.unavailable,
                        )
                    )
                    warnings.append(self._key_retrieval_warning(resource.resource_id, error.status_code))
                    continue
                except ServiceRequestError:
                    inspections.append(
                        CandidateInspection(
                            resource_id=resource.resource_id,
                            status=CandidateInspectionStatus.unavailable,
                        )
                    )
                    warnings.append(self._key_retrieval_transport_warning(resource.resource_id, "request"))
                    continue
                except ServiceResponseError:
                    inspections.append(
                        CandidateInspection(
                            resource_id=resource.resource_id,
                            status=CandidateInspectionStatus.unavailable,
                        )
                    )
                    warnings.append(self._key_retrieval_transport_warning(resource.resource_id, "response"))
                    continue

                values: dict[str, str] = {}
                try:
                    try:
                        values = self._exact_key_material(response)
                    except ProviderOperationError:
                        inspections.append(
                            CandidateInspection(
                                resource_id=resource.resource_id,
                                status=CandidateInspectionStatus.unavailable,
                            )
                        )
                        warnings.append(
                            DiscoveryWarning(
                                code="storage-key-response-incomplete",
                                message=(
                                    "Azure returned Storage key metadata outside the supported two-slot contract; "
                                    "no slots were compared."
                                ),
                                impact=WarningImpact.blocking,
                                category=WarningCategory.contract,
                                provider=_PROVIDER_NAME,
                                resource_id=resource.resource_id,
                            )
                        )
                        continue

                    for slot in STORAGE_KEY_SLOTS:
                        consume(resource.resource_id, slot, values[slot])
                    inspections.append(
                        CandidateInspection(
                            resource_id=resource.resource_id,
                            status=CandidateInspectionStatus.compared,
                            key_slots=STORAGE_KEY_SLOTS,
                        )
                    )
                finally:
                    values.clear()
                    del response
        finally:
            client.close()

        return ProviderCandidateResult(inspections=tuple(inspections), warnings=tuple(warnings))

    def use_key_slot(
        self,
        subscription_id: str,
        resource: DiscoveredResource,
        key_slot: str,
        consume: SecretSink,
    ) -> None:
        """Expose one supported key slot only to an in-process operation callback."""

        self._operation_coordinates(subscription_id, resource, key_slot, require_rotatable=False)

        def consume_selected(slot: str, value: str) -> None:
            if slot == key_slot:
                consume(value)

        self.use_key_state(subscription_id, resource, consume_selected)

    def use_key_state(
        self,
        subscription_id: str,
        resource: DiscoveredResource,
        consume: KeyStateSink,
    ) -> None:
        """Stream the exact supported Storage key pair into an in-process callback."""

        coordinates = self._key_state_coordinates(subscription_id, resource)
        client = self._clients.storage_management(subscription_id)
        values: dict[str, str] = {}
        try:
            try:
                response = client.storage_accounts.list_keys(
                    coordinates.resource_group,
                    coordinates.resource_name,
                    expand=None,
                    logging_enable=False,
                )
            except HttpResponseError as error:
                raise self._operation_http_error("storage-key-read", error.status_code) from None
            except ServiceRequestError:
                raise self._operation_transport_error("storage-key-read", "request") from None
            except ServiceResponseError:
                raise self._operation_transport_error("storage-key-read", "response") from None
            values = self._exact_key_material(response)
            del response
            for slot in STORAGE_KEY_SLOTS:
                consume(slot, values[slot])
        finally:
            values.clear()
            client.close()

    def regenerate_key(
        self,
        subscription_id: str,
        resource: DiscoveredResource,
        key_slot: str,
    ) -> None:
        """Submit one supported regeneration through the SDK policy and validate its response."""

        coordinates = self._operation_coordinates(subscription_id, resource, key_slot, require_rotatable=True)
        client = self._clients.storage_management(subscription_id)
        values: dict[str, str] = {}
        try:
            try:
                response = client.storage_accounts.regenerate_key(
                    coordinates.resource_group,
                    coordinates.resource_name,
                    StorageAccountRegenerateKeyParameters(key_name=key_slot),
                    logging_enable=False,
                )
            except HttpResponseError as error:
                raise self._operation_http_error("storage-key-regeneration", error.status_code) from None
            except ServiceRequestError:
                raise self._operation_transport_error("storage-key-regeneration", "request") from None
            except ServiceResponseError:
                raise self._operation_transport_error("storage-key-regeneration", "response") from None
            values = self._exact_key_material(response)
            del response
        finally:
            values.clear()
            client.close()

    @staticmethod
    def _exact_key_material(response: StorageAccountListKeysResultLike) -> dict[str, str]:
        values: dict[str, str] = {}
        try:
            keys = response.keys_property
            if keys is None:
                raise TypeError
            for key in keys:
                key_name = key.key_name
                value = key.value
                if key_name not in STORAGE_KEY_SLOTS or key_name in values or not isinstance(value, str) or not value:
                    raise TypeError
                values[key_name] = value
        except (AttributeError, TypeError):
            values.clear()
            raise ProviderOperationError(
                "storage-key-response-invalid",
                "Azure returned a Storage key response outside the supported two-slot contract.",
            ) from None
        if set(values) != set(STORAGE_KEY_SLOTS):
            values.clear()
            raise ProviderOperationError(
                "storage-key-response-invalid",
                "Azure returned a Storage key response outside the supported two-slot contract.",
            )
        return values

    @staticmethod
    def _operation_coordinates(
        subscription_id: str,
        resource: DiscoveredResource,
        key_slot: str,
        *,
        require_rotatable: bool,
    ) -> ResourceCoordinates:
        declared = {slot.name: slot for slot in resource.key_slots}
        slot = declared.get(key_slot)
        if (
            resource.provider != _PROVIDER_NAME
            or resource.resource_type.casefold() != _RESOURCE_TYPE.casefold()
            or resource.key_authentication is not KeyAuthentication.enabled
            or slot is None
            or not slot.values_retrievable
            or (require_rotatable and not slot.rotatable)
        ):
            raise ProviderOperationError(
                "storage-operation-contract-invalid",
                "A Storage operation target did not match the expected key-resource shape.",
            )
        try:
            return resource_coordinates(
                resource.resource_id,
                subscription_id=subscription_id,
                expected_resource_type=_RESOURCE_TYPE,
                expected_name=resource.name,
            )
        except ResourceIdError:
            raise ProviderOperationError(
                "storage-operation-contract-invalid",
                "A Storage operation target did not match the expected key-resource shape.",
            ) from None

    @classmethod
    def _key_state_coordinates(
        cls,
        subscription_id: str,
        resource: DiscoveredResource,
    ) -> ResourceCoordinates:
        coordinates = cls._operation_coordinates(
            subscription_id,
            resource,
            STORAGE_KEY_SLOTS[0],
            require_rotatable=False,
        )
        cls._operation_coordinates(
            subscription_id,
            resource,
            STORAGE_KEY_SLOTS[1],
            require_rotatable=False,
        )
        return coordinates

    @staticmethod
    def _operation_http_error(operation: str, status: int | None) -> ProviderOperationError:
        suffix = "forbidden" if status == 403 else "failed"
        status_text = f"HTTP {status}" if status is not None else "an Azure HTTP error"
        return ProviderOperationError(
            f"{operation}-{suffix}",
            f"The supported Storage operation failed with {status_text}.",
        )

    @staticmethod
    def _operation_transport_error(operation: str, phase: str) -> ProviderOperationError:
        return ProviderOperationError(
            f"{operation}-{phase}-failed",
            f"The supported Storage operation failed during Azure {phase} handling.",
        )

    @staticmethod
    def _is_candidate_target(resource: DiscoveredResource) -> bool:
        return (
            resource.provider == _PROVIDER_NAME
            and resource.resource_type.casefold() == _RESOURCE_TYPE.casefold()
            and resource.key_authentication is KeyAuthentication.enabled
            and any(slot.values_retrievable for slot in resource.key_slots)
        )

    @staticmethod
    def _key_retrieval_warning(resource_id: str, status: int | None) -> DiscoveryWarning:
        forbidden = status == 403
        status_text = f"HTTP {status}" if status is not None else "an Azure HTTP error"
        return DiscoveryWarning(
            code="storage-key-retrieval-forbidden" if forbidden else "storage-key-retrieval-failed",
            message=f"Storage key inspection failed with {status_text}.",
            impact=WarningImpact.blocking,
            category=WarningCategory.contract,
            provider=_PROVIDER_NAME,
            resource_id=resource_id,
        )

    @staticmethod
    def _discovery_transport_warning(phase: str) -> DiscoveryWarning:
        return DiscoveryWarning(
            code="storage-discovery-failed",
            message=(
                f"Storage Account discovery failed during Azure {phase} handling. "
                "No Storage key-returning operation was attempted."
            ),
            impact=WarningImpact.blocking,
            category=WarningCategory.contract,
            provider=_PROVIDER_NAME,
        )

    @staticmethod
    def _key_retrieval_transport_warning(resource_id: str, phase: str) -> DiscoveryWarning:
        return DiscoveryWarning(
            code="storage-key-retrieval-failed",
            message=f"Storage key inspection failed during Azure {phase} handling.",
            impact=WarningImpact.blocking,
            category=WarningCategory.contract,
            provider=_PROVIDER_NAME,
            resource_id=resource_id,
        )

    @staticmethod
    def _map_account(account: StorageAccountLike) -> DiscoveredResource | None:
        account_id = account.id
        account_name = account.name
        account_type = account.type
        if (
            not account_id
            or not account_name
            or not account_type
            or account_type.casefold() != _RESOURCE_TYPE.casefold()
        ):
            return None

        shared_keys_enabled = account.allow_shared_key_access is not False
        key_authentication = KeyAuthentication.enabled if shared_keys_enabled else KeyAuthentication.disabled
        slots = tuple(
            KeySlot(name=name, values_retrievable=shared_keys_enabled, rotatable=shared_keys_enabled)
            for name in STORAGE_KEY_SLOTS
        )

        return DiscoveredResource(
            resource_id=account_id,
            name=account_name,
            resource_type=account_type,
            location=account.location,
            kind=account.kind,
            provider=_PROVIDER_NAME,
            key_authentication=key_authentication,
            key_slots=slots,
        )

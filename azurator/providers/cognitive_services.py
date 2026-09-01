"""Reviewed provider for ``Microsoft.CognitiveServices/accounts`` key pairs."""

from __future__ import annotations

from collections.abc import Sequence

from azure.core.exceptions import HttpResponseError, ServiceRequestError, ServiceResponseError

from azurator.clients import AzureClientFactory, CognitiveAccountLike, CognitiveApiKeysLike
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

_RESOURCE_TYPE = "Microsoft.CognitiveServices/accounts"
_PROVIDER_NAME = "azure-cognitive-services"
_PROVIDER_CONTRACT_VERSION = "1"
COGNITIVE_SERVICES_KEY_SLOTS = ("Key1", "Key2")
COGNITIVE_SERVICES_PROVIDER_INFO = ProviderInfo(
    name=_PROVIDER_NAME,
    contract_version=_PROVIDER_CONTRACT_VERSION,
    resource_types=(_RESOURCE_TYPE,),
)
_BINDING_WARNING = "Metadata-only discovery did not inspect credential bindings containing these AI account keys."
_PERMISSION_WARNING = (
    "This read-only command did not call key retrieval or regeneration APIs, so it did not test whether your account "
    "has permission to use them."
)


class CognitiveServicesProvider:
    """Discover and operate the supported Cognitive Services two-key contract."""

    def __init__(self, clients: AzureClientFactory) -> None:
        self._clients = clients

    @property
    def info(self) -> ProviderInfo:
        return COGNITIVE_SERVICES_PROVIDER_INFO

    def discover(self, subscription_id: str) -> ProviderDiscovery:
        client = self._clients.cognitive_services_management(subscription_id)
        resources: list[DiscoveredResource] = []
        warnings: list[DiscoveryWarning] = []
        try:
            for account in client.accounts.list():
                resource = self._map_account(account)
                if resource is None:
                    warnings.append(
                        DiscoveryWarning(
                            code="malformed-cognitive-services-metadata",
                            message=(
                                "Azure returned a Cognitive Services account without the required ID, name, exact "
                                "resource type, or account properties; it was skipped."
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
            code = "cognitive-services-discovery-forbidden" if status == 403 else "cognitive-services-discovery-failed"
            status_text = f"HTTP {status}" if status is not None else "an Azure HTTP error"
            warnings.append(
                DiscoveryWarning(
                    code=code,
                    message=(
                        f"Cognitive Services discovery failed with {status_text}. "
                        "No Cognitive Services key-returning operation was attempted."
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
                code="cognitive-services-bindings-not-inspected",
                message=_BINDING_WARNING,
                impact=WarningImpact.confirmation,
                category=WarningCategory.credential_binding,
                provider=_PROVIDER_NAME,
            )
        )
        warnings.append(
            DiscoveryWarning(
                code="cognitive-services-key-permissions-not-tested",
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
        """Read declared Cognitive key slots and stream values directly to ``consume``."""

        client = self._clients.cognitive_services_management(subscription_id)
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
                            code="cognitive-services-candidate-target-invalid",
                            message="An AI resource returned unexpected metadata and could not be inspected safely.",
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
                            code="malformed-cognitive-services-resource-id",
                            message="An AI resource ID could not safely scope key inspection.",
                            impact=WarningImpact.blocking,
                            category=WarningCategory.contract,
                            provider=_PROVIDER_NAME,
                            resource_id=resource.resource_id,
                        )
                    )
                    continue

                try:
                    response = client.accounts.list_keys(
                        coordinates.resource_group,
                        coordinates.resource_name,
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
                                code="cognitive-services-key-response-incomplete",
                                message=(
                                    "Azure returned AI key metadata outside the supported two-slot contract; "
                                    "no slots were compared."
                                ),
                                impact=WarningImpact.blocking,
                                category=WarningCategory.contract,
                                provider=_PROVIDER_NAME,
                                resource_id=resource.resource_id,
                            )
                        )
                        continue

                    for slot in COGNITIVE_SERVICES_KEY_SLOTS:
                        consume(resource.resource_id, slot, values[slot])
                    inspections.append(
                        CandidateInspection(
                            resource_id=resource.resource_id,
                            status=CandidateInspectionStatus.compared,
                            key_slots=COGNITIVE_SERVICES_KEY_SLOTS,
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
        """Expose one supported Cognitive key only to an in-process callback."""

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
        """Stream the exact supported Cognitive key pair into an in-process callback."""

        coordinates = self._key_state_coordinates(subscription_id, resource)
        client = self._clients.cognitive_services_management(subscription_id)
        values: dict[str, str] = {}
        try:
            try:
                response = client.accounts.list_keys(
                    coordinates.resource_group,
                    coordinates.resource_name,
                    logging_enable=False,
                )
            except HttpResponseError as error:
                raise self._operation_http_error("cognitive-services-key-read", error.status_code) from None
            except ServiceRequestError:
                raise self._operation_transport_error("cognitive-services-key-read", "request") from None
            except ServiceResponseError:
                raise self._operation_transport_error("cognitive-services-key-read", "response") from None
            values = self._exact_key_material(response)
            del response
            for slot in COGNITIVE_SERVICES_KEY_SLOTS:
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
        client = self._clients.cognitive_services_management(subscription_id)
        values: dict[str, str] = {}
        try:
            try:
                regenerated = client.accounts.regenerate_key(
                    coordinates.resource_group,
                    coordinates.resource_name,
                    key_slot,
                    logging_enable=False,
                )
            except HttpResponseError as error:
                raise self._operation_http_error("cognitive-services-key-regeneration", error.status_code) from None
            except ServiceRequestError:
                raise self._operation_transport_error("cognitive-services-key-regeneration", "request") from None
            except ServiceResponseError:
                raise self._operation_transport_error(
                    "cognitive-services-key-regeneration",
                    "response",
                ) from None
            values = self._exact_key_material(regenerated)
            del regenerated
        finally:
            values.clear()
            client.close()

    @staticmethod
    def _exact_key_material(response: CognitiveApiKeysLike) -> dict[str, str]:
        try:
            key1 = response.key1
            key2 = response.key2
        except AttributeError:
            raise ProviderOperationError(
                "cognitive-services-key-response-invalid",
                "Azure returned a Cognitive key response outside the supported two-slot contract.",
            ) from None
        if not isinstance(key1, str) or not key1 or not isinstance(key2, str) or not key2:
            key1 = ""
            key2 = ""
            raise ProviderOperationError(
                "cognitive-services-key-response-invalid",
                "Azure returned a Cognitive key response outside the supported two-slot contract.",
            )
        return {"Key1": key1, "Key2": key2}

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
                "cognitive-services-operation-contract-invalid",
                "A Cognitive Services operation target did not match the expected key-resource shape.",
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
                "cognitive-services-operation-contract-invalid",
                "A Cognitive Services operation target did not match the expected key-resource shape.",
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
            COGNITIVE_SERVICES_KEY_SLOTS[0],
            require_rotatable=False,
        )
        cls._operation_coordinates(
            subscription_id,
            resource,
            COGNITIVE_SERVICES_KEY_SLOTS[1],
            require_rotatable=False,
        )
        return coordinates

    @staticmethod
    def _operation_http_error(operation: str, status: int | None) -> ProviderOperationError:
        suffix = "forbidden" if status == 403 else "failed"
        status_text = f"HTTP {status}" if status is not None else "an Azure HTTP error"
        return ProviderOperationError(
            f"{operation}-{suffix}",
            f"The supported Cognitive Services operation failed with {status_text}.",
        )

    @staticmethod
    def _operation_transport_error(operation: str, phase: str) -> ProviderOperationError:
        return ProviderOperationError(
            f"{operation}-{phase}-failed",
            f"The supported Cognitive Services operation failed during Azure {phase} handling.",
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
            code=(
                "cognitive-services-key-retrieval-forbidden" if forbidden else "cognitive-services-key-retrieval-failed"
            ),
            message=f"AI key inspection failed with {status_text}.",
            impact=WarningImpact.blocking,
            category=WarningCategory.contract,
            provider=_PROVIDER_NAME,
            resource_id=resource_id,
        )

    @staticmethod
    def _discovery_transport_warning(phase: str) -> DiscoveryWarning:
        return DiscoveryWarning(
            code="cognitive-services-discovery-failed",
            message=(
                f"Cognitive Services discovery failed during Azure {phase} handling. "
                "No Cognitive Services key-returning operation was attempted."
            ),
            impact=WarningImpact.blocking,
            category=WarningCategory.contract,
            provider=_PROVIDER_NAME,
        )

    @staticmethod
    def _key_retrieval_transport_warning(resource_id: str, phase: str) -> DiscoveryWarning:
        return DiscoveryWarning(
            code="cognitive-services-key-retrieval-failed",
            message=f"AI key inspection failed during Azure {phase} handling.",
            impact=WarningImpact.blocking,
            category=WarningCategory.contract,
            provider=_PROVIDER_NAME,
            resource_id=resource_id,
        )

    @staticmethod
    def _map_account(account: CognitiveAccountLike) -> DiscoveredResource | None:
        account_id = account.id
        account_name = account.name
        account_type = account.type
        properties = account.properties
        if (
            not account_id
            or not account_name
            or not account_type
            or account_type.casefold() != _RESOURCE_TYPE.casefold()
            or properties is None
        ):
            return None

        # The stable Azure response uses a nullable disabling predicate: only
        # ``true`` disables keys; key-enabled legacy/default accounts can return
        # either ``false`` or ``null``.
        local_auth_disabled = properties.disable_local_auth is True
        keys_enabled = not local_auth_disabled
        key_authentication = KeyAuthentication.enabled if keys_enabled else KeyAuthentication.disabled
        slots = tuple(
            KeySlot(name=name, values_retrievable=keys_enabled, rotatable=keys_enabled)
            for name in COGNITIVE_SERVICES_KEY_SLOTS
        )

        return DiscoveredResource(
            resource_id=account_id,
            name=account_name,
            resource_type=account_type,
            location=account.location,
            kind=account.kind,
            endpoint=properties.endpoint,
            provider=_PROVIDER_NAME,
            key_authentication=key_authentication,
            key_slots=slots,
        )

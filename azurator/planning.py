"""Read-only generation of secret-free Azure key rotation plans."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Sequence
from datetime import datetime
from pathlib import Path

from azurator.discovery import utc_now
from azurator.models import (
    AzureBindingInspection,
    BindingInspection,
    BindingInspectionStatus,
    BindingManagement,
    CandidateInspection,
    CandidateInspectionStatus,
    CredentialBinding,
    DiscoveryWarning,
    MatchReport,
    MatchResource,
    PlanSource,
    PlanState,
    PlanStep,
    PlanStepAction,
    PlanStepPhase,
    PlanWarning,
    PreconditionDigest,
    ProviderInfo,
    RotationPlan,
    ScheduledKeySlot,
    SelectionReport,
    WarningCategory,
    WarningImpact,
)


class PlanningError(RuntimeError):
    """A match report could not be converted into a valid secret-free plan."""


class PlanningService:
    """Turn one read-only match report into a deterministic rotation sequence."""

    def __init__(
        self,
        *,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self._clock = clock

    def create(self, report: MatchReport, tenant_id: str) -> RotationPlan:
        """Generate a plan from ephemeral dotenv matching without mutating Azure."""

        resources_by_id = self._index_resources(report.resources)
        inspections_by_id = self._index_inspections(report.inspections)
        scheduled_slots = self._schedule_slots(report, resources_by_id, inspections_by_id)
        return self._create_plan(
            tenant_id=tenant_id,
            subscription_id=report.subscription_id,
            subscription_name=report.subscription_name,
            azure_binding_inspection=report.azure_binding_inspection,
            providers=report.providers,
            report_resources=report.resources,
            inspections=report.inspections,
            scheduled_slots=scheduled_slots,
            report_binding_inspections=report.binding_inspections,
            report_bindings=report.bindings,
            report_warnings=report.warnings,
            source_format=PlanSource.dotenv_stdin,
            source_path=None,
            source_selectors=report.input_selectors,
            skipped_empty_selectors=report.skipped_empty_selectors,
            incomplete=self._matching_incomplete(report),
        )

    def create_dotenv_file(self, report: MatchReport, tenant_id: str, source_path: str) -> RotationPlan:
        """Generate a plan that manages matched assignments in one exact plaintext dotenv file."""

        if not source_path or not Path(source_path).is_absolute():
            raise PlanningError("the managed dotenv source path must be absolute")
        resources_by_id = self._index_resources(report.resources)
        inspections_by_id = self._index_inspections(report.inspections)
        scheduled_slots = self._schedule_slots(report, resources_by_id, inspections_by_id)
        return self._create_plan(
            tenant_id=tenant_id,
            subscription_id=report.subscription_id,
            subscription_name=report.subscription_name,
            azure_binding_inspection=report.azure_binding_inspection,
            providers=report.providers,
            report_resources=report.resources,
            inspections=report.inspections,
            scheduled_slots=scheduled_slots,
            report_binding_inspections=report.binding_inspections,
            report_bindings=report.bindings,
            report_warnings=report.warnings,
            source_format=PlanSource.dotenv_file,
            source_path=source_path,
            source_selectors=report.input_selectors,
            skipped_empty_selectors=report.skipped_empty_selectors,
            incomplete=self._matching_incomplete(report),
        )

    def create_sops_dotenv_file(self, report: MatchReport, tenant_id: str, source_path: str) -> RotationPlan:
        """Generate a plan that manages matched assignments in one exact SOPS-encrypted dotenv file."""

        if not source_path or not Path(source_path).is_absolute():
            raise PlanningError("the managed SOPS dotenv source path must be absolute")
        resources_by_id = self._index_resources(report.resources)
        inspections_by_id = self._index_inspections(report.inspections)
        scheduled_slots = self._schedule_slots(report, resources_by_id, inspections_by_id)
        return self._create_plan(
            tenant_id=tenant_id,
            subscription_id=report.subscription_id,
            subscription_name=report.subscription_name,
            azure_binding_inspection=report.azure_binding_inspection,
            providers=report.providers,
            report_resources=report.resources,
            inspections=report.inspections,
            scheduled_slots=scheduled_slots,
            report_binding_inspections=report.binding_inspections,
            report_bindings=report.bindings,
            report_warnings=report.warnings,
            source_format=PlanSource.sops_dotenv_file,
            source_path=source_path,
            source_selectors=report.input_selectors,
            skipped_empty_selectors=report.skipped_empty_selectors,
            incomplete=self._matching_incomplete(report),
        )

    def create_selection(self, report: SelectionReport, tenant_id: str) -> RotationPlan:
        """Generate a plan from explicit resource/slot selection without mutating Azure."""

        resources_by_id = self._index_resources(report.resources)
        inspections_by_id = self._index_inspections(report.inspections)
        scheduled_slots = self._schedule_selected_slots(report, resources_by_id, inspections_by_id)
        return self._create_plan(
            tenant_id=tenant_id,
            subscription_id=report.subscription_id,
            subscription_name=report.subscription_name,
            azure_binding_inspection=report.azure_binding_inspection,
            providers=report.providers,
            report_resources=report.resources,
            inspections=report.inspections,
            scheduled_slots=scheduled_slots,
            report_binding_inspections=report.binding_inspections,
            report_bindings=report.bindings,
            report_warnings=report.warnings,
            source_format=PlanSource.direct_selection,
            source_path=None,
            source_selectors=(),
            skipped_empty_selectors=(),
            incomplete=self._selection_incomplete(report),
        )

    def _create_plan(
        self,
        *,
        tenant_id: str,
        subscription_id: str,
        subscription_name: str | None,
        azure_binding_inspection: AzureBindingInspection,
        providers: tuple[ProviderInfo, ...],
        report_resources: tuple[MatchResource, ...],
        inspections: tuple[CandidateInspection, ...],
        scheduled_slots: tuple[ScheduledKeySlot, ...],
        report_binding_inspections: tuple[BindingInspection, ...],
        report_bindings: tuple[CredentialBinding, ...],
        report_warnings: tuple[DiscoveryWarning, ...],
        source_format: PlanSource,
        source_path: str | None,
        source_selectors: tuple[str, ...],
        skipped_empty_selectors: tuple[str, ...],
        incomplete: bool,
    ) -> RotationPlan:
        normalized_tenant_id = tenant_id.strip()
        if not normalized_tenant_id:
            raise PlanningError("the selected Azure tenant ID is unavailable")

        resources_by_id = self._index_resources(report_resources)
        inspections_by_id = self._index_inspections(inspections)
        selected_resource_ids = {slot.resource_id for slot in scheduled_slots}
        resources = tuple(resource for resource in report_resources if resource.resource_id in selected_resource_ids)
        binding_inspections = tuple(
            inspection for inspection in report_binding_inspections if inspection.resource_id in selected_resource_ids
        )
        bindings = tuple(binding for binding in report_bindings if binding.key_resource_id in selected_resource_ids)

        warnings = [
            self._from_discovery_warning(warning)
            for warning in report_warnings
            if warning.resource_id is None
            or warning.resource_id in selected_resource_ids
            or warning.impact is not WarningImpact.advisory
        ]
        self._add_candidate_inspection_warnings(inspections, resources_by_id, warnings, source_format)
        self._add_binding_inspection_warnings(binding_inspections, resources_by_id, warnings)
        self._add_unknown_slot_warnings(bindings, resources_by_id, warnings)

        steps: list[PlanStep] = []
        blocked = incomplete
        for resource in resources:
            selected = tuple(slot for slot in scheduled_slots if slot.resource_id == resource.resource_id)
            resource_bindings = tuple(
                binding for binding in bindings if binding.key_resource_id == resource.resource_id
            )
            resource_steps, resource_blocked = self._plan_resource(
                resource,
                selected,
                inspections_by_id[resource.resource_id],
                resource_bindings,
                warnings,
                start_sequence=len(steps) + 1,
            )
            steps.extend(resource_steps)
            blocked = blocked or resource_blocked

        blocked = blocked or any(warning.impact is WarningImpact.blocking for warning in warnings)
        if blocked:
            state = PlanState.blocked
        elif not scheduled_slots:
            state = PlanState.no_changes
        elif any(warning.impact is WarningImpact.confirmation for warning in warnings):
            state = PlanState.confirmation_required
        else:
            state = PlanState.ready

        warnings_tuple = self._deduplicate_warnings(warnings)
        precondition = self._planning_precondition(
            subscription_id,
            providers,
            resources,
            scheduled_slots,
            binding_inspections,
            bindings,
            azure_binding_inspection,
            source_format,
            source_path,
            source_selectors,
            skipped_empty_selectors,
        )
        return RotationPlan(
            tenant_id=normalized_tenant_id,
            subscription_id=subscription_id,
            subscription_name=subscription_name,
            created_at=self._clock(),
            source_format=source_format,
            azure_binding_inspection=azure_binding_inspection,
            source_path=source_path,
            source_selectors=source_selectors,
            skipped_empty_selectors=skipped_empty_selectors,
            providers=providers,
            resources=resources,
            scheduled_slots=scheduled_slots,
            binding_inspections=binding_inspections,
            bindings=bindings,
            steps=tuple(steps),
            state=state,
            warnings=warnings_tuple,
            preconditions=(precondition,),
        )

    @staticmethod
    def _index_resources(resources: Sequence[MatchResource]) -> dict[str, MatchResource]:
        indexed: dict[str, MatchResource] = {}
        normalized_ids: set[str] = set()
        for resource in resources:
            normalized_id = resource.resource_id.casefold()
            slot_names = [slot.name for slot in resource.key_slots]
            if normalized_id in normalized_ids or len(slot_names) != len(set(slot_names)):
                raise PlanningError("the match report contains conflicting resource metadata")
            normalized_ids.add(normalized_id)
            indexed[resource.resource_id] = resource
        return indexed

    @staticmethod
    def _index_inspections(inspections: Sequence[CandidateInspection]) -> dict[str, CandidateInspection]:
        indexed: dict[str, CandidateInspection] = {}
        for inspection in inspections:
            if inspection.resource_id in indexed:
                raise PlanningError("the match report contains duplicate candidate inspections")
            indexed[inspection.resource_id] = inspection
        return indexed

    @staticmethod
    def _schedule_slots(
        report: MatchReport,
        resources_by_id: dict[str, MatchResource],
        inspections_by_id: dict[str, CandidateInspection],
    ) -> tuple[ScheduledKeySlot, ...]:
        selectors_by_slot: dict[tuple[str, str], list[str]] = {}
        for match in report.matches:
            resource = resources_by_id.get(match.resource_id)
            inspection = inspections_by_id.get(match.resource_id)
            if resource is None or inspection is None:
                raise PlanningError("the match report selected a slot without supported candidate metadata")
            declared_slots = {slot.name for slot in resource.key_slots}
            if (
                inspection.status is not CandidateInspectionStatus.compared
                or match.key_slot not in declared_slots
                or match.key_slot not in inspection.key_slots
            ):
                raise PlanningError("the match report selected a slot without supported candidate metadata")
            selectors = selectors_by_slot.setdefault((match.resource_id, match.key_slot), [])
            if match.input_selector not in selectors:
                selectors.append(match.input_selector)

        resource_order = {resource.resource_id: index for index, resource in enumerate(report.resources)}
        slot_order = {
            (resource.resource_id, slot.name): index
            for resource in report.resources
            for index, slot in enumerate(resource.key_slots)
        }
        return tuple(
            ScheduledKeySlot(resource_id=resource_id, key_slot=key_slot, input_selectors=tuple(selectors))
            for (resource_id, key_slot), selectors in sorted(
                selectors_by_slot.items(),
                key=lambda item: (
                    resource_order[item[0][0]],
                    slot_order[(item[0][0], item[0][1])],
                ),
            )
        )

    @staticmethod
    def _schedule_selected_slots(
        report: SelectionReport,
        resources_by_id: dict[str, MatchResource],
        inspections_by_id: dict[str, CandidateInspection],
    ) -> tuple[ScheduledKeySlot, ...]:
        selected: list[ScheduledKeySlot] = []
        identities: set[tuple[str, str]] = set()
        for selection in report.selected_slots:
            resource = resources_by_id.get(selection.resource_id)
            if resource is None or selection.resource_id not in inspections_by_id:
                raise PlanningError("the selection report contains a slot without supported resource metadata")
            declared_slots = {slot.name for slot in resource.key_slots}
            identity = (selection.resource_id, selection.key_slot)
            if selection.key_slot not in declared_slots or identity in identities:
                raise PlanningError("the selection report contains conflicting key-slot metadata")
            identities.add(identity)
            selected.append(
                ScheduledKeySlot(
                    resource_id=selection.resource_id,
                    key_slot=selection.key_slot,
                    input_selectors=(),
                )
            )

        resource_order = {resource.resource_id: index for index, resource in enumerate(report.resources)}
        slot_order = {
            (resource.resource_id, slot.name): index
            for resource in report.resources
            for index, slot in enumerate(resource.key_slots)
        }
        return tuple(
            sorted(
                selected,
                key=lambda item: (
                    resource_order[item.resource_id],
                    slot_order[(item.resource_id, item.key_slot)],
                ),
            )
        )

    def _plan_resource(
        self,
        resource: MatchResource,
        selected: tuple[ScheduledKeySlot, ...],
        inspection: CandidateInspection,
        bindings: tuple[CredentialBinding, ...],
        warnings: list[PlanWarning],
        *,
        start_sequence: int,
    ) -> tuple[list[PlanStep], bool]:
        if len(resource.key_slots) != 2 or len(selected) > 2:
            warnings.append(
                PlanWarning(
                    code="unsupported-key-slot-layout",
                    message=(f"{resource.name} does not expose the supported two-slot layout required by the planner."),
                    impact=WarningImpact.blocking,
                    category=WarningCategory.contract,
                    provider=resource.provider,
                    resource_id=resource.resource_id,
                )
            )
            return [], True

        expected_inspection_slots = {slot.name for slot in resource.key_slots if slot.values_retrievable}
        if (
            inspection.status is not CandidateInspectionStatus.compared
            or set(inspection.key_slots) != expected_inspection_slots
        ):
            return [], True

        incomplete_managed = [
            binding
            for binding in bindings
            if binding.management is BindingManagement.update_and_verify and not binding.target
        ]
        if incomplete_managed:
            warnings.append(
                PlanWarning(
                    code="managed-binding-contract-incomplete",
                    message=(
                        f"{resource.name} has a managed binding without the target metadata required for "
                        "a supported update and verification."
                    ),
                    impact=WarningImpact.blocking,
                    category=WarningCategory.credential_binding,
                    provider=incomplete_managed[0].provider,
                    resource_id=resource.resource_id,
                )
            )
            return [], True

        declared = {slot.name: slot for slot in resource.key_slots}
        non_rotatable = [slot.key_slot for slot in selected if not declared[slot.key_slot].rotatable]
        if non_rotatable:
            warnings.append(
                PlanWarning(
                    code="selected-slot-not-rotatable",
                    message=(
                        f"{resource.name} has selected key slots that Azurator cannot rotate: "
                        f"{', '.join(non_rotatable)}."
                    ),
                    impact=WarningImpact.blocking,
                    category=WarningCategory.contract,
                    provider=resource.provider,
                    resource_id=resource.resource_id,
                )
            )
            return [], True

        steps: list[PlanStep] = []
        selected_names = tuple(slot.key_slot for slot in selected)
        if len(selected_names) == 1:
            selected_slot = selected_names[0]
            sibling_slot = next(slot.name for slot in resource.key_slots if slot.name != selected_slot)
            sibling = declared[sibling_slot]
            sibling_usable = sibling.values_retrievable and sibling_slot in inspection.key_slots
            affected = tuple(
                binding for binding in bindings if binding.key_slot is None or binding.key_slot == selected_slot
            )
            if self._block_unautomatable_bindings(resource, affected, warnings):
                return [], True
            if affected and sibling_usable:
                self._append_transitions(
                    steps,
                    affected,
                    resource.resource_id,
                    sibling_slot,
                    PlanStepPhase.bridge,
                    start_sequence,
                )
                self._append_regeneration(
                    steps,
                    resource.resource_id,
                    selected_slot,
                    start_sequence,
                )
                self._append_transitions(
                    steps,
                    affected,
                    resource.resource_id,
                    selected_slot,
                    PlanStepPhase.finalize,
                    start_sequence,
                )
            else:
                self._append_regeneration(
                    steps,
                    resource.resource_id,
                    selected_slot,
                    start_sequence,
                )
                if affected:
                    warnings.append(
                        PlanWarning(
                            code="expected-binding-interruption",
                            message=(
                                f"{resource.name} {selected_slot} has an affected connection, but "
                                f"{sibling_slot} was not available as a bridge."
                            ),
                            impact=WarningImpact.confirmation,
                            category=WarningCategory.credential_binding,
                            provider=resource.provider,
                            resource_id=resource.resource_id,
                        )
                    )
                    self._append_transitions(
                        steps,
                        affected,
                        resource.resource_id,
                        selected_slot,
                        PlanStepPhase.finalize,
                        start_sequence,
                    )
        elif len(selected_names) == 2:
            if self._block_unautomatable_bindings(resource, bindings, warnings):
                return [], True
            primary_slot, bridge_slot = (slot.name for slot in resource.key_slots)
            bridge = declared[bridge_slot]
            if not bridge.values_retrievable or bridge_slot not in inspection.key_slots:
                warnings.append(
                    PlanWarning(
                        code="selected-slots-have-no-usable-bridge",
                        message=f"{resource.name} has no supported usable slot for the two-slot bridge sequence.",
                        impact=WarningImpact.blocking,
                        category=WarningCategory.contract,
                        provider=resource.provider,
                        resource_id=resource.resource_id,
                    )
                )
                return [], True

            bridge_moves = tuple(binding for binding in bindings if binding.key_slot != bridge_slot)
            self._append_transitions(
                steps,
                bridge_moves,
                resource.resource_id,
                bridge_slot,
                PlanStepPhase.bridge,
                start_sequence,
            )
            self._append_regeneration(
                steps,
                resource.resource_id,
                primary_slot,
                start_sequence,
            )
            self._append_transitions(
                steps,
                bindings,
                resource.resource_id,
                primary_slot,
                PlanStepPhase.finalize,
                start_sequence,
            )
            self._append_regeneration(
                steps,
                resource.resource_id,
                bridge_slot,
                start_sequence,
            )
            original_bridge_bindings = tuple(binding for binding in bindings if binding.key_slot == bridge_slot)
            self._append_transitions(
                steps,
                original_bridge_bindings,
                resource.resource_id,
                bridge_slot,
                PlanStepPhase.finalize,
                start_sequence,
            )

        return steps, False

    @staticmethod
    def _block_unautomatable_bindings(
        resource: MatchResource,
        bindings: Sequence[CredentialBinding],
        warnings: list[PlanWarning],
    ) -> bool:
        blocked = False
        for binding in bindings:
            if binding.management is BindingManagement.update_and_verify:
                continue
            blocked = True
            warnings.append(
                PlanWarning(
                    code="binding-automation-unavailable",
                    message=(
                        f"Binding {binding.scope_name}/{binding.name} may require a credential change for "
                        f"the rotation of {resource.name}, but "
                        "Azurator cannot update and verify automatically."
                    ),
                    impact=WarningImpact.blocking,
                    category=WarningCategory.credential_binding,
                    provider=binding.provider,
                    resource_id=resource.resource_id,
                    binding_id=binding.binding_id,
                )
            )
        return blocked

    @staticmethod
    def _append_transitions(
        steps: list[PlanStep],
        bindings: Sequence[CredentialBinding],
        resource_id: str,
        key_slot: str,
        phase: PlanStepPhase,
        start_sequence: int,
    ) -> None:
        for binding in bindings:
            if binding.management is not BindingManagement.update_and_verify:
                raise PlanningError("an automatic binding transition requires a managed binding contract")
            for action in (PlanStepAction.update_binding, PlanStepAction.verify_binding):
                steps.append(
                    PlanStep(
                        sequence=start_sequence + len(steps),
                        action=action,
                        phase=phase,
                        resource_id=resource_id,
                        key_slot=key_slot,
                        binding_id=binding.binding_id,
                    )
                )

    @staticmethod
    def _append_regeneration(
        steps: list[PlanStep],
        resource_id: str,
        key_slot: str,
        start_sequence: int,
    ) -> None:
        steps.append(
            PlanStep(
                sequence=start_sequence + len(steps),
                action=PlanStepAction.regenerate_key,
                phase=PlanStepPhase.rotate,
                resource_id=resource_id,
                key_slot=key_slot,
            )
        )

    @staticmethod
    def _from_discovery_warning(warning: DiscoveryWarning) -> PlanWarning:
        return PlanWarning(
            code=warning.code,
            message=warning.message,
            impact=warning.impact,
            category=warning.category,
            provider=warning.provider,
            resource_id=warning.resource_id,
        )

    @staticmethod
    def _matching_incomplete(report: MatchReport) -> bool:
        return PlanningService._candidate_inspection_incomplete(
            report.resources,
            report.inspections,
        ) or any(warning.impact is WarningImpact.blocking for warning in report.warnings)

    @staticmethod
    def _selection_incomplete(report: SelectionReport) -> bool:
        return PlanningService._candidate_inspection_incomplete(
            report.resources,
            report.inspections,
        ) or any(warning.impact is WarningImpact.blocking for warning in report.warnings)

    @staticmethod
    def _candidate_inspection_incomplete(
        resources: Sequence[MatchResource],
        inspections: Sequence[CandidateInspection],
    ) -> bool:
        resources_by_id = {resource.resource_id: resource for resource in resources}
        if set(resources_by_id) != {inspection.resource_id for inspection in inspections}:
            return True
        return any(
            inspection.status is not CandidateInspectionStatus.compared
            or set(inspection.key_slots)
            != {slot.name for slot in resources_by_id[inspection.resource_id].key_slots if slot.values_retrievable}
            for inspection in inspections
        )

    @staticmethod
    def _add_candidate_inspection_warnings(
        inspections: Sequence[CandidateInspection],
        resources_by_id: dict[str, MatchResource],
        warnings: list[PlanWarning],
        source_format: PlanSource,
    ) -> None:
        for inspection in inspections:
            resource = resources_by_id.get(inspection.resource_id)
            expected_slots: set[str] = (
                {slot.name for slot in resource.key_slots if slot.values_retrievable} if resource is not None else set()
            )
            if inspection.status is CandidateInspectionStatus.compared and set(inspection.key_slots) == expected_slots:
                continue
            resource_name = resource.name if resource is not None else inspection.resource_id
            if source_format is PlanSource.direct_selection:
                message = (
                    f"Azure key inspection for {resource_name} was unavailable; "
                    "binding attribution and safe rotation planning could not complete."
                )
            else:
                message = (
                    f"Azure key comparison for {resource_name} was unavailable; "
                    "the supplied values could not be fully evaluated."
                )
            warnings.append(
                PlanWarning(
                    code="candidate-inspection-incomplete",
                    message=message,
                    impact=WarningImpact.blocking,
                    category=WarningCategory.contract,
                    resource_id=inspection.resource_id,
                )
            )

    @staticmethod
    def _add_binding_inspection_warnings(
        inspections: Sequence[BindingInspection],
        resources_by_id: dict[str, MatchResource],
        warnings: list[PlanWarning],
    ) -> None:
        for inspection in inspections:
            if inspection.status is BindingInspectionStatus.inspected:
                continue
            resource = resources_by_id[inspection.resource_id]
            warnings.append(
                PlanWarning(
                    code="binding-inspection-incomplete",
                    message=(
                        f"Binding inspection for {resource.name} was {inspection.status.value}; "
                        "additional bindings may be affected."
                    ),
                    impact=WarningImpact.blocking,
                    category=WarningCategory.credential_binding,
                    provider=inspection.provider,
                    resource_id=inspection.resource_id,
                )
            )

    @staticmethod
    def _add_unknown_slot_warnings(
        bindings: Sequence[CredentialBinding],
        resources_by_id: dict[str, MatchResource],
        warnings: list[PlanWarning],
    ) -> None:
        for binding in bindings:
            if binding.key_slot is not None:
                continue
            resource = resources_by_id[binding.key_resource_id]
            warnings.append(
                PlanWarning(
                    code="binding-key-slot-unknown",
                    message=(
                        f"Binding {binding.scope_name}/{binding.name} targets {resource.name}, but its "
                        "stored key could not be attributed to a slot."
                    ),
                    impact=WarningImpact.confirmation,
                    category=WarningCategory.credential_binding,
                    provider=binding.provider,
                    resource_id=binding.key_resource_id,
                    binding_id=binding.binding_id,
                )
            )

    @staticmethod
    def _deduplicate_warnings(warnings: Sequence[PlanWarning]) -> tuple[PlanWarning, ...]:
        unique: list[PlanWarning] = []
        seen: set[tuple[str, WarningImpact, WarningCategory, str | None, str | None, str]] = set()
        for warning in warnings:
            identity = (
                warning.code,
                warning.impact,
                warning.category,
                warning.resource_id,
                warning.binding_id,
                warning.message,
            )
            if identity not in seen:
                seen.add(identity)
                unique.append(warning)
        return tuple(unique)

    @staticmethod
    def _planning_precondition(
        subscription_id: str,
        providers: tuple[ProviderInfo, ...],
        resources: tuple[MatchResource, ...],
        scheduled_slots: tuple[ScheduledKeySlot, ...],
        binding_inspections: tuple[BindingInspection, ...],
        bindings: tuple[CredentialBinding, ...],
        azure_binding_inspection: AzureBindingInspection,
        source_format: PlanSource,
        source_path: str | None,
        source_selectors: tuple[str, ...],
        skipped_empty_selectors: tuple[str, ...],
    ) -> PreconditionDigest:
        snapshot = {
            "contract": "azurator-planning-snapshot-v1",
            "subscription_id": subscription_id,
            "azure_binding_inspection": azure_binding_inspection.value,
            "source_format": source_format.value,
            "source_path": source_path,
            "source_selectors": source_selectors,
            "skipped_empty_selectors": skipped_empty_selectors,
            "providers": [provider.model_dump(mode="json") for provider in providers],
            "resources": [resource.model_dump(mode="json") for resource in resources],
            "scheduled_slots": [slot.model_dump(mode="json") for slot in scheduled_slots],
            "binding_inspections": [inspection.model_dump(mode="json") for inspection in binding_inspections],
            "bindings": [binding.model_dump(mode="json") for binding in bindings],
        }
        canonical = json.dumps(snapshot, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return PreconditionDigest(
            subject="planning-snapshot",
            algorithm="sha256",
            digest=hashlib.sha256(canonical).hexdigest(),
        )

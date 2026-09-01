"""Guarded execution of validated supported Azure key-rotation plans."""

from __future__ import annotations

import json
import os
from collections.abc import Callable, Sequence
from datetime import datetime
from enum import Enum
from pathlib import Path
from uuid import UUID

from azurator.discovery import utc_now
from azurator.files import resolve_parent_path
from azurator.fingerprints import (
    derive_key_state_fingerprint,
    equal_key_state_fingerprints,
    new_key_state_salt,
)
from azurator.models import (
    AzureBindingInspection,
    BindingLocation,
    BindingManagement,
    CredentialBinding,
    DiscoveredResource,
    KeyAuthentication,
    MatchResource,
    PlanSource,
    PlanState,
    PlanStep,
    PlanStepAction,
    ProviderInfo,
    RotationPlan,
    WarningImpact,
)
from azurator.operation import (
    MAX_OPERATION_ERROR_MESSAGE_CHARACTERS,
    OperationContractError,
    OperationSlotFingerprint,
    OperationState,
    OperationStatus,
    OperationStore,
    PendingOperationStep,
    operation_intent_digest,
    validate_operation_contract,
)
from azurator.providers.base import (
    BINDING_VERIFICATION_MISMATCH_CODE,
    ManagedBindingProvider,
    ProviderOperationError,
    RotationProvider,
)
from azurator.providers.dotenv_file import DOTENV_FILE_PROVIDER_INFO
from azurator.providers.sops_dotenv_file import SOPS_DOTENV_FILE_PROVIDER_INFO


class ExecutionError(RuntimeError):
    """Execution stopped safely with a secret-free error code and message."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


ProgressCallback = Callable[[PlanStep], None]


class _RegenerationState(str, Enum):
    unchanged = "unchanged"
    completed = "completed"


class ExecutionService:
    """Execute only canonical, provider-backed plan steps with durable progress."""

    def __init__(
        self,
        rotation_providers: Sequence[RotationProvider],
        binding_providers: Sequence[ManagedBindingProvider],
        *,
        clock: Callable[[], datetime] = utc_now,
        key_state_salt_factory: Callable[[], str] = new_key_state_salt,
    ) -> None:
        self._rotation_providers = self._index_rotation_providers(rotation_providers)
        self._binding_providers = self._index_binding_providers(binding_providers)
        self._clock = clock
        self._key_state_salt_factory = key_state_salt_factory

    def start(
        self,
        plan: RotationPlan,
        fresh_plan: RotationPlan,
        store: OperationStore,
        operation_id: UUID,
        *,
        progress: ProgressCallback | None = None,
    ) -> OperationState:
        """Validate fresh inspection, persist one operation, and execute from step one."""

        self.validate_start(plan, fresh_plan)
        key_state_salt = self._key_state_salt_factory()
        slot_fingerprints = self._snapshot_slot_fingerprints(plan, key_state_salt)
        now = self._clock()
        operation = OperationState(
            operation_id=operation_id,
            plan=plan,
            intent_digest=operation_intent_digest(plan),
            started_at=now,
            updated_at=now,
            status=OperationStatus.running,
            key_state_salt=key_state_salt,
            slot_fingerprints=slot_fingerprints,
        )
        store.preflight(operation)
        store.create(operation)
        return self._execute(operation, store, progress)

    def resume(
        self,
        store: OperationStore,
        *,
        fresh_plan: RotationPlan | None = None,
        progress: ProgressCallback | None = None,
    ) -> OperationState:
        """Resume one persisted operation without regenerating a completed slot."""

        operation = self.validate_resume(store, fresh_plan=fresh_plan)
        if operation.status is OperationStatus.completed:
            return operation
        self._validate_slot_drift(operation.plan, operation)
        return self._execute(operation, store, progress)

    def validate_start(self, plan: RotationPlan, fresh_plan: RotationPlan) -> None:
        """Validate an initial rotation without persisting state or mutating Azure."""

        self.validate_plan(plan)
        self._validate_fresh_plan(plan, fresh_plan)

    def validate_plan(self, plan: RotationPlan) -> None:
        """Validate one plan before any source-specific Azure reinspection."""

        self._validate_plan(plan)

    def validate_operation(self, store: OperationStore) -> OperationState:
        """Validate persisted intent and progress before any resume reinspection."""

        operation = store.load()
        self._validate_plan(operation.plan)
        self._validate_operation(operation)
        return operation

    def validate_resume(
        self,
        store: OperationStore,
        *,
        fresh_plan: RotationPlan | None = None,
    ) -> OperationState:
        """Validate one operation artifact without executing its pending step."""

        operation = self.validate_operation(store)
        plan = operation.plan
        if not operation.completed_steps and operation.pending_step is None:
            if fresh_plan is None:
                raise ExecutionError(
                    "resume-fresh-validation-required",
                    "This operation has not started; resume requires fresh plan validation.",
                )
            self._validate_fresh_plan(plan, fresh_plan)
        return operation

    def _execute(
        self,
        operation: OperationState,
        store: OperationStore,
        progress: ProgressCallback | None,
    ) -> OperationState:
        plan = operation.plan
        try:
            if operation.pending_step is not None:
                operation = self._reconcile_pending(operation, store, progress)

            for step in plan.steps[len(operation.completed_steps) :]:
                pending = self._pending_for_step(step)
                operation = operation.model_copy(
                    update={
                        "updated_at": self._clock(),
                        "status": OperationStatus.running,
                        "pending_step": pending,
                        "error_code": None,
                        "error_message": None,
                    }
                )
                store.save(operation)
                slot_fingerprints = self._run_step(plan, step, operation)
                operation = self._complete_step(
                    operation,
                    step,
                    store,
                    slot_fingerprints=slot_fingerprints,
                )
                if progress is not None:
                    progress(step)

            completed = operation.model_copy(
                update={
                    "updated_at": self._clock(),
                    "status": OperationStatus.completed,
                    "pending_step": None,
                    "error_code": None,
                    "error_message": None,
                }
            )
            store.save(completed)
            return completed
        except (ExecutionError, ProviderOperationError) as error:
            error_message = str(error)
            if len(error_message) > MAX_OPERATION_ERROR_MESSAGE_CHARACTERS:
                error_message = error_message[:MAX_OPERATION_ERROR_MESSAGE_CHARACTERS]
            failed = operation.model_copy(
                update={
                    "updated_at": self._clock(),
                    "status": OperationStatus.failed,
                    "error_code": error.code,
                    "error_message": error_message,
                }
            )
            store.save(failed)
            if isinstance(error, ProviderOperationError):
                raise ExecutionError(error.code, str(error)) from None
            raise

    def _reconcile_pending(
        self,
        operation: OperationState,
        store: OperationStore,
        progress: ProgressCallback | None,
    ) -> OperationState:
        plan = operation.plan
        pending = operation.pending_step
        if pending is None:
            return operation
        step = plan.steps[pending.sequence - 1]
        slot_fingerprints: tuple[OperationSlotFingerprint, ...] | None = None
        if step.action is PlanStepAction.update_binding:
            try:
                self._run_binding_step(plan, step, verify=True)
            except ProviderOperationError as error:
                if error.code != BINDING_VERIFICATION_MISMATCH_CODE:
                    raise
                self._run_binding_step(plan, step, verify=False)
        elif step.action is PlanStepAction.verify_binding:
            self._run_binding_step(plan, step, verify=True)
        else:
            slot_fingerprints = self._reconcile_regeneration(plan, step, operation)

        completed = self._complete_step(
            operation,
            step,
            store,
            slot_fingerprints=slot_fingerprints,
        )
        if progress is not None:
            progress(step)
        return completed

    def _reconcile_regeneration(
        self,
        plan: RotationPlan,
        step: PlanStep,
        operation: OperationState,
    ) -> tuple[OperationSlotFingerprint, ...]:
        resource = self._resource(plan, step.resource_id)
        expected = self._operation_resource_fingerprints(operation, resource.resource_id)
        current = self._read_key_state(plan, resource, operation.key_state_salt)
        state = self._classify_regeneration(expected, current, step.key_slot)
        self._ensure_binding_checkpoint(plan, step)
        if state is _RegenerationState.completed:
            return current
        return self._regenerate_and_reconcile(plan, resource, step.key_slot, expected, operation.key_state_salt)

    @staticmethod
    def _pending_for_step(step: PlanStep) -> PendingOperationStep:
        return PendingOperationStep(
            sequence=step.sequence,
            action=step.action,
            resource_id=step.resource_id,
            key_slot=step.key_slot,
            binding_id=step.binding_id,
        )

    def _run_step(
        self,
        plan: RotationPlan,
        step: PlanStep,
        operation: OperationState,
    ) -> tuple[OperationSlotFingerprint, ...] | None:
        if step.action is PlanStepAction.update_binding:
            self._run_binding_step(plan, step, verify=False)
            return None
        if step.action is PlanStepAction.verify_binding:
            self._run_binding_step(plan, step, verify=True)
            return None
        resource = self._resource(plan, step.resource_id)
        expected = self._operation_resource_fingerprints(operation, resource.resource_id)
        current = self._read_key_state(plan, resource, operation.key_state_salt)
        if self._classify_regeneration(expected, current, step.key_slot) is not _RegenerationState.unchanged:
            raise ExecutionError(
                "azure-key-slot-drift",
                "The scheduled Azure key slot changed before its recorded regeneration began.",
            )
        self._ensure_binding_checkpoint(plan, step)
        return self._regenerate_and_reconcile(plan, resource, step.key_slot, expected, operation.key_state_salt)

    def _regenerate_and_reconcile(
        self,
        plan: RotationPlan,
        resource: DiscoveredResource,
        key_slot: str,
        expected: tuple[OperationSlotFingerprint, ...],
        key_state_salt: str,
    ) -> tuple[OperationSlotFingerprint, ...]:
        """Delegate retries to the provider SDK and verify the final key-pair state."""

        provider = self._rotation_provider(resource)
        try:
            provider.regenerate_key(plan.subscription_id, resource, key_slot)
        except ProviderOperationError:
            current = self._read_key_state(plan, resource, key_state_salt)
            state = self._classify_regeneration(expected, current, key_slot)
            if state is _RegenerationState.completed:
                return current
            raise

        current = self._read_key_state(plan, resource, key_state_salt)
        state = self._classify_regeneration(expected, current, key_slot)
        if state is _RegenerationState.completed:
            return current
        raise ProviderOperationError(
            "key-regeneration-unverified",
            "Azure returned from key regeneration without changing exactly the scheduled slot.",
        )

    def _run_binding_step(self, plan: RotationPlan, step: PlanStep, *, verify: bool) -> None:
        resource = self._resource(plan, step.resource_id)
        binding = next(
            (item for item in plan.bindings if item.binding_id == step.binding_id),
            None,
        )
        if binding is None:
            raise ExecutionError("plan-binding-missing", "A planned binding operation has no supported target.")
        if verify:
            self._verify_binding_slot(plan, resource, binding, step.key_slot)
            return
        expected_slot = self._binding_slot_before_sequence(plan, binding, step.sequence)
        if expected_slot is None:
            raise ExecutionError(
                "plan-binding-slot-missing",
                "A planned binding transition has no supported current key slot.",
            )
        self._transition_binding_slot(plan, resource, binding, expected_slot, step.key_slot)

    def _ensure_binding_checkpoint(self, plan: RotationPlan, regeneration: PlanStep) -> None:
        """Re-read and, on an exact mismatch, restore managed bindings before rotation."""

        resource = self._resource(plan, regeneration.resource_id)
        for binding in plan.bindings:
            if (
                binding.key_resource_id != resource.resource_id
                or binding.management is not BindingManagement.update_and_verify
            ):
                continue
            expected_slot = binding.key_slot
            for prior_step in plan.steps[: regeneration.sequence - 1]:
                if (
                    prior_step.action is PlanStepAction.update_binding
                    and prior_step.resource_id == resource.resource_id
                    and prior_step.binding_id == binding.binding_id
                ):
                    expected_slot = prior_step.key_slot
            if expected_slot is None:
                continue
            try:
                self._verify_binding_slot(plan, resource, binding, expected_slot)
            except ProviderOperationError as error:
                if error.code != BINDING_VERIFICATION_MISMATCH_CODE:
                    raise
                transition = next(
                    (
                        prior_step
                        for prior_step in reversed(plan.steps[: regeneration.sequence - 1])
                        if prior_step.action is PlanStepAction.update_binding
                        and prior_step.resource_id == resource.resource_id
                        and prior_step.binding_id == binding.binding_id
                        and prior_step.key_slot == expected_slot
                    ),
                    None,
                )
                if transition is None:
                    raise
                predecessor = self._binding_slot_before_sequence(plan, binding, transition.sequence)
                if predecessor is None:
                    raise ExecutionError(
                        "plan-binding-slot-missing",
                        "A planned binding repair has no supported predecessor key slot.",
                    )
                self._transition_binding_slot(plan, resource, binding, predecessor, expected_slot)
                self._verify_binding_slot(plan, resource, binding, expected_slot)

    @staticmethod
    def _binding_slot_before_sequence(
        plan: RotationPlan,
        binding: CredentialBinding,
        sequence: int,
    ) -> str | None:
        expected_slot = binding.key_slot
        for prior_step in plan.steps[: sequence - 1]:
            if (
                prior_step.action is PlanStepAction.update_binding
                and prior_step.resource_id == binding.key_resource_id
                and prior_step.binding_id == binding.binding_id
            ):
                expected_slot = prior_step.key_slot
        return expected_slot

    def _verify_binding_slot(
        self,
        plan: RotationPlan,
        resource: DiscoveredResource,
        binding: CredentialBinding,
        key_slot: str,
    ) -> None:
        key_provider = self._rotation_provider(resource)
        binding_provider = self._binding_providers[binding.provider]

        def consume(key_value: str) -> None:
            binding_provider.verify_binding(plan.subscription_id, binding, resource, key_value)

        key_provider.use_key_slot(plan.subscription_id, resource, key_slot, consume)

    def _transition_binding_slot(
        self,
        plan: RotationPlan,
        resource: DiscoveredResource,
        binding: CredentialBinding,
        expected_slot: str,
        replacement_slot: str,
    ) -> None:
        key_provider = self._rotation_provider(resource)
        binding_provider = self._binding_providers[binding.provider]

        def consume_expected(expected_key: str) -> None:
            try:

                def consume_replacement(replacement_key: str) -> None:
                    binding_provider.update_binding(
                        plan.subscription_id,
                        binding,
                        resource,
                        expected_key,
                        replacement_key,
                    )

                key_provider.use_key_slot(plan.subscription_id, resource, replacement_slot, consume_replacement)
            finally:
                expected_key = ""

        key_provider.use_key_slot(plan.subscription_id, resource, expected_slot, consume_expected)

    def _complete_step(
        self,
        operation: OperationState,
        step: PlanStep,
        store: OperationStore,
        *,
        slot_fingerprints: tuple[OperationSlotFingerprint, ...] | None = None,
    ) -> OperationState:
        fingerprints = operation.slot_fingerprints
        if step.action is PlanStepAction.regenerate_key:
            if slot_fingerprints is None:
                raise ExecutionError(
                    "key-state-unavailable",
                    "The verified Azure key state was unavailable after regeneration.",
                )
            replacement = {(item.resource_id, item.key_slot): item for item in slot_fingerprints}
            expected = {
                (item.resource_id, item.key_slot) for item in fingerprints if item.resource_id == step.resource_id
            }
            if set(replacement) != expected:
                raise ExecutionError(
                    "key-state-contract-invalid",
                    "The verified Azure key state did not contain the recorded resource slots.",
                )
            fingerprints = tuple(replacement.get((item.resource_id, item.key_slot), item) for item in fingerprints)
        elif slot_fingerprints is not None:
            raise ExecutionError(
                "key-state-contract-invalid",
                "A non-regeneration step returned an unexpected Azure key state.",
            )
        completed = operation.model_copy(
            update={
                "updated_at": self._clock(),
                "status": OperationStatus.running,
                "completed_steps": (*operation.completed_steps, step.sequence),
                "slot_fingerprints": fingerprints,
                "pending_step": None,
                "error_code": None,
                "error_message": None,
            }
        )
        store.save(completed)
        return completed

    def _snapshot_slot_fingerprints(
        self,
        plan: RotationPlan,
        key_state_salt: str,
    ) -> tuple[OperationSlotFingerprint, ...]:
        fingerprints: list[OperationSlotFingerprint] = []
        seen_resources: set[str] = set()
        for step in plan.steps:
            if step.action is not PlanStepAction.regenerate_key or step.resource_id in seen_resources:
                continue
            seen_resources.add(step.resource_id)
            resource = self._resource(plan, step.resource_id)
            try:
                fingerprints.extend(self._read_key_state(plan, resource, key_state_salt))
            except ProviderOperationError as error:
                raise ExecutionError(error.code, str(error)) from None
        return tuple(fingerprints)

    def _validate_slot_drift(self, plan: RotationPlan, operation: OperationState) -> None:
        pending = operation.pending_step
        resource_ids = tuple(dict.fromkeys(item.resource_id for item in operation.slot_fingerprints))
        for resource_id in resource_ids:
            resource = self._resource(plan, resource_id)
            try:
                current = self._read_key_state(plan, resource, operation.key_state_salt)
            except ProviderOperationError as error:
                raise ExecutionError(error.code, str(error)) from None
            expected = self._operation_resource_fingerprints(operation, resource_id)
            current_by_slot = {item.key_slot: item for item in current}
            for item in expected:
                if (
                    pending is not None
                    and pending.action is PlanStepAction.regenerate_key
                    and pending.resource_id == item.resource_id
                    and pending.key_slot == item.key_slot
                ):
                    continue
                observed = current_by_slot[item.key_slot]
                if not equal_key_state_fingerprints(item.fingerprint, observed.fingerprint):
                    raise ExecutionError(
                        "azure-key-slot-drift",
                        "An Azure key slot changed outside this operation; resume was blocked.",
                    )

    @staticmethod
    def _operation_resource_fingerprints(
        operation: OperationState,
        resource_id: str,
    ) -> tuple[OperationSlotFingerprint, ...]:
        fingerprints = tuple(item for item in operation.slot_fingerprints if item.resource_id == resource_id)
        if not fingerprints:
            raise ExecutionError(
                "operation-key-state-missing",
                "The operation has no recovery fingerprints for a planned key resource.",
            )
        return fingerprints

    def _read_key_state(
        self,
        plan: RotationPlan,
        resource: DiscoveredResource,
        key_state_salt: str,
    ) -> tuple[OperationSlotFingerprint, ...]:
        provider = self._rotation_provider(resource)
        fingerprints: dict[str, str] = {}

        def capture(key_slot: str, value: str) -> None:
            if key_slot in fingerprints:
                raise ProviderOperationError(
                    "key-state-response-invalid",
                    "A rotation provider returned a duplicate key slot while reading recovery state.",
                )
            fingerprints[key_slot] = derive_key_state_fingerprint(
                value,
                salt=key_state_salt,
                resource_id=resource.resource_id,
                key_slot=key_slot,
            )

        provider.use_key_state(plan.subscription_id, resource, capture)
        declared_slots = tuple(slot.name for slot in resource.key_slots)
        if set(fingerprints) != set(declared_slots) or len(declared_slots) != len(set(declared_slots)):
            fingerprints.clear()
            raise ProviderOperationError(
                "key-state-response-invalid",
                "A rotation provider did not return the exact declared key-slot state.",
            )
        return tuple(
            OperationSlotFingerprint(
                resource_id=resource.resource_id,
                key_slot=key_slot,
                fingerprint=fingerprints[key_slot],
            )
            for key_slot in declared_slots
        )

    @staticmethod
    def _classify_regeneration(
        expected: tuple[OperationSlotFingerprint, ...],
        current: tuple[OperationSlotFingerprint, ...],
        key_slot: str,
    ) -> _RegenerationState:
        expected_by_slot = {item.key_slot: item for item in expected}
        current_by_slot = {item.key_slot: item for item in current}
        if set(expected_by_slot) != set(current_by_slot) or key_slot not in expected_by_slot:
            raise ExecutionError(
                "key-state-contract-invalid",
                "The current Azure key state did not match the recorded slot contract.",
            )
        changed = {
            slot
            for slot, prior in expected_by_slot.items()
            if not equal_key_state_fingerprints(prior.fingerprint, current_by_slot[slot].fingerprint)
        }
        if not changed:
            return _RegenerationState.unchanged
        if changed == {key_slot}:
            return _RegenerationState.completed
        raise ExecutionError(
            "azure-key-slot-drift",
            "An Azure key slot other than the scheduled slot changed; execution was blocked.",
        )

    def _validate_plan(self, plan: RotationPlan) -> None:
        self._validate_plan_envelope(plan)
        self._validate_plan_selection_source(plan)
        resources, bindings = self._index_plan_identities(plan)
        self._validate_plan_bindings(plan, resources)
        self._validate_plan_steps(plan, resources, bindings)
        self._validate_plan_provider_versions(plan, resources, bindings)

    @staticmethod
    def _validate_plan_envelope(plan: RotationPlan) -> None:
        if plan.schema_version != "1":
            raise ExecutionError("plan-schema-unsupported", "The plan schema version is not supported.")
        has_blocking_warning = any(warning.impact is WarningImpact.blocking for warning in plan.warnings)
        has_confirmation_warning = any(warning.impact is WarningImpact.confirmation for warning in plan.warnings)
        expected_state = (
            PlanState.blocked
            if has_blocking_warning
            else PlanState.no_changes
            if not plan.scheduled_slots
            else PlanState.confirmation_required
            if has_confirmation_warning
            else PlanState.ready
        )
        if plan.state is not expected_state:
            raise ExecutionError(
                "plan-warning-impact-invalid",
                "The plan state does not agree with its structured warning impacts.",
            )
        if plan.state is PlanState.blocked:
            raise ExecutionError("plan-blocked", "A blocked plan cannot be executed.")
        if plan.state is PlanState.no_changes:
            raise ExecutionError("plan-no-changes", "The plan contains no changes to execute.")
        if not plan.scheduled_slots or not plan.steps:
            raise ExecutionError("plan-empty", "The plan contains no rotation steps.")
        if [step.sequence for step in plan.steps] != list(range(1, len(plan.steps) + 1)):
            raise ExecutionError("plan-step-order-invalid", "The plan step sequence is invalid.")
        if len(plan.preconditions) != 1 or plan.preconditions[0].subject != "planning-snapshot":
            raise ExecutionError("plan-precondition-invalid", "The plan precondition contract is invalid.")

    @staticmethod
    def _validate_plan_selection_source(plan: RotationPlan) -> None:
        local_source_providers = {
            PlanSource.dotenv_file: DOTENV_FILE_PROVIDER_INFO.name,
            PlanSource.sops_dotenv_file: SOPS_DOTENV_FILE_PROVIDER_INFO.name,
        }
        local_provider_names = frozenset(local_source_providers.values())
        dotenv_source_formats = frozenset((PlanSource.dotenv_stdin, *local_source_providers))
        if plan.source_format in dotenv_source_formats:
            invalid_source = not plan.source_selectors or any(not slot.input_selectors for slot in plan.scheduled_slots)
            local_bindings = tuple(binding for binding in plan.bindings if binding.provider in local_provider_names)
            if plan.source_format is PlanSource.dotenv_stdin:
                invalid_source = invalid_source or plan.source_path is not None or bool(local_bindings)
            else:
                expected_provider = local_source_providers[plan.source_format]
                source_bindings = tuple(binding for binding in local_bindings if binding.provider == expected_provider)
                source_path = Path(plan.source_path or "")
                try:
                    bound_source_path = resolve_parent_path(source_path)
                except OSError:
                    bound_source_path = None
                scheduled_by_slot = {
                    (slot.resource_id, slot.key_slot): slot.input_selectors for slot in plan.scheduled_slots
                }
                scheduled_selectors = tuple(
                    selector for selectors in scheduled_by_slot.values() for selector in selectors
                )
                has_slotless_source_binding = any(binding.key_slot is None for binding in source_bindings)
                bindings_by_slot = {
                    (binding.key_resource_id, binding.key_slot): binding
                    for binding in source_bindings
                    if binding.key_slot is not None
                }
                invalid_source = invalid_source or (
                    not plan.source_path
                    or not source_path.is_absolute()
                    or Path(os.path.abspath(source_path)) != source_path
                    or bound_source_path != source_path
                    or len(scheduled_selectors) != len(set(scheduled_selectors))
                    or has_slotless_source_binding
                    or set(bindings_by_slot) != set(scheduled_by_slot)
                    or len(bindings_by_slot) != len(source_bindings)
                    or len(source_bindings) != len(local_bindings)
                    or any(
                        (
                            binding.scope_id != plan.source_path
                            or binding.target != plan.source_path
                            or binding.selectors != scheduled_by_slot[identity]
                        )
                        for identity, binding in bindings_by_slot.items()
                    )
                )
        else:
            invalid_source = bool(
                plan.source_path
                or plan.source_selectors
                or plan.skipped_empty_selectors
                or any(slot.input_selectors for slot in plan.scheduled_slots)
                or any(binding.provider in local_provider_names for binding in plan.bindings)
            )
        if invalid_source:
            raise ExecutionError("plan-selection-source-invalid", "The plan selection-source contract is invalid.")

    @staticmethod
    def _index_plan_identities(
        plan: RotationPlan,
    ) -> tuple[dict[str, MatchResource], dict[str, CredentialBinding]]:
        resources = {resource.resource_id: resource for resource in plan.resources}
        bindings = {binding.binding_id: binding for binding in plan.bindings}
        if len(resources) != len(plan.resources) or len(bindings) != len(plan.bindings):
            raise ExecutionError("plan-identity-conflict", "The plan contains conflicting resource identities.")
        return resources, bindings

    def _validate_plan_bindings(
        self,
        plan: RotationPlan,
        resources: dict[str, MatchResource],
    ) -> None:
        if plan.azure_binding_inspection is AzureBindingInspection.skipped and (
            any(binding.location is BindingLocation.azure for binding in plan.bindings)
            or any(inspection.location is BindingLocation.azure for inspection in plan.binding_inspections)
        ):
            raise ExecutionError(
                "plan-binding-inspection-invalid",
                "A plan that skipped Azure binding inspection contains Azure binding metadata.",
            )
        for inspection in plan.binding_inspections:
            resource = resources.get(inspection.resource_id)
            if resource is None:
                raise ExecutionError(
                    "plan-binding-target-invalid",
                    "A plan binding inspection targets an undeclared key resource.",
                )
            provider = self._binding_providers.get(inspection.provider)
            if provider is not None and inspection.location is not provider.location:
                raise ExecutionError(
                    "plan-binding-location-invalid",
                    "A plan binding inspection does not match its installed provider location.",
                )
        for binding in plan.bindings:
            resource = resources.get(binding.key_resource_id)
            binding_declared_slots: set[str] = (
                {slot.name for slot in resource.key_slots} if resource is not None else set()
            )
            if resource is None or (binding.key_slot is not None and binding.key_slot not in binding_declared_slots):
                raise ExecutionError(
                    "plan-binding-target-invalid",
                    "A plan binding targets an undeclared key resource or slot.",
                )
            if (
                binding.management is BindingManagement.update_and_verify
                and binding.provider not in self._binding_providers
            ):
                raise ExecutionError(
                    "plan-binding-provider-unavailable",
                    "A managed plan binding requires an integration that is not installed.",
                )
            provider = self._binding_providers.get(binding.provider)
            if provider is not None and binding.location is not provider.location:
                raise ExecutionError(
                    "plan-binding-location-invalid",
                    "A plan binding does not match its installed provider location.",
                )

    def _validate_plan_steps(
        self,
        plan: RotationPlan,
        resources: dict[str, MatchResource],
        bindings: dict[str, CredentialBinding],
    ) -> None:
        for step in plan.steps:
            resource = resources.get(step.resource_id)
            declared_slots = {slot.name: slot for slot in resource.key_slots} if resource is not None else {}
            if (
                resource is None
                or len(declared_slots) != len(resource.key_slots)
                or step.key_slot not in declared_slots
            ):
                raise ExecutionError("plan-step-target-invalid", "A plan step targets an undeclared key slot.")
            if resource.provider not in self._rotation_providers:
                raise ExecutionError(
                    "plan-rotation-provider-unavailable",
                    "A plan step requires a key-rotation integration that is not installed.",
                )
            if step.action is PlanStepAction.regenerate_key:
                if (
                    step.binding_id is not None
                    or not declared_slots[step.key_slot].rotatable
                    or any(not slot.values_retrievable for slot in resource.key_slots)
                ):
                    raise ExecutionError(
                        "plan-step-target-invalid",
                        "A regeneration step violates the supported target or key-state contract.",
                    )
                continue
            binding = bindings.get(step.binding_id or "")
            if binding is None or binding.key_resource_id != step.resource_id:
                raise ExecutionError("plan-step-target-invalid", "A plan step targets an undeclared binding.")
            if binding.management is not BindingManagement.update_and_verify:
                raise ExecutionError(
                    "plan-binding-automation-unavailable",
                    "A plan step targets a binding Azurator cannot update and verify automatically.",
                )
            if binding.provider not in self._binding_providers:
                raise ExecutionError(
                    "plan-binding-provider-unavailable",
                    "A plan step requires a managed binding integration that is not installed.",
                )

    def _validate_plan_provider_versions(
        self,
        plan: RotationPlan,
        resources: dict[str, MatchResource],
        bindings: dict[str, CredentialBinding],
    ) -> None:
        provider_versions = {provider.name: provider.contract_version for provider in plan.providers}
        if len(provider_versions) != len(plan.providers):
            raise ExecutionError(
                "plan-provider-version-mismatch",
                "The plan contains conflicting integration versions.",
            )
        installed_providers: dict[str, ProviderInfo] = {}
        for provider in (*self._rotation_providers.values(), *self._binding_providers.values()):
            installed = installed_providers.get(provider.info.name)
            if installed is not None and installed != provider.info:
                raise ExecutionError(
                    "plan-provider-version-mismatch",
                    "Installed integrations contain conflicting versions.",
                )
            installed_providers[provider.info.name] = provider.info
        for provider_name, recorded_version in provider_versions.items():
            installed = installed_providers.get(provider_name)
            if installed is not None and recorded_version != installed.contract_version:
                raise ExecutionError(
                    "plan-provider-version-mismatch",
                    "A recorded integration version does not match the installed version.",
                )
        required_providers: dict[str, ProviderInfo] = {}
        for step in plan.steps:
            rotation_info = self._rotation_providers[resources[step.resource_id].provider].info
            required_providers[rotation_info.name] = rotation_info
            if step.binding_id is not None:
                binding_info = self._binding_providers[bindings[step.binding_id].provider].info
                required_providers[binding_info.name] = binding_info
        for binding in plan.bindings:
            if binding.management is BindingManagement.update_and_verify:
                binding_info = self._binding_providers[binding.provider].info
                required_providers[binding_info.name] = binding_info
        for provider_info in required_providers.values():
            if provider_versions.get(provider_info.name) != provider_info.contract_version:
                raise ExecutionError(
                    "plan-provider-version-mismatch",
                    "The plan integration versions do not match the installed versions.",
                )

    @staticmethod
    def _validate_fresh_plan(plan: RotationPlan, fresh_plan: RotationPlan) -> None:
        if plan.tenant_id != fresh_plan.tenant_id or plan.subscription_id != fresh_plan.subscription_id:
            raise ExecutionError("plan-scope-drift", "The current tenant or subscription does not match the plan.")
        if _stable_plan_contract(plan) != _stable_plan_contract(fresh_plan):
            raise ExecutionError(
                "plan-drift-detected",
                "Fresh Azure planning inspection no longer agrees with the generated plan.",
            )

    def _validate_operation(self, operation: OperationState) -> None:
        try:
            validate_operation_contract(operation)
        except OperationContractError as error:
            raise ExecutionError(error.code, str(error)) from None

    def _rotation_provider(self, resource: DiscoveredResource) -> RotationProvider:
        return self._rotation_providers[resource.provider]

    @staticmethod
    def _resource(plan: RotationPlan, resource_id: str) -> DiscoveredResource:
        resource = next((item for item in plan.resources if item.resource_id == resource_id), None)
        if resource is None:
            raise ExecutionError("plan-resource-missing", "A plan step has no supported resource metadata.")
        return _execution_resource(resource)

    @staticmethod
    def _index_rotation_providers(providers: Sequence[RotationProvider]) -> dict[str, RotationProvider]:
        indexed = {provider.info.name: provider for provider in providers}
        if len(indexed) != len(providers):
            raise ValueError("rotation providers contain duplicate names")
        return indexed

    @staticmethod
    def _index_binding_providers(
        providers: Sequence[ManagedBindingProvider],
    ) -> dict[str, ManagedBindingProvider]:
        indexed = {provider.info.name: provider for provider in providers}
        if len(indexed) != len(providers):
            raise ValueError("managed binding providers contain duplicate names")
        return indexed


def _execution_resource(resource: MatchResource) -> DiscoveredResource:
    return DiscoveredResource(
        resource_id=resource.resource_id,
        name=resource.name,
        resource_type=resource.resource_type,
        location=resource.location,
        kind=resource.kind,
        endpoint=resource.endpoint,
        provider=resource.provider,
        key_authentication=KeyAuthentication.enabled,
        key_slots=resource.key_slots,
    )


def _stable_plan_contract(plan: RotationPlan) -> str:
    payload = plan.model_dump(mode="json", exclude={"created_at", "subscription_name"})
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)

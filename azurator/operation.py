"""One durable, raw-secret-free state for an in-progress Azure rotation."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Literal
from uuid import UUID

from pydantic import Field, ValidationError

from azurator.files import (
    MAX_OPERATION_ARTIFACT_BYTES,
    PrivateFileExistsError,
    UnsafeInputPathError,
    UnsafeOutputPathError,
    create_private_text,
    ensure_private_directory,
    read_private_text,
    remove_empty_private_directory,
    remove_private_text,
    write_private_text,
)
from azurator.models import AzuratorModel, PlanSource, PlanStepAction, PlanStepPhase, RotationPlan

MAX_OPERATION_STATE_BYTES = MAX_OPERATION_ARTIFACT_BYTES
MAX_OPERATION_ERROR_CODE_CHARACTERS = 128
MAX_OPERATION_ERROR_MESSAGE_CHARACTERS = 4096


class OperationStatus(str, Enum):
    """Durable lifecycle of one rotation operation."""

    running = "running"
    failed = "failed"
    completed = "completed"


class PendingOperationStep(AzuratorModel):
    """A step recorded before its external call so interruption can be reconciled."""

    sequence: int = Field(ge=1)
    action: PlanStepAction
    resource_id: str = Field(min_length=1)
    key_slot: str = Field(min_length=1)
    binding_id: str | None = None


class OperationSlotFingerprint(AzuratorModel):
    """Salted verifier for one high-entropy Azure key in private recovery state."""

    resource_id: str = Field(min_length=1)
    key_slot: str = Field(min_length=1)
    fingerprint: str = Field(pattern=r"^sha256:v1:[0-9a-f]{64}$")


class OperationState(AzuratorModel):
    """Exact rotation intent and crash-recovery progress in one private artifact."""

    schema_version: Literal["1"] = "1"
    operation_id: UUID
    plan: RotationPlan
    intent_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    started_at: datetime
    updated_at: datetime
    status: OperationStatus
    key_state_salt: str = Field(pattern=r"^[0-9a-f]{64}$")
    slot_fingerprints: tuple[OperationSlotFingerprint, ...] = Field(min_length=1)
    completed_steps: tuple[int, ...] = ()
    pending_step: PendingOperationStep | None = None
    error_code: str | None = Field(
        default=None,
        max_length=MAX_OPERATION_ERROR_CODE_CHARACTERS,
        pattern=r"^[a-z0-9-]+$",
    )
    error_message: str | None = Field(default=None, max_length=MAX_OPERATION_ERROR_MESSAGE_CHARACTERS)


class OperationError(RuntimeError):
    """An operation state could not be loaded, persisted, or cleaned safely."""


class OperationContractError(ValueError):
    """A parsed operation violates its immutable intent or recovery-progress contract."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class OperationCatalogError(RuntimeError):
    """Retained operation state could not be inspected through the private catalog."""


class RetainedStepState(str, Enum):
    """Whether the displayed step was already entered or has not started."""

    pending = "pending"
    next = "next"


class RetainedOperationResource(AzuratorModel):
    """Minimal resource/slot projection for local recovery inspection."""

    name: str = Field(min_length=1)
    provider: str = Field(min_length=1)
    kind: str | None = None
    key_slots: tuple[str, ...] = Field(min_length=1)


class RetainedOperationStep(AzuratorModel):
    """Minimal pending-or-next step projection without resource or binding IDs."""

    state: RetainedStepState
    sequence: int = Field(ge=1)
    action: PlanStepAction
    phase: PlanStepPhase
    resource_name: str = Field(min_length=1)
    key_slot: str = Field(min_length=1)
    binding_name: str | None = None
    binding_scope_name: str | None = None


class RetainedOperationSummary(AzuratorModel):
    """Secret-free local status projection for one valid retained operation."""

    schema_version: Literal["1"] = "1"
    operation_id: UUID
    status: OperationStatus
    started_at: datetime
    updated_at: datetime
    subscription_id: str = Field(min_length=1)
    subscription_name: str | None = None
    completed_steps: int = Field(ge=0)
    total_steps: int = Field(ge=1)
    current_step: RetainedOperationStep | None = None
    error_code: str | None = None
    resources: tuple[RetainedOperationResource, ...] = Field(min_length=1)
    resume_command: str = Field(min_length=1)


class RetainedOperationReport(AzuratorModel):
    """Read-only enumeration of valid and invalid UUID-scoped recovery entries."""

    schema_version: Literal["1"] = "1"
    operations: tuple[RetainedOperationSummary, ...]
    invalid_operation_ids: tuple[UUID, ...]


def operation_intent_digest(plan: RotationPlan) -> str:
    """Bind mutable progress to the exact immutable plan embedded in the operation."""

    canonical = json.dumps(
        plan.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def validate_operation_contract(operation: OperationState) -> None:
    """Validate intent binding, progress, recovery fingerprints, and lifecycle."""

    plan = operation.plan
    if operation.intent_digest != operation_intent_digest(plan):
        raise OperationContractError(
            "operation-intent-invalid",
            "The operation no longer contains its exact recorded rotation intent.",
        )
    expected_completed = tuple(range(1, len(operation.completed_steps) + 1))
    if operation.completed_steps != expected_completed or len(operation.completed_steps) > len(plan.steps):
        raise OperationContractError(
            "operation-progress-invalid",
            "The operation contains invalid completed-step progress.",
        )
    expected_slots = _expected_operation_slots(plan)
    operation_slots = [(item.resource_id, item.key_slot) for item in operation.slot_fingerprints]
    if len(operation_slots) != len(set(operation_slots)) or set(operation_slots) != expected_slots:
        raise OperationContractError(
            "operation-key-state-invalid",
            "The operation key-state fingerprints disagree with its plan.",
        )
    resources = {resource.resource_id: resource for resource in plan.resources}
    for fingerprint in operation.slot_fingerprints:
        if fingerprint.resource_id not in resources:
            raise OperationContractError(
                "operation-key-state-invalid",
                "The operation key-state fingerprints disagree with its plan.",
            )
    has_error_code = operation.error_code is not None
    has_error_message = operation.error_message is not None
    invalid_lifecycle = (
        has_error_code != has_error_message
        or (operation.status is OperationStatus.failed and (operation.pending_step is None or not has_error_code))
        or (operation.status is not OperationStatus.failed and has_error_code)
    )
    if invalid_lifecycle:
        raise OperationContractError(
            "operation-status-invalid",
            "The operation status, pending step, and failure metadata are inconsistent.",
        )
    if operation.pending_step is not None:
        expected_sequence = len(operation.completed_steps) + 1
        if expected_sequence > len(plan.steps):
            raise OperationContractError(
                "operation-progress-invalid",
                "The operation has a pending step after completion.",
            )
        step = plan.steps[expected_sequence - 1]
        pending = operation.pending_step
        if (
            pending.sequence != step.sequence
            or pending.action is not step.action
            or pending.resource_id != step.resource_id
            or pending.key_slot != step.key_slot
            or pending.binding_id != step.binding_id
        ):
            raise OperationContractError(
                "operation-progress-invalid",
                "The pending operation step disagrees with the plan.",
            )
    if operation.status is OperationStatus.completed and (
        len(operation.completed_steps) != len(plan.steps) or operation.pending_step is not None
    ):
        raise OperationContractError(
            "operation-progress-invalid",
            "The completed operation is internally inconsistent.",
        )


class OperationCatalog:
    """Read-only access to UUID-scoped retained operations under one private root."""

    def __init__(self, root: Path) -> None:
        self.root = root.expanduser()

    def list(self) -> RetainedOperationReport:
        """Enumerate valid retained operations while isolating invalid entries."""

        operation_ids = self._operation_ids(missing_ok=True)
        operations: list[RetainedOperationSummary] = []
        invalid: list[UUID] = []
        for operation_id in operation_ids:
            try:
                operations.append(self._load_summary(operation_id))
            except (OSError, OperationError, OperationContractError, OperationCatalogError, ValidationError):
                invalid.append(operation_id)
        operations.sort(
            key=lambda item: (item.updated_at.isoformat(), str(item.operation_id)),
            reverse=True,
        )
        return RetainedOperationReport(
            operations=tuple(operations),
            invalid_operation_ids=tuple(sorted(invalid, key=str)),
        )

    def show(self, operation_id: UUID) -> RetainedOperationSummary:
        """Load one exact retained operation without scanning or contacting Azure."""

        self._validate_root(missing_ok=False)
        try:
            return self._load_summary(operation_id)
        except (OSError, OperationError, OperationContractError, OperationCatalogError, ValidationError):
            raise OperationCatalogError("the retained rotation operation is missing, unsafe, or invalid") from None

    def _operation_ids(self, *, missing_ok: bool) -> tuple[UUID, ...]:
        root_metadata = self._validate_root(missing_ok=missing_ok)
        if root_metadata is None:
            return ()
        try:
            entries = tuple(self.root.iterdir())
        except OSError:
            raise OperationCatalogError(
                "the private rotation-operation directory is unsafe or cannot be inspected"
            ) from None
        self._validate_same_directory(self.root, root_metadata)
        operation_ids: list[UUID] = []
        for entry in entries:
            try:
                operation_id = UUID(entry.name)
            except ValueError:
                continue
            if entry.name == str(operation_id):
                operation_ids.append(operation_id)
        return tuple(sorted(operation_ids, key=str))

    def _validate_root(self, *, missing_ok: bool) -> os.stat_result | None:
        try:
            return _private_directory_metadata(self.root)
        except FileNotFoundError:
            if missing_ok:
                return None
            raise OperationCatalogError("the retained rotation operation is missing, unsafe, or invalid") from None
        except (OSError, OperationCatalogError):
            raise OperationCatalogError(
                "the private rotation-operation directory is unsafe or cannot be inspected"
            ) from None

    def _load_summary(self, operation_id: UUID) -> RetainedOperationSummary:
        root_metadata = self._validate_root(missing_ok=False)
        assert root_metadata is not None
        directory = self.root / str(operation_id)
        directory_metadata = _private_directory_metadata(directory)
        operation = OperationStore(
            directory / "operation.json",
            expected_operation_id=operation_id,
        ).load()
        validate_operation_contract(operation)
        summary = _operation_summary(operation)
        self._validate_same_directory(directory, directory_metadata)
        self._validate_same_directory(self.root, root_metadata)
        return summary

    @staticmethod
    def _validate_same_directory(path: Path, expected: os.stat_result) -> None:
        try:
            current = _private_directory_metadata(path)
        except (OSError, OperationCatalogError):
            raise OperationCatalogError("a private rotation-operation directory changed during inspection") from None
        if (current.st_dev, current.st_ino) != (expected.st_dev, expected.st_ino):
            raise OperationCatalogError("a private rotation-operation directory changed during inspection")


def _private_directory_metadata(path: Path) -> os.stat_result:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise OperationCatalogError("a retained rotation-operation path is not a private directory")
    if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077:
        raise OperationCatalogError("a retained rotation-operation directory is accessible by other users")
    return metadata


def _operation_summary(operation: OperationState) -> RetainedOperationSummary:
    plan = operation.plan
    resources = {resource.resource_id: resource for resource in plan.resources}
    bindings = {binding.binding_id: binding for binding in plan.bindings}
    if len(resources) != len(plan.resources) or len(bindings) != len(plan.bindings):
        raise OperationCatalogError("the retained rotation operation contains conflicting identities")

    slots_by_resource: dict[str, list[str]] = {}
    for scheduled in plan.scheduled_slots:
        resource = resources.get(scheduled.resource_id)
        if resource is None or scheduled.key_slot not in {slot.name for slot in resource.key_slots}:
            raise OperationCatalogError("the retained rotation operation contains invalid selected slots")
        selected_slots = slots_by_resource.setdefault(scheduled.resource_id, [])
        if scheduled.key_slot in selected_slots:
            raise OperationCatalogError("the retained rotation operation contains duplicate selected slots")
        selected_slots.append(scheduled.key_slot)
    resource_summaries = tuple(
        RetainedOperationResource(
            name=resources[resource_id].name,
            provider=resources[resource_id].provider,
            kind=resources[resource_id].kind,
            key_slots=tuple(key_slots),
        )
        for resource_id, key_slots in slots_by_resource.items()
    )
    if not resource_summaries:
        raise OperationCatalogError("the retained rotation operation contains no selected key slots")

    active_step = None
    active_state = RetainedStepState.next
    if operation.pending_step is not None:
        step = plan.steps[operation.pending_step.sequence - 1]
        active_state = RetainedStepState.pending
    elif len(operation.completed_steps) < len(plan.steps):
        step = plan.steps[len(operation.completed_steps)]
    else:
        step = None
    if step is not None:
        resource = resources.get(step.resource_id)
        binding = bindings.get(step.binding_id) if step.binding_id is not None else None
        if resource is None or (step.binding_id is not None and binding is None):
            raise OperationCatalogError("the retained rotation operation contains an invalid active step")
        active_step = RetainedOperationStep(
            state=active_state,
            sequence=step.sequence,
            action=step.action,
            phase=step.phase,
            resource_name=resource.name,
            key_slot=step.key_slot,
            binding_name=binding.name if binding is not None else None,
            binding_scope_name=binding.scope_name if binding is not None else None,
        )

    resume_command = f"azurator rotate --resume {operation.operation_id}"
    if (
        plan.source_format is PlanSource.dotenv_stdin
        and not operation.completed_steps
        and operation.pending_step is None
    ):
        resume_command += " --stdin"

    return RetainedOperationSummary(
        operation_id=operation.operation_id,
        status=operation.status,
        started_at=operation.started_at,
        updated_at=operation.updated_at,
        subscription_id=plan.subscription_id,
        subscription_name=plan.subscription_name,
        completed_steps=len(operation.completed_steps),
        total_steps=len(plan.steps),
        current_step=active_step,
        error_code=operation.error_code,
        resources=resource_summaries,
        resume_command=resume_command,
    )


def _expected_operation_slots(plan: RotationPlan) -> set[tuple[str, str]]:
    resource_ids = {step.resource_id for step in plan.steps if step.action is PlanStepAction.regenerate_key}
    return {
        (resource.resource_id, slot.name)
        for resource in plan.resources
        if resource.resource_id in resource_ids
        for slot in resource.key_slots
    }


class OperationStore:
    """Private atomic persistence for one transient rotation operation."""

    def __init__(self, path: Path, *, expected_operation_id: UUID | None = None) -> None:
        self.path = path.expanduser()
        self._expected_operation_id = expected_operation_id

    def preflight(self, operation: OperationState) -> None:
        """Prove that every bounded operation state fits before Azure mutation."""

        pending_steps = tuple(
            PendingOperationStep(
                sequence=step.sequence,
                action=step.action,
                resource_id=step.resource_id,
                key_slot=step.key_slot,
                binding_id=step.binding_id,
            )
            for step in operation.plan.steps
        )
        largest_pending = max(
            pending_steps,
            key=lambda item: len(item.model_dump_json().encode("utf-8")),
            default=None,
        )
        worst_case = operation.model_copy(
            update={
                "status": OperationStatus.failed,
                "completed_steps": tuple(step.sequence for step in operation.plan.steps),
                "pending_step": largest_pending,
                "error_code": "x" * MAX_OPERATION_ERROR_CODE_CHARACTERS,
                # A NUL is escaped to six ASCII bytes in JSON, so this reserves
                # at least as much space as any bounded UTF-8 error message.
                "error_message": "\0" * MAX_OPERATION_ERROR_MESSAGE_CHARACTERS,
            }
        )
        _operation_payload(operation)
        _operation_payload(worst_case)

    def create(self, operation: OperationState) -> None:
        self._validate_expected_id(operation)
        payload = _operation_payload(operation)
        try:
            ensure_private_directory(self.path.parent)
            create_private_text(self.path, payload)
        except PrivateFileExistsError:
            raise OperationError("the rotation operation already exists; resume it or choose another ID")
        except (OSError, UnsafeOutputPathError):
            raise OperationError("the rotation operation could not be persisted safely") from None

    def load(self) -> OperationState:
        try:
            payload = read_private_text(self.path, max_bytes=MAX_OPERATION_STATE_BYTES)
            operation = OperationState.model_validate_json(payload)
        except (OSError, UnicodeError, UnsafeInputPathError, ValidationError):
            raise OperationError("the rotation operation is missing, unsafe, or invalid") from None
        self._validate_expected_id(operation)
        return operation

    def save(self, operation: OperationState) -> None:
        self._validate_expected_id(operation)
        payload = _operation_payload(operation)
        try:
            write_private_text(self.path, payload)
        except (OSError, UnsafeOutputPathError):
            raise OperationError("the rotation operation could not be persisted safely") from None

    def remove_completed(self, operation: OperationState) -> None:
        """Remove only the exact completed state; leave recoverable failures intact."""

        self._validate_expected_id(operation)
        if operation.status is not OperationStatus.completed:
            raise OperationError("only a completed rotation operation may be cleaned automatically")
        persisted = self.load()
        if persisted != operation:
            raise OperationError("the completed rotation operation changed before cleanup")
        try:
            remove_private_text(self.path)
            if self._expected_operation_id is not None:
                remove_empty_private_directory(self.path.parent)
        except (OSError, UnsafeOutputPathError):
            raise OperationError("the completed rotation operation could not be removed safely") from None

    def _validate_expected_id(self, operation: OperationState) -> None:
        if self._expected_operation_id is None:
            return
        if operation.operation_id != self._expected_operation_id:
            raise OperationError("the rotation operation ID does not match its private state path")
        if self.path.name != "operation.json" or self.path.parent.name != str(self._expected_operation_id):
            raise OperationError("the private rotation-operation path does not match its operation ID")


def _operation_payload(operation: OperationState) -> str:
    payload = operation.model_dump_json(indent=2) + "\n"
    if len(payload.encode("utf-8")) > MAX_OPERATION_STATE_BYTES:
        raise OperationError("the rotation operation exceeds the supported private artifact size limit")
    return payload

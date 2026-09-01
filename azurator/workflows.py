"""Application workflows shared by the command adapter.

This module coordinates already supported services and source adapters. It does
not authenticate, render terminal output, persist plans, or mutate Azure.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, TextIO

from azurator.auth import SubscriptionSelection
from azurator.models import (
    AzureBindingInspection,
    Inventory,
    KeySlotSelection,
    MatchReport,
    PlanSource,
    RotationPlan,
    SelectionReport,
)
from azurator.planning import PlanningError, PlanningService


class DotenvMatcher(Protocol):
    def __call__(
        self,
        subscription_id: str,
        stream: TextIO,
        *,
        skip_azure_bindings: bool = False,
    ) -> MatchReport: ...


class FileMatcher(Protocol):
    def __call__(
        self,
        subscription_id: str,
        path: Path,
        *,
        skip_azure_bindings: bool = False,
    ) -> tuple[MatchReport, Path]: ...


class SelectionInspector(Protocol):
    def __call__(
        self,
        subscription_id: str,
        inventory: Inventory,
        selections: tuple[KeySlotSelection, ...],
        *,
        skip_azure_bindings: bool = False,
    ) -> SelectionReport: ...


class SelectionCanonicalizer(Protocol):
    def __call__(
        self,
        inventory: Inventory,
        selections: Sequence[KeySlotSelection],
        *,
        require_rotatable: bool,
    ) -> tuple[KeySlotSelection, ...]: ...


@dataclass(frozen=True)
class RotationPlanningWorkflow:
    """Build and freshly reconstruct rotation plans from every supported source."""

    discover_inventory: Callable[[str], Inventory]
    match_dotenv: DotenvMatcher
    match_dotenv_file: FileMatcher
    match_sops_dotenv_file: FileMatcher
    inspect_selection: SelectionInspector
    prompt_selection: Callable[[Inventory], tuple[KeySlotSelection, ...]]
    canonicalize_selection: SelectionCanonicalizer
    planner_factory: Callable[[], PlanningService] = PlanningService

    def build(
        self,
        selected_subscription: SubscriptionSelection,
        *,
        stdin_input: bool,
        env_file: Path | None,
        sops_file: Path | None,
        direct_selections: tuple[KeySlotSelection, ...] | None,
        skip_azure_bindings: bool,
        stream: TextIO,
    ) -> RotationPlan:
        tenant_id = selected_subscription.tenant_id
        if not tenant_id:
            raise PlanningError("the tenant ID for the selected subscription is unavailable")
        if direct_selections is not None and (stdin_input or env_file is not None or sops_file is not None):
            raise PlanningError("direct selection cannot be combined with a dotenv input mode")

        subscription_id = selected_subscription.subscription_id
        subscription_name = selected_subscription.name
        planner = self.planner_factory()
        if stdin_input:
            report = self.match_dotenv(
                subscription_id,
                stream,
                skip_azure_bindings=skip_azure_bindings,
            ).model_copy(update={"subscription_name": subscription_name})
            return planner.create(report, tenant_id)
        if env_file is not None:
            report, source = self.match_dotenv_file(
                subscription_id,
                env_file,
                skip_azure_bindings=skip_azure_bindings,
            )
            report = report.model_copy(update={"subscription_name": subscription_name})
            return planner.create_dotenv_file(report, tenant_id, str(source))
        if sops_file is not None:
            report, source = self.match_sops_dotenv_file(
                subscription_id,
                sops_file,
                skip_azure_bindings=skip_azure_bindings,
            )
            report = report.model_copy(update={"subscription_name": subscription_name})
            return planner.create_sops_dotenv_file(report, tenant_id, str(source))

        inventory = self.discover_inventory(subscription_id).model_copy(update={"subscription_name": subscription_name})
        requested_selections = direct_selections or self.prompt_selection(inventory)
        selections = self.canonicalize_selection(
            inventory,
            requested_selections,
            require_rotatable=True,
        )
        report = self.inspect_selection(
            subscription_id,
            inventory,
            selections,
            skip_azure_bindings=skip_azure_bindings,
        )
        return planner.create_selection(report, tenant_id)

    def rebuild(
        self,
        plan: RotationPlan,
        selected_subscription: SubscriptionSelection,
        stream: TextIO,
    ) -> RotationPlan:
        tenant_id = selected_subscription.tenant_id
        if not tenant_id:
            raise PlanningError("the tenant ID for the selected subscription is unavailable")
        skip_azure_bindings = plan.azure_binding_inspection is AzureBindingInspection.skipped
        subscription_name = selected_subscription.name
        planner = self.planner_factory()

        if plan.source_format is PlanSource.dotenv_stdin:
            report = self.match_dotenv(
                plan.subscription_id,
                stream,
                skip_azure_bindings=skip_azure_bindings,
            ).model_copy(update={"subscription_name": subscription_name})
            return planner.create(report, tenant_id)
        if plan.source_format is PlanSource.dotenv_file:
            if plan.source_path is None:
                raise PlanningError("the managed dotenv source path is unavailable")
            report, source = self.match_dotenv_file(
                plan.subscription_id,
                Path(plan.source_path),
                skip_azure_bindings=skip_azure_bindings,
            )
            report = report.model_copy(update={"subscription_name": subscription_name})
            return planner.create_dotenv_file(report, tenant_id, str(source))
        if plan.source_format is PlanSource.sops_dotenv_file:
            if plan.source_path is None:
                raise PlanningError("the managed SOPS dotenv source path is unavailable")
            report, source = self.match_sops_dotenv_file(
                plan.subscription_id,
                Path(plan.source_path),
                skip_azure_bindings=skip_azure_bindings,
            )
            report = report.model_copy(update={"subscription_name": subscription_name})
            return planner.create_sops_dotenv_file(report, tenant_id, str(source))
        if plan.source_format is not PlanSource.direct_selection:
            raise PlanningError("the rotation plan source is not supported")

        inventory = self.discover_inventory(plan.subscription_id).model_copy(
            update={"subscription_name": subscription_name}
        )
        selections = tuple(
            KeySlotSelection(resource_id=slot.resource_id, key_slot=slot.key_slot) for slot in plan.scheduled_slots
        )
        report = self.inspect_selection(
            plan.subscription_id,
            inventory,
            selections,
            skip_azure_bindings=skip_azure_bindings,
        )
        return planner.create_selection(report, tenant_id)

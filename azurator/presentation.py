"""Rich terminal rendering for Azurator reports and supported intents."""

from __future__ import annotations

from enum import IntEnum
from pathlib import Path

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from azurator.auth import SubscriptionSelection
from azurator.exporting import DotenvExportAssignment
from azurator.models import (
    BindingInspection,
    BindingInspectionStatus,
    BindingLocation,
    CandidateInspectionStatus,
    CredentialBinding,
    DiscoveryWarning,
    Inventory,
    MatchReport,
    PlanSource,
    PlanState,
    PlanStep,
    PlanStepAction,
    PlanStepPhase,
    PlanWarning,
    RotationPlan,
    SupportCatalog,
    WarningImpact,
)
from azurator.operation import (
    OperationError,
    OperationStatus,
    RetainedOperationReport,
    RetainedOperationStep,
    RetainedOperationSummary,
    RetainedStepState,
)

_WARNING_TITLES = {
    "malformed-storage-metadata": "Skipped resource",
    "storage-discovery-forbidden": "Storage discovery permission",
    "storage-discovery-failed": "Storage discovery failure",
    "malformed-cognitive-services-metadata": "Skipped AI resource",
    "cognitive-services-discovery-forbidden": "AI discovery permission",
    "cognitive-services-discovery-failed": "AI discovery failure",
    "malformed-storage-resource-id": "Storage resource scope",
    "storage-candidate-target-invalid": "Storage key inspection",
    "storage-key-retrieval-forbidden": "Storage key access",
    "storage-key-retrieval-failed": "Storage key inspection",
    "storage-key-response-incomplete": "Storage key response",
    "malformed-cognitive-services-resource-id": "AI resource scope",
    "cognitive-services-candidate-target-invalid": "AI key inspection",
    "cognitive-services-key-retrieval-forbidden": "AI key access",
    "cognitive-services-key-retrieval-failed": "AI key inspection",
    "cognitive-services-key-response-incomplete": "AI key response",
    "foundry-account-scope-invalid": "Foundry account scope",
    "foundry-project-list-forbidden": "Foundry project access",
    "foundry-project-list-failed": "Foundry project inspection",
    "foundry-project-list-request-failed": "Foundry project inspection",
    "foundry-project-list-response-failed": "Foundry project inspection",
    "foundry-project-metadata-invalid": "Foundry project metadata",
    "foundry-project-endpoint-invalid": "Foundry project endpoint",
    "foundry-connection-list-forbidden": "Foundry connection access",
    "foundry-connection-list-failed": "Foundry connection inspection",
    "foundry-connection-list-request-failed": "Foundry connection inspection",
    "foundry-connection-list-response-failed": "Foundry connection inspection",
    "foundry-connection-metadata-invalid": "Foundry connection metadata",
    "foundry-storage-target-unresolved": "Foundry Storage target",
    "foundry-cognitive-target-unresolved": "Foundry AI target",
    "foundry-connection-credential-forbidden": "Foundry credential access",
    "foundry-connection-credential-failed": "Foundry credential inspection",
    "foundry-connection-credential-request-failed": "Foundry credential inspection",
    "foundry-connection-credential-response-failed": "Foundry credential inspection",
    "foundry-connection-credential-unavailable": "Foundry credential response",
    "foundry-connection-key-unmatched": "Foundry key attribution",
    "app-service-site-list-forbidden": "App Service access",
    "app-service-site-list-failed": "App Service inspection",
    "app-service-site-list-request-failed": "App Service inspection",
    "app-service-site-list-response-failed": "App Service inspection",
    "app-service-site-metadata-invalid": "App Service metadata",
    "app-service-settings-list-forbidden": "App settings access",
    "app-service-settings-list-failed": "App settings inspection",
    "app-service-settings-list-request-failed": "App settings inspection",
    "app-service-settings-list-response-failed": "App settings inspection",
    "app-service-settings-response-invalid": "App settings response",
    "app-service-setting-key-ambiguous": "App setting key attribution",
    "app-service-settings-binding-coverage-limited": "App Service binding coverage",
    "app-service-settings-restart-and-concurrency": "App settings update",
    "binding-automation-unavailable": "Automatic binding update unavailable",
    "azure-binding-inspection-skipped": "Azure binding inspection skipped",
    "dotenv-file-plaintext-at-rest": "Plaintext dotenv file",
    "sops-file-managed-update": "SOPS-encrypted dotenv file",
}

_COVERAGE_WARNING_CODES = {"provider-coverage-limited"}
_BINDING_WARNING_CODES = {
    "storage-bindings-not-inspected",
    "cognitive-services-bindings-not-inspected",
}
_PERMISSION_WARNING_CODES = {
    "storage-key-permissions-not-tested",
    "cognitive-services-key-permissions-not-tested",
}
_BINDING_COVERAGE_WARNING_CODES = {
    "foundry-binding-coverage-limited",
    "app-service-settings-binding-coverage-limited",
}
_BINDING_SKIP_WARNING_CODES = {"azure-binding-inspection-skipped"}
_GROUPED_WARNING_CODES = (
    _COVERAGE_WARNING_CODES
    | _BINDING_WARNING_CODES
    | _BINDING_COVERAGE_WARNING_CODES
    | _BINDING_SKIP_WARNING_CODES
    | _PERMISSION_WARNING_CODES
)


class OutputDetail(IntEnum):
    """How much secret-safe explanatory detail human output should include."""

    normal = 0
    verbose = 1
    diagnostic = 2

    @classmethod
    def from_count(cls, count: int) -> OutputDetail:
        """Clamp a repeatable CLI verbosity count to the supported levels."""

        return cls(min(max(count, 0), cls.diagnostic))


def _diagnostic_suffix(warning: DiscoveryWarning | PlanWarning, detail: OutputDetail) -> str:
    if detail < OutputDetail.diagnostic:
        return ""
    fields = [
        f"code={warning.code}",
        f"impact={warning.impact.value}",
        f"category={warning.category.value}",
    ]
    if warning.provider is not None:
        fields.append(f"provider={warning.provider}")
    if warning.resource_id is not None:
        fields.append(f"resource={warning.resource_id}")
    binding_id = getattr(warning, "binding_id", None)
    if isinstance(binding_id, str):
        fields.append(f"binding={binding_id}")
    return f" [dim]({escape(', '.join(fields))})[/dim]"


def subscription_label(subscription_id: str, name: str | None = None) -> str:
    """Prefer a normalized subscription name while retaining its exact scope."""

    normalized_name = " ".join(name.split()) if name else None
    return f"{normalized_name} ({subscription_id})" if normalized_name else subscription_id


def service_label(provider: str, kind: str | None) -> str:
    """Return the concise user-facing service label for one supported resource."""

    if provider == "azure-storage":
        return "Storage Account"
    if provider == "azure-cognitive-services":
        return {
            "OpenAI": "Azure OpenAI",
            "AIServices": "Azure AI Services",
        }.get(kind or "", kind or "Azure AI Services")
    return kind or provider


def warning_title(code: str) -> str:
    """Return a stable human-readable title without changing warning policy."""

    return _WARNING_TITLES.get(code, code.replace("-", " ").capitalize())


def render_dotenv_permissions_warning() -> None:
    """Render one non-blocking local least-privilege notice."""

    typer.echo(
        "Warning: The dotenv file has broad permissions. Consider restricting access to the minimum required.",
        err=True,
    )


def render_support_catalog(
    catalog: SupportCatalog,
    *,
    show_key_resources: bool,
    show_bindings: bool,
    detail: OutputDetail = OutputDetail.normal,
) -> None:
    """Render supported key-resource and credential-binding types by domain role."""

    console = Console()
    if show_key_resources:
        count = len(catalog.key_resources)
        console.print(f"[bold]Supported key resources[/bold] [dim]· {count}[/dim]")
        console.print()
        table = Table()
        table.add_column("Key resource", overflow="fold")
        table.add_column("Key slots")
        for resource in catalog.key_resources:
            table.add_row(
                f"{escape(resource.name)}\n[dim]{escape(resource.resource_type)}[/dim]",
                ", ".join(escape(slot) for slot in resource.key_slots),
            )
        console.print(table)
        if detail >= OutputDetail.verbose:
            console.print()
            console.print("[dim]Supports discovery, matching, export, and rotation.[/dim]")

    if show_key_resources and show_bindings:
        console.print()

    if show_bindings:
        count = len(catalog.credential_bindings)
        console.print(f"[bold]Supported credential bindings[/bold] [dim]· {count}[/dim]")
        console.print()
        table = Table()
        table.add_column("Credential binding", overflow="fold")
        table.add_column("Location")
        table.add_column("Included by")
        for binding in catalog.credential_bindings:
            table.add_row(
                escape(binding.name),
                escape(binding.location.value.title()),
                escape("Automatic" if binding.included_by == "automatic" else binding.included_by),
            )
        console.print(table)
        if detail >= OutputDetail.verbose:
            console.print()
            console.print("[dim]Supports inspection, update, and verification.[/dim]")


def render_inventory(inventory: Inventory, *, detail: OutputDetail = OutputDetail.normal) -> None:
    """Render a metadata-only Azure inventory."""

    console = Console()
    resource_count = len(inventory.resources)
    console.print(f"[bold]Supported Azure key resources[/bold] [dim]· {resource_count}[/dim]")
    subscription = escape(subscription_label(inventory.subscription_id, inventory.subscription_name))
    console.print(f"[dim]Subscription {subscription}[/dim]")
    console.print()

    table = Table()
    table.add_column("Key resource")
    table.add_column("Service")
    table.add_column("Region")
    table.add_column("Key authentication")

    for resource in inventory.resources:
        table.add_row(
            resource.name,
            service_label(resource.provider, resource.kind),
            resource.location or "—",
            resource.key_authentication.value,
        )

    console.print(table)
    _render_inventory_notes(console, inventory, detail=detail)


def render_matches(report: MatchReport, *, detail: OutputDetail = OutputDetail.normal) -> None:
    """Render sparse exact-key matches and supported bindings."""

    console = Console()
    _render_match_heading(console, report, detail=detail)

    if not report.matches:
        console.print("No matching Azure key slots were found.")
    else:
        resources = {resource.resource_id: resource for resource in report.resources}
        table = Table()
        table.add_column("Input selector")
        table.add_column("Key resource")
        table.add_column("Service")
        table.add_column("Slot", justify="right")
        for match in report.matches:
            resource = resources[match.resource_id]
            table.add_row(
                escape(match.input_selector),
                escape(resource.name),
                escape(service_label(resource.provider, resource.kind)),
                escape(match.key_slot),
            )
        console.print(table)

    _render_bindings(console, report, detail=detail)
    _render_match_notes(console, report, detail=detail)


def render_match_matrix(report: MatchReport, *, detail: OutputDetail = OutputDetail.normal) -> None:
    """Render exact-key matches as an input-by-resource matrix."""

    console = Console()
    _render_match_heading(console, report, detail=detail)

    inspections = {inspection.resource_id: inspection for inspection in report.inspections}
    cells: dict[tuple[str, str], list[str]] = {}
    for match in report.matches:
        cells.setdefault((match.input_selector, match.resource_id), []).append(match.key_slot)

    table = Table()
    table.add_column("Input selector")
    for resource in report.resources:
        service = service_label(resource.provider, resource.kind)
        unavailable = inspections[resource.resource_id].status is CandidateInspectionStatus.unavailable
        status = "\n[yellow]unavailable[/yellow]" if unavailable else ""
        table.add_column(f"{escape(resource.name)}\n[dim]{escape(service)}[/dim]{status}")
    for selector in report.input_selectors:
        table.add_row(
            escape(selector),
            *(", ".join(cells.get((selector, resource.resource_id), ())) or "—" for resource in report.resources),
        )
    console.print(table)
    _render_bindings(console, report, detail=detail)
    _render_match_notes(console, report, detail=detail)


def render_export_intent(
    assignments: tuple[DotenvExportAssignment, ...],
    destination: Path,
    subscription: SubscriptionSelection,
    *,
    encrypted: bool,
    detail: OutputDetail = OutputDetail.normal,
) -> None:
    """Render the complete secret-free plaintext or SOPS export intent."""

    console = Console()
    slot_count = len({(assignment.resource.resource_id.casefold(), assignment.key_slot) for assignment in assignments})
    slot_noun = "key slot" if slot_count == 1 else "key slots"
    assignment_count = len(assignments)
    summary = f"{slot_count} {slot_noun}"
    if assignment_count != slot_count:
        assignment_noun = "assignment" if assignment_count == 1 else "assignments"
        summary += f", {assignment_count} {assignment_noun}"
    title = "SOPS-encrypted dotenv export" if encrypted else "Plaintext dotenv export"
    console.print(f"[bold]{title}[/bold] [dim]· {summary}[/dim]")
    console.print(f"[dim]Subscription {subscription_label(subscription.subscription_id, subscription.name)}[/dim]")
    console.print(f"[dim]Destination {escape(str(destination))}[/dim]")
    console.print()
    table = Table()
    table.add_column("Environment selector")
    table.add_column("Key resource")
    table.add_column("Service")
    table.add_column("Slot")
    for assignment in assignments:
        table.add_row(
            escape(assignment.selector),
            escape(assignment.resource.name),
            escape(service_label(assignment.resource.provider, assignment.resource.kind)),
            escape(assignment.key_slot),
        )
    console.print(table)
    if encrypted:
        if detail >= OutputDetail.verbose:
            console.print()
            console.print(
                "[dim]SOPS encrypts and verifies every value before Azurator creates the destination. "
                "No plaintext file is written.[/dim]"
            )
            console.print("[dim]The destination is created with mode 0600 and never replaces an existing path.[/dim]")
    else:
        console.print()
        console.print("[yellow]This creates a plaintext file containing live Azure keys.[/yellow]")
        if detail >= OutputDetail.verbose:
            console.print("[dim]The destination is created with mode 0600 and never replaces an existing path.[/dim]")
    if detail >= OutputDetail.verbose:
        console.print(
            "[dim]The export contains only the displayed retrievable slots from supported key resources.[/dim]"
        )


def render_plan(
    rotation_plan: RotationPlan,
    destination: Path | None,
    *,
    detail: OutputDetail = OutputDetail.normal,
) -> None:
    """Render a secret-free plan preview or persisted-plan result."""

    console = Console()
    slot_count = len(rotation_plan.scheduled_slots)
    if rotation_plan.state is PlanState.blocked:
        summary = "blocked"
    elif rotation_plan.state is PlanState.no_changes:
        summary = "no changes"
    else:
        slot_noun = "key slot" if slot_count == 1 else "key slots"
        step_noun = "step" if len(rotation_plan.steps) == 1 else "steps"
        summary = f"{slot_count} {slot_noun}, {len(rotation_plan.steps)} {step_noun}"
    console.print(f"[bold]Rotation plan[/bold] [dim]· {summary}[/dim]")
    subscription = escape(subscription_label(rotation_plan.subscription_id, rotation_plan.subscription_name))
    console.print(f"[dim]Subscription {subscription}[/dim]")
    if rotation_plan.source_format in {PlanSource.dotenv_file, PlanSource.sops_dotenv_file}:
        label = (
            "Managed SOPS dotenv file"
            if rotation_plan.source_format is PlanSource.sops_dotenv_file
            else "Managed dotenv file"
        )
        if rotation_plan.source_path is not None:
            console.print(f"[dim]{label} {escape(rotation_plan.source_path)}[/dim]")

    if not slot_count:
        console.print()
        if rotation_plan.state is PlanState.blocked:
            console.print("No executable rotation steps were generated.")
        else:
            if rotation_plan.source_format is PlanSource.direct_selection:
                console.print("No Azure key slots were selected for rotation.")
            else:
                console.print("No supplied value matched a supported Azure key slot.")
    else:
        console.print()
        _render_plan_selection(console, rotation_plan)
        if rotation_plan.steps:
            console.print()
            _render_plan_steps(console, rotation_plan)

    _render_plan_notes(console, rotation_plan, detail=detail)
    if destination is not None:
        console.print()
        console.print(f"Saved plan to [bold]{escape(str(destination))}[/bold].")
        if detail >= OutputDetail.verbose and rotation_plan.state is not PlanState.blocked and rotation_plan.steps:
            rotate_command = "azurator rotate --plan ..."
            if rotation_plan.source_format is PlanSource.dotenv_stdin:
                rotate_command += " --stdin"
            console.print(f"[dim]Rotate with '{rotate_command}'.[/dim]")
    elif detail >= OutputDetail.verbose:
        console.print()
        console.print("[dim]Preview only. No plan file was written.[/dim]")


def render_rotate_intent(
    rotation_plan: RotationPlan,
    operation_path: Path,
    *,
    resume: bool,
    detail: OutputDetail = OutputDetail.normal,
) -> None:
    """Render the exact executable plan before confirmation."""

    console = Console()
    action = "Resume rotation" if resume else "Rotate selected keys"
    console.print(f"[bold]{action}[/bold] [dim]· {len(rotation_plan.steps)} planned steps[/dim]")
    subscription = escape(subscription_label(rotation_plan.subscription_id, rotation_plan.subscription_name))
    console.print(f"[dim]Subscription {subscription}[/dim]")
    if rotation_plan.source_format in {PlanSource.dotenv_file, PlanSource.sops_dotenv_file}:
        label = (
            "Managed SOPS dotenv file"
            if rotation_plan.source_format is PlanSource.sops_dotenv_file
            else "Managed dotenv file"
        )
        if rotation_plan.source_path is not None:
            console.print(f"[dim]{label} {escape(rotation_plan.source_path)}[/dim]")
    console.print()
    _render_plan_selection(console, rotation_plan)
    console.print()
    _render_plan_steps(console, rotation_plan)
    _render_plan_notes(console, rotation_plan, detail=detail)
    console.print()
    console.print("[dim]Verification covers the planned Azure keys and credential-binding values.[/dim]")
    if detail >= OutputDetail.verbose:
        console.print(f"[dim]Transient recovery state {escape(str(operation_path))}[/dim]")
    if detail >= OutputDetail.verbose and not resume:
        console.print(
            "[dim]Recovery state is created only after confirmation and removed after verified success.[/dim]"
        )


def render_rotate_progress(rotation_plan: RotationPlan, step: PlanStep) -> None:
    """Render one verified completed execution step without secret data."""

    resources = {resource.resource_id: resource for resource in rotation_plan.resources}
    bindings = {binding.binding_id: binding for binding in rotation_plan.bindings}
    resource = resources[step.resource_id]
    binding = bindings.get(step.binding_id or "")
    target = _binding_target(binding) if binding is not None else resource.name
    typer.echo(
        f"Completed {step.sequence}/{len(rotation_plan.steps)}: "
        f"{_completed_step_label(step)} · {target} · slot {step.key_slot}"
    )


def render_rotate_complete(
    rotation_plan: RotationPlan,
    operation_path: Path,
    *,
    cleanup_error: OperationError | None,
    detail: OutputDetail = OutputDetail.normal,
) -> None:
    """Render verified rotation completion and recovery cleanup."""

    console = Console()
    console.print()
    console.print(
        f"[bold green]Rotation completed[/bold green] [dim]· {len(rotation_plan.steps)}/{len(rotation_plan.steps)} "
        "steps verified[/dim]"
    )
    if detail >= OutputDetail.verbose and rotation_plan.source_format in {
        PlanSource.dotenv_file,
        PlanSource.sops_dotenv_file,
    }:
        storage = "SOPS-encrypted dotenv" if rotation_plan.source_format is PlanSource.sops_dotenv_file else "dotenv"
        console.print(f"The managed {storage} assignments contain their verified final planned values.")
    render_operation_cleanup(operation_path, cleanup_error, console=console, detail=detail)


def render_operation_cleanup(
    operation_path: Path,
    cleanup_error: OperationError | None,
    *,
    console: Console | None = None,
    detail: OutputDetail = OutputDetail.normal,
) -> None:
    """Render whether transient recovery state was removed."""

    output = console or Console()
    if cleanup_error is None:
        if detail >= OutputDetail.verbose:
            output.print("[dim]Transient recovery state was removed.[/dim]")
        return
    output.print(
        "[yellow]Rotation succeeded, but completed recovery state could not be removed. "
        f"Inspect {escape(str(operation_path))}.[/yellow]"
    )


def render_operation_list(
    report: RetainedOperationReport,
    *,
    detail: OutputDetail = OutputDetail.normal,
) -> None:
    """Render a concise local-only index of retained recovery operations."""

    console = Console()
    operation_count = len(report.operations)
    noun = "operation" if operation_count == 1 else "operations"
    if not report.operations and not report.invalid_operation_ids:
        console.print("No retained rotation operations.")
        if detail >= OutputDetail.verbose:
            console.print("[dim]Verified successful rotations do not retain local operation history.[/dim]")
        return

    console.print(f"[bold]Retained rotation operations[/bold] [dim]· {operation_count} valid {noun}[/dim]")

    if report.operations:
        console.print()
        for index, summary in enumerate(report.operations):
            if index:
                console.print()
            current = _retained_step_compact(summary.current_step)
            console.print(f"[bold]{summary.operation_id}[/bold]")
            console.print(
                f"  {summary.status.value} · {summary.completed_steps}/{summary.total_steps} verified · "
                f"updated {escape(summary.updated_at.isoformat(timespec='seconds'))}"
            )
            subscription = escape(subscription_label(summary.subscription_id, summary.subscription_name))
            console.print(f"  Subscription {subscription}")
            console.print(f"  {escape(current)}")
            if detail >= OutputDetail.verbose and summary.error_code is not None:
                console.print(f"  Failure code {escape(summary.error_code)}")

    if report.invalid_operation_ids:
        console.print()
        count = len(report.invalid_operation_ids)
        noun = "entry" if count == 1 else "entries"
        message = f"[yellow]{count} retained {noun} could not be read safely.[/yellow]"
        console.print(message)
        if detail >= OutputDetail.verbose:
            operation_ids = ", ".join(str(operation_id) for operation_id in report.invalid_operation_ids)
            console.print(f"[dim]Unreadable operation IDs: {escape(operation_ids)}[/dim]")

    if detail >= OutputDetail.verbose:
        console.print()
        console.print("[dim]Only local recovery state was inspected. Azure was not contacted.[/dim]")
        if report.operations:
            console.print("[dim]Use 'azurator operation show OPERATION_ID' for one operation.[/dim]")


def render_operation_show(
    summary: RetainedOperationSummary,
    *,
    detail: OutputDetail = OutputDetail.normal,
) -> None:
    """Render one retained operation without exposing its embedded plan or verifiers."""

    console = Console()
    status = "unfinished" if summary.status is OperationStatus.running else summary.status.value
    console.print(f"[bold]Retained rotation operation[/bold] [dim]· {status}[/dim]")
    console.print(f"[dim]Operation {summary.operation_id}[/dim]")
    subscription = escape(subscription_label(summary.subscription_id, summary.subscription_name))
    console.print(f"[dim]Subscription {subscription}[/dim]")
    console.print(f"[dim]Started {escape(summary.started_at.isoformat(timespec='seconds'))}[/dim]")
    console.print(f"[dim]Updated {escape(summary.updated_at.isoformat(timespec='seconds'))}[/dim]")
    console.print()
    console.print(f"Verified progress: {summary.completed_steps}/{summary.total_steps} steps")
    if summary.error_code is not None:
        console.print(f"Last failure code: [yellow]{escape(summary.error_code)}[/yellow]")
    if summary.current_step is not None:
        step = summary.current_step
        heading = "Pending checkpoint" if step.state is RetainedStepState.pending else "Next unstarted step"
        console.print(
            f"{heading}: {step.sequence}/{summary.total_steps} · "
            f"{escape(_retained_step_label(step))} · {escape(_retained_step_target(step))} · "
            f"slot {escape(step.key_slot)}"
        )
        if step.state is RetainedStepState.pending:
            console.print("[dim]Current Azure state will be reconciled before this step is resumed.[/dim]")

    console.print()
    table = Table(title="Scheduled key slots")
    table.add_column("Key resource")
    table.add_column("Service")
    table.add_column("Slots")
    for resource in summary.resources:
        table.add_row(
            escape(resource.name),
            escape(service_label(resource.provider, resource.kind)),
            escape(", ".join(resource.key_slots)),
        )
    console.print(table)
    console.print()
    if summary.status is OperationStatus.completed:
        console.print(
            "[yellow]Rotation is recorded as complete; the retained artifact is awaiting validated cleanup.[/yellow]"
        )
    console.print(f"Resume command: [bold]{escape(summary.resume_command)}[/bold]")
    if detail >= OutputDetail.verbose:
        console.print(
            "[dim]Only local recovery state was inspected. Resume repeats authentication, scope, source, "
            "progress, and drift checks before continuing.[/dim]"
        )


def _retained_step_compact(step: RetainedOperationStep | None) -> str:
    if step is None:
        return "cleanup pending"
    prefix = "pending" if step.state is RetainedStepState.pending else "next"
    return f"{prefix} {step.sequence} · {_retained_step_label(step)}"


def _retained_step_label(step: RetainedOperationStep) -> str:
    if step.action is PlanStepAction.regenerate_key:
        return "Regenerate Azure key"
    if step.action is PlanStepAction.verify_binding:
        return "Verify bridge key" if step.phase is PlanStepPhase.bridge else "Verify rotated key"
    return "Persist bridge key" if step.phase is PlanStepPhase.bridge else "Persist rotated key"


def _retained_step_target(step: RetainedOperationStep) -> str:
    if step.binding_name is None:
        return step.resource_name
    if step.binding_scope_name is None:
        return step.binding_name
    return f"{step.binding_scope_name} / {step.binding_name}"


def _render_plan_selection(console: Console, rotation_plan: RotationPlan) -> None:
    resources = {resource.resource_id: resource for resource in rotation_plan.resources}
    table = Table(title="Selected key slots")
    table.add_column("Key resource")
    table.add_column("Service")
    table.add_column("Slot")
    shows_selectors = rotation_plan.source_format in {
        PlanSource.dotenv_stdin,
        PlanSource.dotenv_file,
        PlanSource.sops_dotenv_file,
    }
    if shows_selectors:
        table.add_column("Input selectors")
    for scheduled in rotation_plan.scheduled_slots:
        resource = resources[scheduled.resource_id]
        row = [
            escape(resource.name),
            escape(service_label(resource.provider, resource.kind)),
            escape(scheduled.key_slot),
        ]
        if shows_selectors:
            row.append(escape(", ".join(scheduled.input_selectors)))
        table.add_row(*row)
    console.print(table)


def _render_plan_steps(console: Console, rotation_plan: RotationPlan) -> None:
    resources = {resource.resource_id: resource for resource in rotation_plan.resources}
    bindings = {binding.binding_id: binding for binding in rotation_plan.bindings}
    table = Table(title="Ordered steps")
    table.add_column("#", justify="right")
    table.add_column("Action")
    table.add_column("Target")
    table.add_column("Slot")
    for step in rotation_plan.steps:
        resource = resources[step.resource_id]
        binding = bindings.get(step.binding_id or "")
        target = _binding_target(binding) if binding is not None else resource.name
        table.add_row(
            str(step.sequence),
            _plan_step_label(step),
            escape(target),
            escape(step.key_slot),
        )
    console.print(table)


def _plan_step_label(step: PlanStep) -> str:
    if step.action is PlanStepAction.regenerate_key:
        return "Regenerate Azure key"
    if step.action is PlanStepAction.verify_binding:
        return "Verify temporary bridge key" if step.phase is PlanStepPhase.bridge else "Verify final rotated key"
    return "Persist temporary bridge key" if step.phase is PlanStepPhase.bridge else "Persist final rotated key"


def _completed_step_label(step: PlanStep) -> str:
    if step.action is PlanStepAction.regenerate_key:
        return "Azure key regenerated"
    if step.action is PlanStepAction.verify_binding:
        return "Temporary bridge key verified" if step.phase is PlanStepPhase.bridge else "Final rotated key verified"
    return "Temporary bridge key persisted" if step.phase is PlanStepPhase.bridge else "Final rotated key persisted"


def _binding_target(binding: CredentialBinding) -> str:
    if binding.provider in {"local-dotenv-file", "local-sops-dotenv-file"}:
        return f"{binding.scope_name} · {binding.name}"
    return f"{binding.scope_name} / {binding.name}"


def _plan_scope_note(rotation_plan: RotationPlan) -> str:
    resources = {resource.resource_id: resource for resource in rotation_plan.resources}
    counts = {"azure-storage": 0, "azure-cognitive-services": 0, "other": 0}
    for scheduled in rotation_plan.scheduled_slots:
        provider = resources[scheduled.resource_id].provider
        bucket = provider if provider in counts else "other"
        counts[bucket] += 1

    clauses: list[str] = []
    for provider, label in (
        ("azure-storage", "Storage Account key"),
        ("azure-cognitive-services", "Azure AI key"),
        ("other", "other supported key"),
    ):
        count = counts[provider]
        if count:
            clauses.append(f"{count} {label} {'slot' if count == 1 else 'slots'}")
    if not clauses:
        return "Plan scope: no Azure key slots were selected. Coverage remains limited to supported key resources."

    resource_count = len({scheduled.resource_id for scheduled in rotation_plan.scheduled_slots})
    resource_noun = "key resource" if resource_count == 1 else "key resources"
    return (
        f"Plan scope: {' and '.join(clauses)} selected on {resource_count} {resource_noun}. "
        "Other Azure credential types are not included."
    )


def _render_plan_notes(
    console: Console,
    rotation_plan: RotationPlan,
    *,
    detail: OutputDetail,
) -> None:
    if not rotation_plan.warnings:
        return

    resources = {resource.resource_id: resource for resource in rotation_plan.resources}
    summary_by_code = {
        "storage-bindings-not-inspected": (
            "No Azure-side configurations containing selected Storage keys were checked."
        ),
        "cognitive-services-bindings-not-inspected": (
            "No Azure-side configurations containing selected Azure AI keys were checked."
        ),
    }
    scope_notes: list[tuple[str, PlanWarning]] = []
    notes: list[tuple[str, WarningImpact, PlanWarning]] = []
    seen: set[str] = set()
    for warning in rotation_plan.warnings:
        is_scope_summary = False
        if warning.code == "provider-coverage-limited":
            if detail < OutputDetail.verbose:
                continue
            message = _plan_scope_note(rotation_plan)
        elif warning.code == "foundry-binding-coverage-limited":
            if detail >= OutputDetail.verbose:
                message = (
                    binding_scope_note({resource.provider for resource in rotation_plan.resources}) or warning.message
                )
            else:
                message = _azure_binding_scope_summary(rotation_plan)
                if message is None:
                    continue
                is_scope_summary = True
        elif warning.code == "app-service-settings-binding-coverage-limited":
            if detail >= OutputDetail.verbose:
                message = warning.message
            else:
                message = _azure_binding_scope_summary(rotation_plan)
                if message is None:
                    continue
                is_scope_summary = True
        elif warning.code == "azure-binding-inspection-skipped":
            message = "Azure credential-binding inspection was skipped."
            if any(binding.location is BindingLocation.local for binding in rotation_plan.bindings):
                message += " Explicit local bindings remain included."
        elif warning.code == "dotenv-file-plaintext-at-rest":
            if detail >= OutputDetail.verbose:
                message = warning.message
            else:
                message = "Managed dotenv assignments may remain on a valid sibling key if rotation is interrupted."
        elif warning.code == "sops-file-managed-update":
            if detail >= OutputDetail.verbose:
                message = warning.message
            else:
                message = "Managed dotenv assignments may remain on a valid sibling key if rotation is interrupted."
        elif warning.code == "app-service-settings-restart-and-concurrency":
            affected = tuple(
                binding
                for binding in rotation_plan.bindings
                if binding.provider == "azure-app-service-settings" and binding.scope_id == warning.resource_id
            )
            update_count = sum(
                step.action is PlanStepAction.update_binding
                and any(step.binding_id == binding.binding_id for binding in affected)
                for step in rotation_plan.steps
            )
            app_name = affected[0].scope_name if affected else "the selected app"
            noun = "replacement" if update_count == 1 else "replacements"
            message = (
                f"App Service {app_name}: {update_count} complete application-settings {noun} are planned. "
                "Each update restarts the app. Do not edit or deploy settings concurrently. "
                "Workload health is not checked."
            )
        else:
            if warning.impact is WarningImpact.advisory and detail < OutputDetail.verbose:
                continue
            message = summary_by_code.get(warning.code)
        if message is None:
            resource = resources.get(warning.resource_id or "")
            resource_suffix = f" ({resource.name})" if resource is not None else ""
            message = f"{warning_title(warning.code)}{resource_suffix}: {warning.message}"
        if message in seen:
            continue
        seen.add(message)
        if is_scope_summary:
            scope_notes.append((message, warning))
            continue
        notes.append((message, warning.impact, warning))

    if not scope_notes and not notes:
        return
    console.print()
    for message, warning in scope_notes:
        console.print(f"[dim]{escape(message)}[/dim]{_diagnostic_suffix(warning, detail)}")
    if not notes:
        return
    if scope_notes:
        console.print()
    has_warning = any(impact is not WarningImpact.advisory for _, impact, _ in notes)
    console.print("[bold]Warnings[/bold]" if has_warning else "[bold]Details[/bold]")
    styles = {
        WarningImpact.advisory: "dim",
        WarningImpact.confirmation: "yellow",
        WarningImpact.blocking: "red",
    }
    for message, impact, warning in notes:
        style = styles[impact]
        suffix = _diagnostic_suffix(warning, detail)
        console.print(f"[{style}]• {escape(message)}[/{style}]{suffix}")


def _azure_binding_scope_summary(rotation_plan: RotationPlan) -> str | None:
    providers = {
        *(inspection.provider for inspection in rotation_plan.binding_inspections),
        *(
            warning.provider
            for warning in rotation_plan.warnings
            if warning.code in {"foundry-binding-coverage-limited", "app-service-settings-binding-coverage-limited"}
            and warning.provider is not None
        ),
    }
    labels: list[str] = []
    if "azure-foundry-connections" in providers:
        labels.append("Foundry project key connections")
    if "azure-app-service-settings" in providers:
        labels.append("top-level App Service application settings")
    if not labels:
        return None
    if len(labels) == 1:
        scope = labels[0]
    else:
        scope = f"{', '.join(labels[:-1])} and {labels[-1]}"
    return f"Azure bindings checked: {scope}."


def _render_bindings(
    console: Console,
    report: MatchReport,
    *,
    detail: OutputDetail,
) -> None:
    if not report.binding_inspections:
        return

    foundry_inspections = tuple(
        inspection for inspection in report.binding_inspections if inspection.provider == "azure-foundry-connections"
    )
    foundry_bindings = tuple(binding for binding in report.bindings if binding.provider == "azure-foundry-connections")
    if foundry_inspections and (foundry_bindings or detail >= OutputDetail.verbose):
        _render_foundry_bindings(console, report, foundry_bindings, foundry_inspections)

    app_service_inspections = tuple(
        inspection for inspection in report.binding_inspections if inspection.provider == "azure-app-service-settings"
    )
    app_service_bindings = tuple(
        binding for binding in report.bindings if binding.provider == "azure-app-service-settings"
    )
    if app_service_inspections and (app_service_bindings or detail >= OutputDetail.verbose):
        _render_app_service_bindings(console, report, app_service_bindings, app_service_inspections)

    dotenv_inspections = tuple(
        inspection for inspection in report.binding_inspections if inspection.provider == "local-dotenv-file"
    )
    dotenv_bindings = tuple(binding for binding in report.bindings if binding.provider == "local-dotenv-file")
    if dotenv_inspections and (dotenv_bindings or detail >= OutputDetail.verbose):
        _render_dotenv_bindings(console, report, dotenv_bindings)

    sops_inspections = tuple(
        inspection for inspection in report.binding_inspections if inspection.provider == "local-sops-dotenv-file"
    )
    sops_bindings = tuple(binding for binding in report.bindings if binding.provider == "local-sops-dotenv-file")
    if sops_inspections and (sops_bindings or detail >= OutputDetail.verbose):
        _render_dotenv_bindings(console, report, sops_bindings, encrypted=True)


def _render_foundry_bindings(
    console: Console,
    report: MatchReport,
    bindings: tuple[CredentialBinding, ...],
    inspections: tuple[BindingInspection, ...],
) -> None:
    count = len(bindings)
    noun = "connection" if count == 1 else "connections"
    console.print()
    console.print(f"[bold]Foundry connections[/bold] [dim]· {count} {noun}[/dim]")
    if not bindings:
        incomplete = any(inspection.status is not BindingInspectionStatus.inspected for inspection in inspections)
        if incomplete:
            console.print("No supported Foundry key connection was confirmed; inspection was incomplete.")
        else:
            console.print("No checked Foundry project connection targeted a matched Azure key resource.")
        return

    resources = {resource.resource_id: resource for resource in report.resources}
    table = Table()
    table.add_column("Foundry project")
    table.add_column("Connection name")
    table.add_column("Target key resource")
    table.add_column("Stored key slot")
    for binding in bindings:
        resource = resources[binding.key_resource_id]
        slot = escape(binding.key_slot) if binding.key_slot is not None else "[yellow]unknown[/yellow]"
        table.add_row(
            escape(binding.scope_name),
            escape(binding.name),
            escape(resource.name),
            slot,
        )
    console.print(table)


def _render_dotenv_bindings(
    console: Console,
    report: MatchReport,
    bindings: tuple[CredentialBinding, ...],
    *,
    encrypted: bool = False,
) -> None:
    assignment_count = sum(len(binding.selectors) for binding in bindings)
    noun = "assignment" if assignment_count == 1 else "assignments"
    console.print()
    label = "SOPS dotenv assignments" if encrypted else "Dotenv assignments"
    console.print(f"[bold]{label}[/bold] [dim]· {assignment_count} {noun}[/dim]")
    if not bindings:
        console.print("No dotenv assignment matched an Azure key slot.")
        return

    resources = {resource.resource_id: resource for resource in report.resources}
    table = Table()
    table.add_column("File")
    table.add_column("Assignments")
    table.add_column("Target key resource")
    table.add_column("Stored key slot")
    for binding in bindings:
        resource = resources[binding.key_resource_id]
        table.add_row(
            escape(binding.scope_name),
            escape(", ".join(binding.selectors)),
            escape(resource.name),
            escape(binding.key_slot or "unknown"),
        )
    console.print(table)


def _render_app_service_bindings(
    console: Console,
    report: MatchReport,
    bindings: tuple[CredentialBinding, ...],
    inspections: tuple[BindingInspection, ...],
) -> None:
    setting_count = sum(len(binding.selectors) for binding in bindings)
    noun = "setting" if setting_count == 1 else "settings"
    console.print()
    console.print(f"[bold]App Service settings[/bold] [dim]· {setting_count} matched {noun}[/dim]")
    if not bindings:
        incomplete = any(inspection.status is not BindingInspectionStatus.inspected for inspection in inspections)
        if incomplete:
            console.print("No App Service setting was confirmed; inspection was incomplete.")
        else:
            console.print("No checked App Service application setting exactly matched a selected Azure key.")
        return

    resources = {resource.resource_id: resource for resource in report.resources}
    table = Table()
    table.add_column("App Service app")
    table.add_column("Application settings")
    table.add_column("Target key resource")
    table.add_column("Stored key slot")
    for binding in bindings:
        resource = resources[binding.key_resource_id]
        table.add_row(
            escape(binding.scope_name),
            escape(", ".join(binding.selectors)),
            escape(resource.name),
            escape(binding.key_slot or "unknown"),
        )
    console.print(table)


def _render_match_heading(
    console: Console,
    report: MatchReport,
    *,
    detail: OutputDetail,
) -> None:
    match_count = len(report.matches)
    match_noun = "match" if match_count == 1 else "matches"
    console.print(f"[bold]Azure key matches[/bold] [dim]· {match_count} {match_noun}[/dim]")
    subscription = escape(subscription_label(report.subscription_id, report.subscription_name))
    console.print(f"[dim]Subscription {subscription}[/dim]")
    if detail >= OutputDetail.verbose:
        compared_resources = sum(
            inspection.status is CandidateInspectionStatus.compared for inspection in report.inspections
        )
        input_noun = "value" if len(report.input_selectors) == 1 else "values"
        slot_noun = "slot" if report.candidate_slots_compared == 1 else "slots"
        resource_noun = "key resource" if compared_resources == 1 else "key resources"
        console.print(
            f"[dim]Compared {len(report.input_selectors)} input {input_noun} with "
            f"{report.candidate_slots_compared} Azure key {slot_noun} across "
            f"{compared_resources} {resource_noun}.[/dim]"
        )
    console.print()


def binding_scope_note(providers: set[str]) -> str | None:
    has_storage = "azure-storage" in providers
    has_ai = "azure-cognitive-services" in providers
    if has_storage and has_ai:
        return (
            "Azure binding scope: public-cloud, project-level Foundry AzureStorageAccount/AccountKey and "
            "AzureOpenAI/ApiKey connections targeting the selected resources. Other Azure binding categories "
            "were not inspected. Running workloads were not tested."
        )
    if has_storage:
        return (
            "Azure binding scope: public-cloud, project-level Foundry AzureStorageAccount/AccountKey connections "
            "targeting the selected Storage Accounts. Other Storage binding categories were not inspected. "
            "Running workloads were not tested."
        )
    if has_ai:
        return (
            "Azure binding scope: public-cloud, project-level Foundry AzureOpenAI/ApiKey connections targeting "
            "the selected Azure AI resources. Other AI binding categories were not inspected. Running workloads "
            "were not tested."
        )
    return None


def _render_match_notes(
    console: Console,
    report: MatchReport,
    *,
    detail: OutputDetail,
) -> None:
    notes: list[str] = []
    alerts: list[str] = []
    warning_codes = {warning.code for warning in report.warnings}
    resource_providers = {resource.provider for resource in report.resources}
    if detail >= OutputDetail.verbose and report.skipped_empty_selectors:
        count = len(report.skipped_empty_selectors)
        noun = "assignment" if count == 1 else "assignments"
        notes.append(f"Skipped {count} empty dotenv {noun}.")
    if detail >= OutputDetail.verbose and warning_codes & _COVERAGE_WARNING_CODES:
        key_types: list[str] = []
        if "azure-storage" in resource_providers:
            key_types.append("Storage Account key1/key2")
        if "azure-cognitive-services" in resource_providers:
            key_types.append("Azure AI Key1/Key2")
        if key_types:
            notes.append(
                f"Key comparison scope: {' and '.join(key_types)}. Other Azure credential types were not checked."
            )
        else:
            notes.append(
                "Key comparison was limited to supported key-resource types. Other Azure credentials were not checked."
            )
    if detail >= OutputDetail.verbose and "storage-bindings-not-inspected" in warning_codes:
        notes.append("No Azure-side configurations containing matched Storage keys were checked.")
    if detail >= OutputDetail.verbose and "cognitive-services-bindings-not-inspected" in warning_codes:
        notes.append("No Azure-side configurations containing matched Azure AI keys were checked.")
    if detail >= OutputDetail.verbose and "foundry-binding-coverage-limited" in warning_codes:
        matched_ids = {match.resource_id for match in report.matches}
        matched_providers = {resource.provider for resource in report.resources if resource.resource_id in matched_ids}
        coverage_warning = next(
            warning for warning in report.warnings if warning.code == "foundry-binding-coverage-limited"
        )
        notes.append(binding_scope_note(matched_providers) or coverage_warning.message)
    if detail >= OutputDetail.verbose:
        notes.extend(
            warning.message
            for warning in report.warnings
            if warning.code == "app-service-settings-binding-coverage-limited"
        )
    if warning_codes & _BINDING_SKIP_WARNING_CODES:
        message = "Azure credential-binding inspection was skipped."
        if any(binding.location is BindingLocation.local for binding in report.bindings):
            message += " Explicit local bindings remain included."
        alerts.append(message)

    resources = {resource.resource_id: resource for resource in report.resources}
    for inspection in report.binding_inspections:
        if inspection.status is BindingInspectionStatus.inspected:
            continue
        has_specific_warning = any(
            warning.provider == inspection.provider and warning.code not in _BINDING_COVERAGE_WARNING_CODES
            for warning in report.warnings
        )
        if has_specific_warning:
            continue
        resource = resources.get(inspection.resource_id)
        target = resource.name if resource is not None else "a selected key resource"
        alerts.append(f"Credential-binding inspection was incomplete for {target}.")

    grouped_codes = (
        _COVERAGE_WARNING_CODES
        | _BINDING_WARNING_CODES
        | _BINDING_COVERAGE_WARNING_CODES
        | _BINDING_SKIP_WARNING_CODES
        | _PERMISSION_WARNING_CODES
    )
    verbose_only_codes = {
        "app-service-settings-restart-and-concurrency",
        "dotenv-file-plaintext-at-rest",
        "sops-file-managed-update",
    }
    detailed = [
        warning
        for warning in report.warnings
        if warning.code not in grouped_codes
        and (detail >= OutputDetail.verbose or warning.code not in verbose_only_codes)
        and (detail >= OutputDetail.verbose or warning.impact is not WarningImpact.advisory)
    ]
    if not notes and not alerts and not detailed:
        return

    console.print()
    console.print("[bold]Warnings[/bold]" if alerts or detailed else "[bold]Details[/bold]")
    for alert in alerts:
        console.print(f"[yellow]• {escape(alert)}[/yellow]")
    for note in notes:
        console.print(f"[dim]• {escape(note)}[/dim]")
    for warning in detailed:
        resource = resources.get(warning.resource_id or "")
        resource_suffix = f" · {escape(resource.name)}" if resource is not None else ""
        suffix = _diagnostic_suffix(warning, detail)
        console.print(
            f"[yellow]• {escape(warning_title(warning.code))}{resource_suffix}:[/yellow] "
            f"{escape(warning.message)}{suffix}"
        )


def _render_inventory_notes(
    console: Console,
    inventory: Inventory,
    *,
    detail: OutputDetail,
) -> None:
    warning_codes = {warning.code for warning in inventory.warnings}
    notes: list[str] = []

    if detail >= OutputDetail.verbose and warning_codes & _COVERAGE_WARNING_CODES:
        notes.append(
            "Coverage is limited to supported key-resource types. Other Azure resource types are not included."
        )

    bindings_missing = detail >= OutputDetail.verbose and bool(warning_codes & _BINDING_WARNING_CODES)
    permissions_missing = detail >= OutputDetail.verbose and bool(warning_codes & _PERMISSION_WARNING_CODES)
    if bindings_missing and permissions_missing:
        notes.append("Credential bindings and key-operation permissions are not checked by discover.")
    elif bindings_missing:
        notes.append("Credential bindings are not inspected by discover.")
    elif permissions_missing:
        notes.append("Key-operation permissions are not checked by discover.")

    seen: set[tuple[str, str]] = set()
    detailed_warnings: list[DiscoveryWarning] = []
    for warning in inventory.warnings:
        identity = (warning.code, warning.message)
        if warning.code in _GROUPED_WARNING_CODES or identity in seen:
            continue
        seen.add(identity)
        detailed_warnings.append(warning)

    if not notes and not detailed_warnings:
        return

    console.print()
    console.print("[bold]Warnings[/bold]" if detailed_warnings else "[bold]Details[/bold]")
    for note in notes:
        console.print(f"[dim]• {note}[/dim]")
    for warning in detailed_warnings:
        suffix = _diagnostic_suffix(warning, detail)
        console.print(f"[yellow]• {escape(warning_title(warning.code))}:[/yellow] {escape(warning.message)}{suffix}")

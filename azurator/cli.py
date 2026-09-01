"""Standalone Typer command adapter for Azurator."""

from __future__ import annotations

import json
import os
import shlex
import sys
from collections.abc import Generator, Sequence
from contextlib import contextmanager
from io import StringIO
from pathlib import Path
from typing import NoReturn, TextIO
from uuid import UUID, uuid4

import typer
from azure.core.exceptions import (
    ClientAuthenticationError,
    HttpResponseError,
    ServiceRequestError,
    ServiceResponseError,
)
from azure.identity import AuthenticationRequiredError, CredentialUnavailableError
from azure.mgmt.core.tools import parse_resource_id
from platformdirs import user_state_path
from pydantic import ValidationError
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from azurator import __version__
from azurator.auth import (
    AuthConfigurationError,
    Authenticator,
    AuthError,
    AuthMethod,
    AuthStore,
    SubscriptionSelection,
)
from azurator.composition import discover_inventory as _compose_discover_inventory
from azurator.composition import execution_service as _compose_execution_service
from azurator.composition import export_service as _compose_export_service
from azurator.composition import inspect_selection as _compose_inspect_selection
from azurator.composition import match_dotenv as _compose_match_dotenv
from azurator.execution import ExecutionError, ExecutionService
from azurator.exporting import (
    DotenvExportService,
    ExportError,
    SopsDotenvExportService,
    build_dotenv_export_assignments,
)
from azurator.files import (
    MAX_OPERATION_ARTIFACT_BYTES,
    PrivateFileExistsError,
    UnsafeInputPathError,
    UnsafeOutputPathError,
    create_private_bytes,
    create_private_text,
    ensure_private_directory,
    managed_plaintext_permissions_are_broad,
    open_managed_plaintext,
    read_private_text,
    resolve_parent_path,
    write_private_text,
)
from azurator.inputs import SecretInputError
from azurator.matching import MatchingError
from azurator.models import (
    DiscoveredResource,
    Inventory,
    KeyAuthentication,
    KeySlot,
    KeySlotSelection,
    MatchReport,
    PlanSource,
    RotationPlan,
    SelectionReport,
)
from azurator.operation import (
    OperationCatalog,
    OperationCatalogError,
    OperationContractError,
    OperationError,
    OperationState,
    OperationStatus,
    OperationStore,
    validate_operation_contract,
)
from azurator.planning import PlanningError
from azurator.presentation import (
    render_dotenv_permissions_warning as _render_dotenv_permissions_warning,
)
from azurator.presentation import render_export_intent as _render_export_intent
from azurator.presentation import (
    render_inventory as _render_inventory,
)
from azurator.presentation import (
    render_match_matrix as _render_match_matrix,
)
from azurator.presentation import (
    render_matches as _render_matches,
)
from azurator.presentation import render_operation_cleanup as _render_operation_cleanup
from azurator.presentation import render_operation_list as _render_operation_list
from azurator.presentation import render_operation_show as _render_operation_show
from azurator.presentation import render_plan as _render_plan
from azurator.presentation import render_rotate_complete as _render_rotate_complete
from azurator.presentation import render_rotate_intent as _render_rotate_intent
from azurator.presentation import render_rotate_progress as _render_rotate_progress
from azurator.presentation import render_support_catalog as _render_support_catalog
from azurator.presentation import (
    service_label as _service_label,
)
from azurator.presentation import (
    subscription_label as _subscription_label,
)
from azurator.providers.base import ProviderOperationError
from azurator.providers.builtin import builtin_support_catalog
from azurator.providers.dotenv_file import (
    DotenvFileContractError,
    attach_dotenv_file_bindings,
    normalize_dotenv_file_path,
)
from azurator.providers.sops_dotenv_file import (
    SopsDotenvFileContractError,
    SopsDotenvFileProvider,
    attach_sops_dotenv_file_bindings,
    normalize_sops_dotenv_file_path,
)
from azurator.sops import SopsCli, SopsError
from azurator.workflows import RotationPlanningWorkflow

app = typer.Typer(
    name="azurator",
    help="Find, export, plan, and safely rotate supported Azure account keys.",
    no_args_is_help=True,
    pretty_exceptions_enable=False,
)
auth_app = typer.Typer(help="Inspect or clear Azurator's authentication selection.", no_args_is_help=True)
app.add_typer(auth_app, name="auth")
operation_app = typer.Typer(help="Inspect retained local rotation recovery state.", no_args_is_help=True)
app.add_typer(operation_app, name="operation")


_MAX_PLAN_ARTIFACT_BYTES = MAX_OPERATION_ARTIFACT_BYTES


class _EphemeralStringIO(StringIO):
    """Release a decrypted in-memory buffer as soon as its parser reaches EOF."""

    def readline(self, size: int = -1, /) -> str:
        line = super().readline(size)
        if line == "":
            self.seek(0)
            self.truncate(0)
            self.close()
        return line


class DirectSelectionError(ValueError):
    """One scriptable resource/slot selector violates the supported CLI contract."""


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"azurator {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show the installed version and exit.",
    ),
) -> None:
    """Find and safely rotate selected Azure account keys."""

    del version


def _auth_store() -> AuthStore:
    return AuthStore()


def _authenticator() -> Authenticator:
    return Authenticator(_auth_store())


@contextmanager
def _terminal_status(message: str) -> Generator[None, None, None]:
    """Show transient progress only on an interactive stderr terminal."""

    if not sys.stderr.isatty():
        yield
        return
    with Console(stderr=True).status(message):
        yield


def _discover_inventory(subscription_id: str) -> Inventory:
    with _terminal_status("Discovering supported Azure key resources..."):
        return _compose_discover_inventory(subscription_id, _auth_store())


def _match_dotenv(
    subscription_id: str,
    stream: TextIO,
    *,
    skip_azure_bindings: bool = False,
) -> MatchReport:
    message = (
        "Comparing dotenv values with supported Azure keys..."
        if skip_azure_bindings
        else "Comparing dotenv values and inspecting Azure credential bindings..."
    )
    with _terminal_status(message):
        return _compose_match_dotenv(
            subscription_id,
            stream,
            _auth_store(),
            skip_azure_bindings=skip_azure_bindings,
        )


def _match_dotenv_file(
    subscription_id: str,
    path: Path,
    *,
    skip_azure_bindings: bool = False,
) -> tuple[MatchReport, Path]:
    source = normalize_dotenv_file_path(path)
    _warn_for_broad_dotenv_permissions(source)
    with open_managed_plaintext(source) as stream:
        report = _match_dotenv(subscription_id, stream, skip_azure_bindings=skip_azure_bindings)
    return attach_dotenv_file_bindings(report, source), source


def _warn_for_broad_dotenv_permissions(path: Path) -> None:
    """Emit one local notice without turning file permissions into plan state."""

    if managed_plaintext_permissions_are_broad(path):
        _render_dotenv_permissions_warning()


def _match_sops_dotenv_file(
    subscription_id: str,
    path: Path,
    *,
    skip_azure_bindings: bool = False,
) -> tuple[MatchReport, Path]:
    source = normalize_sops_dotenv_file_path(path)
    content = ""
    stream: _EphemeralStringIO | None = None
    try:
        content = SopsDotenvFileProvider().read_source(source)
        stream = _EphemeralStringIO(content, newline="")
        content = ""
        report = _match_dotenv(
            subscription_id,
            stream,
            skip_azure_bindings=skip_azure_bindings,
        )
        return attach_sops_dotenv_file_bindings(report, source), source
    finally:
        content = ""
        if stream is not None and not stream.closed:
            stream.seek(0)
            stream.truncate(0)
            stream.close()


def _inspect_selection(
    subscription_id: str,
    inventory: Inventory,
    selections: tuple[KeySlotSelection, ...],
    *,
    skip_azure_bindings: bool = False,
) -> SelectionReport:
    message = (
        "Inspecting the selected Azure key slots..."
        if skip_azure_bindings
        else "Inspecting selected Azure key slots and credential bindings..."
    )
    with _terminal_status(message):
        return _compose_inspect_selection(
            subscription_id,
            inventory,
            selections,
            _auth_store(),
            skip_azure_bindings=skip_azure_bindings,
        )


def _execution_service(subscription_id: str) -> ExecutionService:
    return _compose_execution_service(subscription_id, _auth_store())


def _export_service(subscription_id: str) -> DotenvExportService:
    return _compose_export_service(subscription_id, _auth_store())


def _sops_export_service() -> SopsDotenvExportService:
    return SopsDotenvExportService(SopsCli())


def _validate_subscription(value: str) -> str:
    try:
        parsed = UUID(value)
    except ValueError as error:
        raise typer.BadParameter("must be an Azure subscription UUID") from error
    if parsed.int == 0:
        raise typer.BadParameter("must not be the all-zero UUID")
    return str(parsed)


def _fail(message: str) -> NoReturn:
    typer.secho(f"Error: {message}", fg=typer.colors.RED, err=True)
    raise typer.Exit(code=1)


def _paths_refer_to_same_file(first: Path, second: Path) -> bool:
    first_absolute = Path(os.path.abspath(first.expanduser()))
    second_absolute = Path(os.path.abspath(second.expanduser()))
    if os.path.normcase(str(first_absolute)) == os.path.normcase(str(second_absolute)):
        return True
    try:
        return first_absolute.samefile(second_absolute)
    except OSError:
        return False


def _authentication_failure(error: BaseException) -> NoReturn:
    if isinstance(error, AuthenticationRequiredError):
        _fail("the saved session requires interaction; run 'azurator login' again")
    if isinstance(error, CredentialUnavailableError):
        _fail("the selected authentication method is unavailable; run 'azurator login'")
    if isinstance(error, ClientAuthenticationError):
        _fail("Microsoft Entra authentication failed; run 'azurator login' and check tenant access")
    if isinstance(error, AuthError):
        _fail(str(error))
    _fail("authentication failed; response details were suppressed")


def _resolve_subscription(value: str | None) -> SubscriptionSelection:
    if value is not None:
        subscription_id = _validate_subscription(value)
        try:
            config = _auth_store().load()
        except AuthError as error:
            _authentication_failure(error)
        if config is not None and config.subscription_id == subscription_id:
            return SubscriptionSelection(
                subscription_id,
                config.subscription_name,
                config.tenant_id,
            )
        return SubscriptionSelection(subscription_id)
    try:
        return _authenticator().resolve_subscription()
    except AuthError as error:
        _authentication_failure(error)


def _resolve_plan_subscription(value: str | None) -> SubscriptionSelection:
    subscription_id = _validate_subscription(value) if value is not None else None
    try:
        return _authenticator().resolve_subscription(subscription_id)
    except AuthError as error:
        _authentication_failure(error)


@app.command()
def login(
    method: AuthMethod = typer.Option(
        AuthMethod.azure_cli,
        "--method",
        case_sensitive=False,
        help="Authentication host: azure-cli, browser, device-code, or environment.",
    ),
    tenant: str | None = typer.Option(None, "--tenant", help="Optional Microsoft Entra tenant ID or domain."),
    subscription: str | None = typer.Option(
        None,
        "--subscription",
        help="Optional subscription UUID used to verify the selected Azure CLI account.",
    ),
    client_id: str | None = typer.Option(
        None,
        "--client-id",
        envvar="AZURATOR_CLIENT_ID",
        help="Public-client application ID required for native browser/device login.",
    ),
    use_device_code: bool = typer.Option(
        False,
        "--use-device-code",
        help="Ask Azure CLI to use its device-code flow instead of opening a browser.",
    ),
    redirect_uri: str = typer.Option(
        "http://localhost",
        "--redirect-uri",
        help="Registered localhost redirect URI for native browser login.",
    ),
) -> None:
    """Sign in and remember the authentication method without storing passwords."""

    selected_subscription = _validate_subscription(subscription) if subscription else None
    try:
        result = _authenticator().login(
            method,
            tenant_id=tenant,
            subscription_id=selected_subscription,
            client_id=client_id,
            use_device_code=use_device_code,
            redirect_uri=redirect_uri,
        )
    except (AuthError, AuthenticationRequiredError, ClientAuthenticationError, CredentialUnavailableError) as error:
        _authentication_failure(error)

    tenant_suffix = f" in tenant {result.tenant_id}" if result.tenant_id else ""
    subscription_suffix = (
        f" for subscription {_subscription_label(result.subscription_id, result.subscription_name)}"
        if result.subscription_id
        else ""
    )
    typer.echo(f"Authenticated with {result.method.value}{tenant_suffix}{subscription_suffix}.")


@auth_app.command("status")
def auth_status(
    subscription: str | None = typer.Option(
        None,
        "--subscription",
        help="Azure subscription UUID override; defaults to the selection pinned at login.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Print the verified authentication status as JSON.",
    ),
) -> None:
    """Verify that the active adapter can acquire an Azure management token."""

    selected_subscription = _resolve_subscription(subscription)
    try:
        method = _authenticator().verify(selected_subscription.subscription_id)
    except (AuthError, AuthenticationRequiredError, ClientAuthenticationError, CredentialUnavailableError) as error:
        _authentication_failure(error)
    if json_output:
        typer.echo(
            json.dumps(
                {
                    "schema_version": "1",
                    "method": method.value,
                    "subscription_id": selected_subscription.subscription_id,
                    "subscription_name": selected_subscription.name,
                    "tenant_id": selected_subscription.tenant_id,
                    "ready": True,
                },
                indent=2,
            )
        )
        return
    typer.echo(
        f"Authentication is ready via {method.value} for subscription "
        f"{_subscription_label(selected_subscription.subscription_id, selected_subscription.name)}."
    )


@auth_app.command("clear")
def auth_clear() -> None:
    """Forget Azurator's saved adapter and subscription selection."""

    try:
        removed = _auth_store().clear()
    except AuthError as error:
        _authentication_failure(error)
    if removed:
        typer.echo("Cleared Azurator's saved authentication selection. Azure CLI sign-in was not changed.")
    else:
        typer.echo("No saved Azurator authentication selection was present. Azure CLI sign-in was not changed.")


@operation_app.command("list")
def list_operations(
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Print the secret-free retained-operation summary as JSON.",
    ),
) -> None:
    """List failed, interrupted, or cleanup-pending local rotation operations."""

    try:
        report = OperationCatalog(_operation_root()).list()
    except OperationCatalogError as error:
        _fail(str(error))
    if json_output:
        typer.echo(json.dumps(report.model_dump(mode="json"), indent=2))
        return
    _render_operation_list(report)


@operation_app.command("show")
def show_operation(
    operation_id: UUID = typer.Argument(
        ...,
        metavar="OPERATION_ID",
        help="Exact retained rotation-operation UUID.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Print the secret-free retained-operation detail as JSON.",
    ),
) -> None:
    """Show one local recovery operation without contacting Azure."""

    try:
        summary = OperationCatalog(_operation_root()).show(operation_id)
    except OperationCatalogError as error:
        _fail(str(error))
    if json_output:
        typer.echo(json.dumps(summary.model_dump(mode="json"), indent=2))
        return
    _render_operation_show(summary)


@app.command("list")
def list_supported_types(
    key_resources: bool = typer.Option(
        False,
        "--key-resources",
        help="Show only supported Azure key-resource types.",
    ),
    bindings: bool = typer.Option(
        False,
        "--bindings",
        help="Show only supported credential-binding types.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Print the selected support catalog as JSON instead of tables.",
    ),
) -> None:
    """List key-resource and credential-binding types supported by this build."""

    catalog = builtin_support_catalog()
    show_key_resources = key_resources or not bindings
    show_bindings = bindings or not key_resources
    if json_output:
        selected_catalog = catalog.model_copy(
            update={
                "key_resources": catalog.key_resources if show_key_resources else (),
                "credential_bindings": catalog.credential_bindings if show_bindings else (),
            }
        )
        typer.echo(json.dumps(selected_catalog.model_dump(mode="json"), indent=2))
        return
    _render_support_catalog(
        catalog,
        show_key_resources=show_key_resources,
        show_bindings=show_bindings,
    )


@app.command()
def discover(
    subscription: str | None = typer.Option(
        None,
        "--subscription",
        help="Azure subscription UUID override; defaults to the selection pinned at login.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Print the complete inventory as JSON instead of a table.",
    ),
    out: Path | None = typer.Option(None, "--out", help="Write the complete JSON inventory to a private file."),
) -> None:
    """Enumerate supported Azure key resources using metadata-only operations."""

    selected_subscription = _resolve_subscription(subscription)

    try:
        inventory = _discover_inventory(selected_subscription.subscription_id).model_copy(
            update={"subscription_name": selected_subscription.name}
        )
    except (
        AuthConfigurationError,
        AuthenticationRequiredError,
        ClientAuthenticationError,
        CredentialUnavailableError,
    ) as error:
        _authentication_failure(error)
    except HttpResponseError:
        _fail("Azure discovery failed; response details were suppressed")

    if json_output or out is not None:
        payload = inventory.model_dump_json(indent=2) + "\n"
        if out is None:
            typer.echo(payload, nl=False)
        else:
            try:
                write_private_text(out, payload)
            except (OSError, UnsafeOutputPathError):
                _fail("could not safely write the inventory output")
            typer.echo(f"Wrote metadata-only inventory to {out}.")
        return

    _render_inventory(inventory)


@app.command("match")
def match_keys(
    subscription: str | None = typer.Option(
        None,
        "--subscription",
        help="Azure subscription UUID override; defaults to the selection pinned at login.",
    ),
    stdin_input: bool = typer.Option(
        False,
        "--stdin",
        help="Read dotenv assignments from standard input.",
    ),
    env_file: Path | None = typer.Option(
        None,
        "--env-file",
        help="Read one existing plaintext dotenv file and report the assignments a file plan would manage.",
    ),
    sops_file: Path | None = typer.Option(
        None,
        "--sops-file",
        help="Decrypt one SOPS-encrypted dotenv file in memory and report its managed assignments.",
    ),
    skip_azure_bindings: bool = typer.Option(
        False,
        "--skip-azure-bindings",
        help=(
            "Skip all Azure credential-binding inspection. Skipped bindings cannot be included or updated; "
            "explicit local files remain included."
        ),
    ),
    matrix: bool = typer.Option(
        False,
        "--matrix",
        help="Show input selectors by key resource instead of the sparse match table.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Print the complete secret-free match report as JSON.",
    ),
) -> None:
    """Compare stdin, plaintext-file, or SOPS-file dotenv values with supported Azure key slots."""

    source_count = int(stdin_input) + int(env_file is not None) + int(sops_file is not None)
    if source_count > 1:
        _fail("--stdin, --env-file, and --sops-file cannot be used together")
    if source_count == 0:
        _fail("select one input mode: --stdin, --env-file, or --sops-file")
    if matrix and json_output:
        _fail("--matrix and --json cannot be used together")
    if stdin_input and sys.stdin.isatty():
        _fail("refusing to read raw values from an interactive terminal; pipe or redirect dotenv input")

    selected_subscription = _resolve_subscription(subscription)
    try:
        if env_file is not None:
            report, _ = _match_dotenv_file(
                selected_subscription.subscription_id,
                env_file,
                skip_azure_bindings=skip_azure_bindings,
            )
        elif sops_file is not None:
            report, _ = _match_sops_dotenv_file(
                selected_subscription.subscription_id,
                sops_file,
                skip_azure_bindings=skip_azure_bindings,
            )
        else:
            report = _match_dotenv(
                selected_subscription.subscription_id,
                sys.stdin,
                skip_azure_bindings=skip_azure_bindings,
            )
        report = report.model_copy(update={"subscription_name": selected_subscription.name})
    except SecretInputError as error:
        _fail(str(error))
    except DotenvFileContractError as error:
        _fail(str(error))
    except (SopsDotenvFileContractError, SopsError) as error:
        _fail(str(error))
    except (OSError, UnicodeError, UnsafeInputPathError):
        if sops_file is not None:
            _fail("the SOPS dotenv file is missing, unsafe, invalid, or could not be decrypted")
        _fail("the dotenv input file is missing, unsafe, or invalid")
    except MatchingError:
        _fail("matching stopped because a supported integration returned an unexpected result")
    except (
        AuthConfigurationError,
        AuthenticationRequiredError,
        ClientAuthenticationError,
        CredentialUnavailableError,
    ) as error:
        _authentication_failure(error)
    except HttpResponseError:
        _fail("Azure matching failed; response details were suppressed")

    if json_output:
        typer.echo(report.model_dump_json(indent=2))
        return
    if matrix:
        _render_match_matrix(report)
        return
    _render_matches(report)


def _parse_selection_numbers(value: str, option_count: int) -> tuple[int, ...]:
    parts = [part.strip() for part in value.split(",")]
    if not parts or any(not part or not part.isdecimal() for part in parts):
        raise ValueError("enter one or more comma-separated numbers")
    selected: list[int] = []
    for part in parts:
        number = int(part)
        if number < 1 or number > option_count:
            raise ValueError(f"selection numbers must be between 1 and {option_count}")
        index = number - 1
        if index not in selected:
            selected.append(index)
    return tuple(selected)


def _parse_key_slot_selectors(
    values: Sequence[str],
    subscription_id: str,
) -> tuple[KeySlotSelection, ...]:
    """Parse exact top-level ARM resource IDs with one provider-declared slot."""

    selections: list[KeySlotSelection] = []
    identities: set[tuple[str, str]] = set()
    for value in values:
        if value != value.strip() or value.count("#") != 1:
            raise DirectSelectionError("--select values must use the exact form ARM_RESOURCE_ID#SLOT")
        resource_id, key_slot = value.rsplit("#", 1)
        if not resource_id or not key_slot or any(character.isspace() for character in key_slot):
            raise DirectSelectionError("--select values must use the exact form ARM_RESOURCE_ID#SLOT")
        if "?" in resource_id:
            raise DirectSelectionError("--select requires a complete top-level Azure Resource Manager ID")

        try:
            parsed = parse_resource_id(resource_id)
        except (TypeError, ValueError):
            raise DirectSelectionError("--select requires a complete top-level Azure Resource Manager ID") from None
        fields = {
            "subscription": parsed.get("subscription"),
            "resource_group": parsed.get("resource_group"),
            "namespace": parsed.get("namespace"),
            "type": parsed.get("type"),
            "name": parsed.get("name"),
        }
        if not all(isinstance(item, str) and item for item in fields.values()) or parsed.get("children") not in {
            None,
            "",
        }:
            raise DirectSelectionError("--select requires a complete top-level Azure Resource Manager ID")
        subscription = fields["subscription"]
        assert isinstance(subscription, str)
        try:
            selector_subscription = str(UUID(subscription))
        except ValueError:
            raise DirectSelectionError("--select contains an invalid Azure subscription ID") from None
        if selector_subscription.casefold() != subscription_id.casefold():
            raise DirectSelectionError("a --select resource belongs to a different Azure subscription")

        canonical_id = (
            f"/subscriptions/{fields['subscription']}"
            f"/resourceGroups/{fields['resource_group']}"
            f"/providers/{fields['namespace']}/{fields['type']}/{fields['name']}"
        )
        if canonical_id.casefold() != resource_id.casefold():
            raise DirectSelectionError("--select requires a complete top-level Azure Resource Manager ID")

        identity = (resource_id.casefold(), key_slot)
        if identity in identities:
            raise DirectSelectionError("the same key resource and slot were selected more than once")
        identities.add(identity)
        selections.append(KeySlotSelection(resource_id=resource_id, key_slot=key_slot))

    if not selections:
        raise DirectSelectionError("provide at least one --select ARM_RESOURCE_ID#SLOT")
    return tuple(selections)


def _interactive_terminal_available() -> bool:
    return sys.stdin.isatty() and sys.stderr.isatty()


def _key_slot_options(
    inventory: Inventory,
    *,
    require_rotatable: bool,
) -> tuple[tuple[DiscoveredResource, KeySlot], ...]:
    options: list[tuple[DiscoveredResource, KeySlot]] = []
    for resource in inventory.resources:
        if (
            resource.key_authentication is not KeyAuthentication.enabled
            or len(resource.key_slots) != 2
            or any(not slot.values_retrievable for slot in resource.key_slots)
        ):
            continue
        options.extend((resource, slot) for slot in resource.key_slots if not require_rotatable or slot.rotatable)
    return tuple(options)


def _canonicalize_key_slot_selections(
    inventory: Inventory,
    selections: Sequence[KeySlotSelection],
    *,
    require_rotatable: bool,
) -> tuple[KeySlotSelection, ...]:
    """Resolve explicit selections only against slots displayed by this inventory."""

    resources_by_id: dict[str, DiscoveredResource] = {}
    for resource in inventory.resources:
        identity = resource.resource_id.casefold()
        if identity in resources_by_id:
            raise DirectSelectionError("Azure discovery returned conflicting resource identities")
        resources_by_id[identity] = resource

    options = {
        (resource.resource_id.casefold(), slot.name): KeySlotSelection(
            resource_id=resource.resource_id,
            key_slot=slot.name,
        )
        for resource, slot in _key_slot_options(inventory, require_rotatable=require_rotatable)
    }
    canonical: list[KeySlotSelection] = []
    identities: set[tuple[str, str]] = set()
    for selection in selections:
        resource_identity = selection.resource_id.casefold()
        if resource_identity not in resources_by_id:
            raise DirectSelectionError(
                "a --select resource was not found among the supported key resources in this subscription"
            )
        identity = (resource_identity, selection.key_slot)
        resolved = options.get(identity)
        if resolved is None:
            qualifier = "rotatable" if require_rotatable else "retrievable"
            raise DirectSelectionError(f"a --select slot is not a supported {qualifier} slot for that resource")
        if identity in identities:
            raise DirectSelectionError("the same key resource and slot were selected more than once")
        identities.add(identity)
        canonical.append(resolved)
    return tuple(canonical)


def _prompt_key_slot_selection(
    inventory: Inventory,
    *,
    heading: str = "Select Azure key slots for rotation",
    noninteractive_hint: str = "use --select, --stdin, --env-file, or --sops-file instead",
    require_rotatable: bool = True,
) -> tuple[KeySlotSelection, ...]:
    """Render a metadata-only picker on the terminal and return explicit identities."""

    if not _interactive_terminal_available():
        _fail(f"interactive key selection requires a terminal; {noninteractive_hint}")

    options = _key_slot_options(inventory, require_rotatable=require_rotatable)
    if not options:
        qualifier = "rotatable " if require_rotatable else "exportable "
        _fail(f"no {qualifier}key slots were found among supported key resources")

    console = Console(stderr=True)
    console.print(f"[bold]{escape(heading)}[/bold]")
    subscription = escape(_subscription_label(inventory.subscription_id, inventory.subscription_name))
    console.print(f"[dim]Subscription {subscription}[/dim]")
    console.print("[dim]This list contains metadata only; no key value is displayed.[/dim]")
    console.print()
    table = Table()
    table.add_column("#", justify="right")
    table.add_column("Key resource")
    table.add_column("Service")
    table.add_column("Region")
    table.add_column("Slot")
    for index, (resource, slot) in enumerate(options, start=1):
        table.add_row(
            str(index),
            escape(resource.name),
            escape(_service_label(resource.provider, resource.kind)),
            escape(resource.location or "—"),
            escape(slot.name),
        )
    console.print(table)

    while True:
        try:
            response = console.input("\n[bold]Selection[/bold] [dim](comma-separated numbers)[/dim]: ")
            indices = _parse_selection_numbers(response, len(options))
        except (EOFError, KeyboardInterrupt):
            _fail("interactive key selection was cancelled")
        except ValueError as error:
            console.print(f"[red]Invalid selection:[/red] {escape(str(error))}")
            continue
        return tuple(
            KeySlotSelection(resource_id=options[index][0].resource_id, key_slot=options[index][1].name)
            for index in indices
        )


@app.command("export")
def export_keys(
    out: Path | None = typer.Option(
        None,
        "--out",
        help="Exclusively create this private plaintext dotenv file.",
    ),
    sops_out: Path | None = typer.Option(
        None,
        "--sops-out",
        help="Exclusively create this private SOPS-encrypted dotenv file.",
    ),
    subscription: str | None = typer.Option(
        None,
        "--subscription",
        help="Azure subscription UUID override; defaults to the selection pinned at login.",
    ),
    all_slots: bool = typer.Option(
        False,
        "--all",
        help="Export every retrievable slot from supported key resources.",
    ),
    selectors: list[str] | None = typer.Option(
        None,
        "--select",
        help="Select one exact ARM_RESOURCE_ID#SLOT; repeat for multiple slots.",
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Accept the displayed export intent without prompting.",
    ),
) -> None:
    """Write selected Azure account keys to one new plaintext or SOPS dotenv file."""

    selector_values = tuple(selectors or ())
    if out is not None and sops_out is not None:
        _fail("--out and --sops-out cannot be used together")
    output_option = sops_out if sops_out is not None else out
    if output_option is None:
        _fail("select one export destination: --out for plaintext or --sops-out for SOPS encryption")
    encrypted = sops_out is not None
    if all_slots and selector_values:
        _fail("--all and --select cannot be used together")
    if not all_slots and not selector_values and not _interactive_terminal_available():
        _fail("interactive key selection requires a terminal; use --select or --all instead")

    try:
        destination = resolve_parent_path(output_option)
    except OSError:
        _fail("the dotenv export destination has a missing or unsafe parent directory")

    try:
        destination.lstat()
    except FileNotFoundError:
        pass
    except OSError:
        _fail("the dotenv export destination could not be inspected safely")
    else:
        _fail("refusing to replace an existing dotenv export destination")

    selected_subscription = _resolve_subscription(subscription)
    try:
        direct_selections = (
            _parse_key_slot_selectors(selector_values, selected_subscription.subscription_id)
            if selector_values
            else None
        )
    except DirectSelectionError as error:
        _fail(str(error))
    try:
        inventory = _discover_inventory(selected_subscription.subscription_id).model_copy(
            update={"subscription_name": selected_subscription.name}
        )
    except (
        AuthConfigurationError,
        AuthenticationRequiredError,
        ClientAuthenticationError,
        CredentialUnavailableError,
    ) as error:
        _authentication_failure(error)
    except HttpResponseError:
        _fail("Azure export discovery failed; response details were suppressed")

    if all_slots:
        options = _key_slot_options(inventory, require_rotatable=False)
        if not options:
            _fail("no exportable key slots were found among supported key resources")
        selections = tuple(
            KeySlotSelection(resource_id=resource.resource_id, key_slot=slot.name) for resource, slot in options
        )
    elif direct_selections is not None:
        try:
            selections = _canonicalize_key_slot_selections(
                inventory,
                direct_selections,
                require_rotatable=False,
            )
        except DirectSelectionError as error:
            _fail(str(error))
    else:
        selections = _prompt_key_slot_selection(
            inventory,
            heading="Select Azure key slots to export",
            noninteractive_hint="use --all for an explicit complete export",
            require_rotatable=False,
        )

    try:
        assignments = build_dotenv_export_assignments(inventory, selections)
    except ExportError as error:
        _fail(str(error))

    _render_export_intent(assignments, destination, selected_subscription, encrypted=encrypted)
    confirmation = (
        "Encrypt these Azure keys into the displayed SOPS dotenv file?"
        if encrypted
        else "Write these Azure keys to the displayed plaintext dotenv file?"
    )
    if not yes and not _confirm_mutation(confirmation):
        typer.echo("Export cancelled; no key values were retrieved and no file was written.")
        return

    payload = ""
    ciphertext = bytearray()
    try:
        with _terminal_status(
            "Retrieving and encrypting the selected Azure keys..."
            if encrypted
            else "Retrieving the selected Azure keys..."
        ):
            sops_export = _sops_export_service() if encrypted else None
            if sops_export is not None:
                sops_export.validate_environment()
            payload = _export_service(selected_subscription.subscription_id).render(
                selected_subscription.subscription_id,
                assignments,
            )
            if sops_export is None:
                create_private_text(destination, payload)
            else:
                ciphertext = sops_export.encrypt(payload, destination)
                create_private_bytes(destination, ciphertext)
    except (
        AuthConfigurationError,
        AuthenticationRequiredError,
        ClientAuthenticationError,
        CredentialUnavailableError,
    ) as error:
        _authentication_failure(error)
    except ProviderOperationError:
        _fail("Azure key export failed while reading a selected key resource; no dotenv file was written")
    except (HttpResponseError, ServiceRequestError, ServiceResponseError):
        _fail("Azure key export failed; response details were suppressed and no dotenv file was written")
    except SopsError:
        _fail("SOPS could not create and verify the encrypted dotenv export; no file was written")
    except ExportError as error:
        _fail(f"{error}; no dotenv file was written")
    except PrivateFileExistsError:
        _fail("the dotenv export destination appeared concurrently; no file was replaced")
    except (OSError, UnicodeError, UnsafeOutputPathError):
        _fail("the dotenv export could not be written safely")
    finally:
        payload = ""
        ciphertext[:] = b"\x00" * len(ciphertext)

    count = len(assignments)
    noun = "key slot" if count == 1 else "key slots"
    if encrypted:
        typer.echo(f"Exported {count} Azure {noun} to private SOPS-encrypted dotenv file {destination}.")
        typer.echo("Key values were encrypted before the file was written and were not printed.")
    else:
        typer.echo(f"Exported {count} Azure {noun} to private plaintext dotenv file {destination}.")
        typer.echo("Key values were written only to that file and were not printed.")


def _rotation_planning_workflow() -> RotationPlanningWorkflow:
    """Bind command adapters to command-independent rotation planning."""

    return RotationPlanningWorkflow(
        discover_inventory=_discover_inventory,
        match_dotenv=_match_dotenv,
        match_dotenv_file=_match_dotenv_file,
        match_sops_dotenv_file=_match_sops_dotenv_file,
        inspect_selection=_inspect_selection,
        prompt_selection=_prompt_key_slot_selection,
        canonicalize_selection=_canonicalize_key_slot_selections,
    )


def _build_rotation_plan(
    selected_subscription: SubscriptionSelection,
    *,
    stdin_input: bool,
    env_file: Path | None,
    sops_file: Path | None,
    direct_selections: tuple[KeySlotSelection, ...] | None,
    skip_azure_bindings: bool,
    stream: TextIO,
) -> RotationPlan:
    return _rotation_planning_workflow().build(
        selected_subscription,
        stdin_input=stdin_input,
        env_file=env_file,
        sops_file=sops_file,
        direct_selections=direct_selections,
        skip_azure_bindings=skip_azure_bindings,
        stream=stream,
    )


@app.command()
def plan(
    subscription: str | None = typer.Option(
        None,
        "--subscription",
        help="Azure subscription UUID override; defaults to the selection pinned at login.",
    ),
    stdin_input: bool = typer.Option(
        False,
        "--stdin",
        help="Read dotenv assignments from standard input.",
    ),
    env_file: Path | None = typer.Option(
        None,
        "--env-file",
        help="Plan rotation and managed updates for one existing plaintext dotenv file.",
    ),
    sops_file: Path | None = typer.Option(
        None,
        "--sops-file",
        help="Plan rotation and managed updates for one SOPS-encrypted dotenv file.",
    ),
    selectors: list[str] | None = typer.Option(
        None,
        "--select",
        help="Select one exact ARM_RESOURCE_ID#SLOT; repeat for multiple slots.",
    ),
    skip_azure_bindings: bool = typer.Option(
        False,
        "--skip-azure-bindings",
        help=(
            "Skip all Azure credential-binding inspection. Skipped bindings cannot be included or updated; "
            "explicit local files remain included."
        ),
    ),
    out: Path | None = typer.Option(
        None,
        "--out",
        help="Write the generated secret-free JSON plan to this private file.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Print the complete secret-free JSON plan instead of the readable preview.",
    ),
) -> None:
    """Plan from exact slots, stdin dotenv, or a managed plaintext or SOPS dotenv file."""

    selector_values = tuple(selectors or ())
    if json_output and out is not None:
        _fail("--json and --out cannot be used together")
    source_count = (
        int(stdin_input) + int(env_file is not None) + int(sops_file is not None) + int(bool(selector_values))
    )
    if source_count > 1:
        _fail("--select, --stdin, --env-file, and --sops-file cannot be used together")
    managed_file = env_file or sops_file
    if managed_file is not None and out is not None and _paths_refer_to_same_file(managed_file, out):
        _fail("--out must not refer to the managed input file")
    if stdin_input and sys.stdin.isatty():
        _fail("refusing to read raw values from an interactive terminal; pipe or redirect dotenv input")
    if source_count == 0 and not _interactive_terminal_available():
        _fail("interactive key selection requires a terminal; use --select, --stdin, --env-file, or --sops-file")

    selected_subscription = _resolve_plan_subscription(subscription)
    if not selected_subscription.tenant_id:
        _fail("the tenant ID for the selected subscription is unavailable; run 'azurator login' again")

    try:
        direct_selections = (
            _parse_key_slot_selectors(selector_values, selected_subscription.subscription_id)
            if selector_values
            else None
        )
        rotation_plan = _build_rotation_plan(
            selected_subscription,
            stdin_input=stdin_input,
            env_file=env_file,
            sops_file=sops_file,
            direct_selections=direct_selections,
            skip_azure_bindings=skip_azure_bindings,
            stream=sys.stdin,
        )
    except DirectSelectionError as error:
        _fail(str(error))
    except SecretInputError as error:
        _fail(str(error))
    except DotenvFileContractError as error:
        _fail(str(error))
    except (SopsDotenvFileContractError, SopsError) as error:
        _fail(str(error))
    except (OSError, UnicodeError, UnsafeInputPathError):
        if sops_file is not None:
            _fail("the SOPS dotenv file is missing, unsafe, invalid, or could not be decrypted")
        _fail("the dotenv input file is missing, unsafe, or invalid")
    except MatchingError:
        _fail("planning stopped because a supported integration returned an unexpected result")
    except PlanningError as error:
        _fail(str(error))
    except (
        AuthConfigurationError,
        AuthenticationRequiredError,
        ClientAuthenticationError,
        CredentialUnavailableError,
    ) as error:
        _authentication_failure(error)
    except HttpResponseError:
        _fail("Azure planning failed; response details were suppressed")

    payload = _rotation_plan_payload(rotation_plan)
    if json_output:
        typer.echo(payload, nl=False)
        return
    if out is not None:
        if (
            rotation_plan.source_format in {PlanSource.dotenv_file, PlanSource.sops_dotenv_file}
            and rotation_plan.source_path is not None
            and _paths_refer_to_same_file(Path(rotation_plan.source_path), out)
        ):
            _fail("--out must not refer to the managed input file")
        try:
            write_private_text(out, payload)
        except (OSError, UnsafeOutputPathError):
            _fail("could not safely write the rotation plan")

    _render_plan(rotation_plan, out.expanduser() if out is not None else None)


def _rebuild_plan(
    rotation_plan: RotationPlan,
    selected_subscription: SubscriptionSelection,
    stream: TextIO,
) -> RotationPlan:
    return _rotation_planning_workflow().rebuild(rotation_plan, selected_subscription, stream)


@app.command("rotate")
def rotate_keys(
    plan_file: Path | None = typer.Option(
        None,
        "--plan",
        help="Rotate from a private JSON plan previously written by 'azurator plan --out'.",
    ),
    subscription: str | None = typer.Option(
        None,
        "--subscription",
        help="Subscription override for a generated plan; cannot replace a saved plan or operation scope.",
    ),
    env_file: Path | None = typer.Option(
        None,
        "--env-file",
        help="Match, plan, and rotate one existing plaintext dotenv file without saving a plan.",
    ),
    sops_file: Path | None = typer.Option(
        None,
        "--sops-file",
        help="Match, plan, and rotate one SOPS-encrypted dotenv file without saving a plan.",
    ),
    selectors: list[str] | None = typer.Option(
        None,
        "--select",
        help="Select one exact ARM_RESOURCE_ID#SLOT; repeat for multiple slots.",
    ),
    skip_azure_bindings: bool = typer.Option(
        False,
        "--skip-azure-bindings",
        help=(
            "Skip all Azure credential-binding inspection. Skipped bindings cannot be included or updated; "
            "explicit local files remain included."
        ),
    ),
    stdin_input: bool = typer.Option(
        False,
        "--stdin",
        help="Repeat dotenv matching for a saved or pristine-resume stdin-sourced plan.",
    ),
    resume: UUID | None = typer.Option(
        None,
        "--resume",
        help="Resume one retained private operation by its UUID.",
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Accept the validated executable plan and displayed warnings without prompting.",
    ),
) -> None:
    """Plan and rotate selected keys, or resume one interrupted operation."""

    is_resume = resume is not None
    uses_shortcut = not is_resume and plan_file is None
    selector_values = tuple(selectors or ())
    if is_resume and (
        any(value is not None for value in (plan_file, subscription, env_file, sops_file))
        or selector_values
        or skip_azure_bindings
    ):
        _fail(
            "--resume already contains its plan, scope, and binding-inspection choice. "
            "Do not combine it with --plan, --subscription, --env-file, --sops-file, --select, "
            "or --skip-azure-bindings"
        )
    if not is_resume and plan_file is not None and (env_file is not None or sops_file is not None):
        _fail("--plan and managed-file shortcuts are separate rotation modes")
    if not is_resume and plan_file is not None and selector_values:
        _fail("--plan already contains its exact selection and cannot be combined with --select")
    if not is_resume and plan_file is not None and subscription is not None:
        _fail("--subscription cannot override the scope recorded in --plan")
    if not is_resume and plan_file is not None and skip_azure_bindings:
        _fail("--plan already records whether Azure credential bindings were inspected")
    shortcut_source_count = int(env_file is not None) + int(sops_file is not None) + int(bool(selector_values))
    if shortcut_source_count > 1:
        _fail("--env-file, --sops-file, and --select are separate rotation modes")
    if shortcut_source_count and stdin_input:
        _fail("--stdin cannot be combined with --env-file, --sops-file, or --select")
    if uses_shortcut and stdin_input:
        _fail("streamed direct rotation is not implemented; generate a plan with --stdin first")
    if uses_shortcut and shortcut_source_count == 0 and not _interactive_terminal_available():
        _fail("interactive rotation requires a terminal; use --select, --env-file, --sops-file, or --plan")
    if stdin_input and sys.stdin.isatty():
        _fail("refusing to read raw values from an interactive terminal; pipe or redirect dotenv input")

    shortcut_fresh_plan: RotationPlan | None = None
    operation_snapshot: OperationState | None = None
    if resume is not None:
        operation_id = resume
        operation_path = _automatic_operation_path(operation_id)
        store = OperationStore(operation_path, expected_operation_id=operation_id)
        try:
            operation_snapshot = store.load()
        except OperationError as error:
            _fail(str(error))
        rotation_plan = operation_snapshot.plan
        selected_subscription = _resolve_plan_subscription(rotation_plan.subscription_id)
    elif plan_file is not None:
        rotation_plan = _load_rotation_plan(plan_file)
        selected_subscription = _resolve_plan_subscription(rotation_plan.subscription_id)
        operation_id = uuid4()
        operation_path = _automatic_operation_path(operation_id)
        store = OperationStore(operation_path, expected_operation_id=operation_id)
    else:
        selected_subscription = _resolve_plan_subscription(subscription)
        if not selected_subscription.tenant_id:
            _fail("the tenant ID for the selected subscription is unavailable; run 'azurator login' again")
        try:
            direct_selections = (
                _parse_key_slot_selectors(selector_values, selected_subscription.subscription_id)
                if selector_values
                else None
            )
            rotation_plan = _build_rotation_plan(
                selected_subscription,
                stdin_input=False,
                env_file=env_file,
                sops_file=sops_file,
                direct_selections=direct_selections,
                skip_azure_bindings=skip_azure_bindings,
                stream=sys.stdin,
            )
        except DirectSelectionError as error:
            _fail(str(error))
        except SecretInputError as error:
            _fail(str(error))
        except DotenvFileContractError as error:
            _fail(str(error))
        except (SopsDotenvFileContractError, SopsError) as error:
            _fail(str(error))
        except (OSError, UnicodeError, UnsafeInputPathError):
            if sops_file is not None:
                _fail("the SOPS dotenv file is missing, unsafe, invalid, or could not be decrypted")
            _fail("the dotenv input file is missing, unsafe, or invalid")
        except MatchingError:
            _fail("rotation planning stopped because a supported integration returned an unexpected result")
        except PlanningError as error:
            _fail(str(error))
        except (
            AuthConfigurationError,
            AuthenticationRequiredError,
            ClientAuthenticationError,
            CredentialUnavailableError,
        ) as error:
            _authentication_failure(error)
        except HttpResponseError:
            _fail("Azure rotation planning failed; response details were suppressed")
        operation_id = uuid4()
        operation_path = _automatic_operation_path(operation_id)
        store = OperationStore(operation_path, expected_operation_id=operation_id)
        shortcut_fresh_plan = rotation_plan

    uses_stdin_source = rotation_plan.source_format is PlanSource.dotenv_stdin
    uses_file_source = rotation_plan.source_format in {PlanSource.dotenv_file, PlanSource.sops_dotenv_file}
    if not is_resume and uses_stdin_source and not stdin_input:
        _fail("this stdin-sourced plan requires --stdin for fresh matching and drift checks")
    if not is_resume and not uses_stdin_source and stdin_input:
        _fail("managed-file and direct-selection plans do not accept stdin input")
    if not selected_subscription.tenant_id:
        _fail("the tenant ID for the plan subscription is unavailable; run 'azurator login' again")
    if selected_subscription.tenant_id.casefold() != rotation_plan.tenant_id.casefold():
        _fail("the active tenant does not match the generated plan")
    _rotation_plan_payload(rotation_plan)

    try:
        service = _execution_service(rotation_plan.subscription_id)
        if is_resume:
            if operation_snapshot is None:
                _fail("the requested rotation operation could not be loaded")
            result = _resume_rotation(
                service,
                store,
                selected_subscription,
                rotation_plan,
                operation_path,
                stdin_input=stdin_input,
                yes=yes,
                stream=sys.stdin,
            )
        else:
            result = _start_rotation(
                service,
                store,
                rotation_plan,
                selected_subscription,
                operation_id,
                operation_path,
                shortcut_fresh_plan=shortcut_fresh_plan,
                yes=yes,
                stream=sys.stdin,
            )
        if result is None:
            return
    except SecretInputError as error:
        _fail(str(error))
    except DotenvFileContractError as error:
        _fail(str(error))
    except (SopsDotenvFileContractError, SopsError) as error:
        _fail(str(error))
    except (OSError, UnicodeError, UnsafeInputPathError):
        if uses_file_source:
            _fail("the managed input file is missing, unsafe, or invalid")
        _fail("a required private input file could not be read safely")
    except MatchingError:
        _fail("rotation stopped because a supported integration returned an unexpected result")
    except PlanningError as error:
        _fail(str(error))
    except ExecutionError as error:
        _rotation_failure(error, operation_id, operation_path)
    except OperationError as error:
        _rotation_failure(error, operation_id, operation_path)
    except (
        AuthConfigurationError,
        AuthenticationRequiredError,
        ClientAuthenticationError,
        CredentialUnavailableError,
    ) as error:
        _authentication_failure(error)
    except HttpResponseError:
        _fail("Azure rotation failed; response details were suppressed")

    cleanup_error = _cleanup_completed_operation(store, result)
    _render_rotate_complete(rotation_plan, operation_path, cleanup_error=cleanup_error)


def _resume_rotation(
    service: ExecutionService,
    store: OperationStore,
    selected_subscription: SubscriptionSelection,
    rotation_plan: RotationPlan,
    operation_path: Path,
    *,
    stdin_input: bool,
    yes: bool,
    stream: TextIO,
) -> OperationState | None:
    operation_snapshot = service.validate_operation(store)
    pristine = not operation_snapshot.completed_steps and operation_snapshot.pending_step is None
    uses_stdin_source = rotation_plan.source_format is PlanSource.dotenv_stdin
    if pristine and uses_stdin_source and not stdin_input:
        _fail("this stdin-sourced operation has not started; resume requires --stdin")
    if pristine and not uses_stdin_source and stdin_input:
        _fail("managed-file and direct-selection plans do not accept stdin input")
    if not pristine and stdin_input:
        _fail("fresh stdin input is not accepted after a recorded Azure step has started")
    fresh_plan = _rebuild_plan(rotation_plan, selected_subscription, stream) if pristine else None
    current_operation = service.validate_resume(store, fresh_plan=fresh_plan)
    if current_operation.status is OperationStatus.completed:
        cleanup_error = _cleanup_completed_operation(store, current_operation)
        typer.echo(f"Operation {current_operation.operation_id} was already complete; no Azure call was made.")
        _render_operation_cleanup(operation_path, cleanup_error)
        return None
    if not pristine and rotation_plan.source_format is PlanSource.dotenv_file:
        if rotation_plan.source_path is None:
            _fail("the managed dotenv source path is unavailable")
        _warn_for_broad_dotenv_permissions(Path(rotation_plan.source_path))
    _render_rotate_intent(rotation_plan, operation_path, resume=True)
    if not yes and not _confirm_mutation("Resume this Azure mutation sequence?"):
        typer.echo("Cancelled; no additional Azure operation was performed.")
        return None
    return service.resume(
        store,
        fresh_plan=fresh_plan,
        progress=lambda step: _render_rotate_progress(rotation_plan, step),
    )


def _start_rotation(
    service: ExecutionService,
    store: OperationStore,
    rotation_plan: RotationPlan,
    selected_subscription: SubscriptionSelection,
    operation_id: UUID,
    operation_path: Path,
    *,
    shortcut_fresh_plan: RotationPlan | None,
    yes: bool,
    stream: TextIO,
) -> OperationState | None:
    service.validate_plan(rotation_plan)
    fresh_plan = shortcut_fresh_plan or _rebuild_plan(rotation_plan, selected_subscription, stream)
    service.validate_start(rotation_plan, fresh_plan)
    _render_rotate_intent(rotation_plan, operation_path, resume=False)
    if not yes and not _confirm_mutation("Rotate these selected keys? Azure key regeneration cannot be rolled back."):
        typer.echo("Cancelled; no Azure resource was changed.")
        return None
    _prepare_operation_root()
    return service.start(
        rotation_plan,
        fresh_plan,
        store,
        operation_id,
        progress=lambda step: _render_rotate_progress(rotation_plan, step),
    )


def _load_rotation_plan(path: Path) -> RotationPlan:
    try:
        payload = read_private_text(path, max_bytes=_MAX_PLAN_ARTIFACT_BYTES)
        return RotationPlan.model_validate_json(payload)
    except (OSError, UnicodeError, UnsafeInputPathError, ValidationError):
        _fail("the plan file is missing, unsafe, or invalid; use a private file written by 'azurator plan --out'")


def _operation_root() -> Path:
    return Path(os.path.abspath(user_state_path("azurator", appauthor=False).expanduser())) / "operations"


def _automatic_operation_path(operation_id: UUID) -> Path:
    return _operation_root() / str(operation_id) / "operation.json"


def _prepare_operation_root() -> None:
    try:
        app_state = ensure_private_directory(_operation_root().parent)
        ensure_private_directory(app_state / "operations")
    except (OSError, UnsafeOutputPathError):
        _fail("the private rotation-operation directory could not be prepared; no Azure resource was changed")


def _rotation_plan_payload(rotation_plan: RotationPlan) -> str:
    payload = rotation_plan.model_dump_json(indent=2) + "\n"
    if len(payload.encode("utf-8")) > _MAX_PLAN_ARTIFACT_BYTES:
        _fail(
            "the generated rotation plan exceeds the supported private artifact size limit; "
            "reduce the input or selection"
        )
    return payload


def _cleanup_completed_operation(store: OperationStore, operation: OperationState) -> OperationError | None:
    try:
        store.remove_completed(operation)
    except OperationError as error:
        return error
    return None


def _rotation_failure(error: BaseException, operation_id: UUID, operation_path: Path) -> NoReturn:
    try:
        operation = OperationStore(operation_path, expected_operation_id=operation_id).load()
        validate_operation_contract(operation)
    except (OperationError, OperationContractError):
        operation = None
    if operation is not None:
        resume_command = shlex.join(("azurator", "rotate", "--resume", str(operation_id)))
        _fail(f"{error} Recovery state remains in {operation_path}. Resume with `{resume_command}`.")
    try:
        operation_path.lstat()
    except OSError:
        pass
    else:
        _fail(
            f"{error} An operation entry remains in {operation_path}, but it is unsafe or invalid; "
            "Azurator will not suggest a resume command."
        )
    _fail(f"{error} No recovery state was written and no Azure resource was changed.")


def _confirm_mutation(prompt: str) -> bool:
    """Prompt on the controlling terminal because secret input occupies stdin."""

    if sys.stdin.isatty():
        return typer.confirm(prompt, default=False)
    try:
        if os.name == "nt":
            with open("CONOUT$", "w", encoding="utf-8", newline="") as output:
                output.write(f"{prompt} [y/N]: ")
                output.flush()
            with open("CONIN$", "r", encoding="utf-8", newline="") as input_stream:
                response = input_stream.readline()
        else:
            with open("/dev/tty", "r+", encoding="utf-8", newline="") as terminal:
                terminal.write(f"{prompt} [y/N]: ")
                terminal.flush()
                response = terminal.readline()
    except OSError:
        _fail("explicit confirmation requires a controlling terminal; review the plan and rerun with --yes")
    return response.strip().casefold() in {"y", "yes"}

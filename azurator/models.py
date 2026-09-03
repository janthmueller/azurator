"""Secret-free models shared by discovery providers and command adapters."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class AzuratorModel(BaseModel):
    """Strict immutable base model for persisted or rendered data."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class KeyAuthentication(str, Enum):
    """Whether Azure permits resource-key authentication for one resource."""

    enabled = "enabled"
    disabled = "disabled"


class BindingLocation(str, Enum):
    """Where one credential binding is stored."""

    azure = "azure"
    local = "local"


class AzureBindingInspection(str, Enum):
    """Whether automatic Azure credential-binding inspection was requested."""

    enabled = "enabled"
    skipped = "skipped"


class KeySlot(AzuratorModel):
    """A documented key slot without its value."""

    name: str = Field(min_length=1)
    values_retrievable: bool
    rotatable: bool


class WarningImpact(str, Enum):
    """How one structured warning affects safe planning."""

    advisory = "advisory"
    confirmation = "confirmation"
    blocking = "blocking"


class WarningCategory(str, Enum):
    """The supported concern represented by one structured warning."""

    coverage = "coverage"
    permission = "permission"
    contract = "contract"
    credential_binding = "credential-binding"
    persistence = "persistence"


class DiscoveryWarning(AzuratorModel):
    """A structured, secret-free warning suitable for JSON output."""

    code: str = Field(min_length=1, pattern=r"^[a-z0-9-]+$")
    message: str = Field(min_length=1)
    impact: WarningImpact
    category: WarningCategory
    provider: str | None = None
    resource_id: str | None = None


class ProviderInfo(AzuratorModel):
    """Versioned provider metadata included in every inventory."""

    name: str = Field(min_length=1)
    contract_version: str = Field(
        min_length=1,
        description="Azurator provider-contract version, independent of Azure REST and SDK versions.",
    )
    resource_types: tuple[str, ...]


class DiscoveredResource(AzuratorModel):
    """Metadata about one resource understood by a supported provider."""

    resource_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    resource_type: str = Field(min_length=1)
    location: str | None = None
    kind: str | None = None
    endpoint: str | None = None
    provider: str = Field(min_length=1)
    key_authentication: KeyAuthentication
    key_slots: tuple[KeySlot, ...]


class ProviderDiscovery(AzuratorModel):
    """The isolated result of one provider's metadata-only discovery pass."""

    resources: tuple[DiscoveredResource, ...] = ()
    warnings: tuple[DiscoveryWarning, ...] = ()


class CandidateInspectionStatus(str, Enum):
    """Whether a supported provider compared a resource's declared key slots."""

    compared = "compared"
    unavailable = "unavailable"


class CandidateInspection(AzuratorModel):
    """Secret-free outcome of one provider key-retrieval operation."""

    resource_id: str = Field(min_length=1)
    status: CandidateInspectionStatus
    key_slots: tuple[str, ...] = ()


class ProviderCandidateResult(AzuratorModel):
    """Secret-free metadata returned after provider candidates were consumed."""

    inspections: tuple[CandidateInspection, ...] = ()
    warnings: tuple[DiscoveryWarning, ...] = ()


class BindingManagement(str, Enum):
    """How much of a discovered binding Azurator can safely manage."""

    observed_only = "observed-only"
    update_and_verify = "update-and-verify"


class SupportedKeyResource(AzuratorModel):
    """One key-resource type exposed by the built-in support catalog."""

    name: str = Field(min_length=1)
    resource_type: str = Field(min_length=1)
    key_slots: tuple[str, ...] = Field(min_length=1)
    operations: tuple[Literal["discover", "match", "export", "refresh", "rotate"], ...] = Field(min_length=1)
    contract_id: str = Field(min_length=1)
    contract_version: str = Field(min_length=1)


class SupportedCredentialBinding(AzuratorModel):
    """One credential-binding type exposed by the built-in support catalog."""

    name: str = Field(min_length=1)
    binding_type: str = Field(min_length=1)
    location: BindingLocation
    included_by: Literal["automatic", "--env-file", "--sops-file"]
    key_resource_types: tuple[str, ...] = Field(min_length=1)
    management: BindingManagement
    operations: tuple[Literal["inspect", "update", "verify"], ...] = Field(min_length=1)
    contract_id: str = Field(min_length=1)
    contract_version: str = Field(min_length=1)


class SupportCatalog(AzuratorModel):
    """Login-free description of key resources and bindings supported by this build."""

    schema_version: Literal["1"] = "1"
    key_resources: tuple[SupportedKeyResource, ...]
    credential_bindings: tuple[SupportedCredentialBinding, ...]


class BindingInspectionStatus(str, Enum):
    """Whether a binding provider inspected all of its discovered scopes."""

    inspected = "inspected"
    partial = "partial"
    unavailable = "unavailable"


class BindingInspection(AzuratorModel):
    """Secret-free inspection status for one key-bearing resource."""

    resource_id: str = Field(min_length=1)
    provider: str = Field(min_length=1)
    location: BindingLocation
    status: BindingInspectionStatus
    scopes_inspected: int = Field(ge=0)


class CredentialBinding(AzuratorModel):
    """A secret-free downstream configuration link to an Azure key slot."""

    binding_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    binding_type: str = Field(min_length=1)
    provider: str = Field(min_length=1)
    location: BindingLocation
    scope_id: str = Field(min_length=1)
    scope_name: str = Field(min_length=1)
    key_resource_id: str = Field(min_length=1)
    key_slot: str | None = None
    target: str | None = None
    selectors: tuple[str, ...]
    management: BindingManagement


class ProviderBindingResult(AzuratorModel):
    """Secret-free bindings returned by one binding provider."""

    inspections: tuple[BindingInspection, ...] = ()
    bindings: tuple[CredentialBinding, ...] = ()
    warnings: tuple[DiscoveryWarning, ...] = ()


class MatchResource(AzuratorModel):
    """Azure resource metadata required to understand a key match."""

    resource_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    resource_type: str = Field(min_length=1)
    location: str | None = None
    kind: str | None = None
    endpoint: str | None = None
    provider: str = Field(min_length=1)
    key_slots: tuple[KeySlot, ...]


class KeyMatch(AzuratorModel):
    """A secret-free link between an input selector and an Azure key slot."""

    input_selector: str = Field(min_length=1)
    resource_id: str = Field(min_length=1)
    key_slot: str = Field(min_length=1)


class KeyMapEntry(AzuratorModel):
    """One portable dotenv selector mapped to an exact Azure key slot."""

    selector: str = Field(min_length=1)
    key_resource_id: str = Field(min_length=1)
    key_slot: str = Field(min_length=1)


class DotenvKeyAssignment(AzuratorModel):
    """One resolved, secret-free Azure key slot to dotenv selector assignment."""

    resource: DiscoveredResource
    resource_group: str = Field(min_length=1)
    key_slot: str = Field(min_length=1)
    selector: str = Field(min_length=1)


class KeyMap(AzuratorModel):
    """A secret-free, reusable selector-to-Azure-key mapping artifact."""

    schema_version: Literal["1"] = "1"
    subscription_id: str = Field(min_length=1)
    mappings: tuple[KeyMapEntry, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def require_unique_selectors(self) -> KeyMap:
        """Keep every dotenv selector bound to exactly one artifact entry."""

        selectors: set[str] = set()
        for mapping in self.mappings:
            if mapping.selector in selectors:
                raise ValueError("key-map selectors must be unique")
            selectors.add(mapping.selector)
        return self


class MatchReport(AzuratorModel):
    """Read-only result of matching input values against supported Azure slots."""

    schema_version: Literal["1"] = "1"
    subscription_id: str = Field(min_length=1)
    subscription_name: str | None = None
    generated_at: datetime
    azure_binding_inspection: AzureBindingInspection
    providers: tuple[ProviderInfo, ...]
    input_selectors: tuple[str, ...]
    skipped_empty_selectors: tuple[str, ...] = ()
    resources: tuple[MatchResource, ...]
    inspections: tuple[CandidateInspection, ...]
    candidate_slots_compared: int = Field(ge=0)
    matches: tuple[KeyMatch, ...]
    binding_inspections: tuple[BindingInspection, ...] = ()
    bindings: tuple[CredentialBinding, ...] = ()
    warnings: tuple[DiscoveryWarning, ...]


class KeySlotSelection(AzuratorModel):
    """One explicit Azure resource and key slot selected without a raw value."""

    resource_id: str = Field(min_length=1)
    key_slot: str = Field(min_length=1)


class SelectionReport(AzuratorModel):
    """Read-only inspection result for explicitly selected Azure key slots."""

    schema_version: Literal["1"] = "1"
    subscription_id: str = Field(min_length=1)
    subscription_name: str | None = None
    generated_at: datetime
    azure_binding_inspection: AzureBindingInspection
    providers: tuple[ProviderInfo, ...]
    resources: tuple[MatchResource, ...]
    inspections: tuple[CandidateInspection, ...]
    selected_slots: tuple[KeySlotSelection, ...] = Field(min_length=1)
    binding_inspections: tuple[BindingInspection, ...] = ()
    bindings: tuple[CredentialBinding, ...] = ()
    warnings: tuple[DiscoveryWarning, ...]


class PlanSource(str, Enum):
    """How the slots represented by a rotation plan were selected."""

    dotenv_stdin = "dotenv-stdin"
    dotenv_file = "dotenv-file"
    sops_dotenv_file = "sops-dotenv-file"
    direct_selection = "direct-selection"


class PlanState(str, Enum):
    """Whether a generated rotation sequence can proceed without an override."""

    no_changes = "no-changes"
    ready = "ready"
    confirmation_required = "confirmation-required"
    blocked = "blocked"


class PlanStepAction(str, Enum):
    """One explicit action in a generated rotation sequence."""

    update_binding = "update-binding"
    verify_binding = "verify-binding"
    regenerate_key = "regenerate-key"


class PlanStepPhase(str, Enum):
    """The role an action plays in the bridge-key algorithm."""

    bridge = "bridge"
    rotate = "rotate"
    finalize = "finalize"


class ScheduledKeySlot(AzuratorModel):
    """One deduplicated slot and any dotenv selectors that matched it."""

    resource_id: str = Field(min_length=1)
    key_slot: str = Field(min_length=1)
    input_selectors: tuple[str, ...]


class PlanStep(AzuratorModel):
    """A secret-free, ordered operation in a generated rotation plan."""

    sequence: int = Field(ge=1)
    action: PlanStepAction
    phase: PlanStepPhase
    resource_id: str = Field(min_length=1)
    key_slot: str = Field(min_length=1)
    binding_id: str | None = None


class PlanWarning(AzuratorModel):
    """A secret-free planning warning with explicit execution semantics."""

    code: str = Field(min_length=1, pattern=r"^[a-z0-9-]+$")
    message: str = Field(min_length=1)
    impact: WarningImpact
    category: WarningCategory
    provider: str | None = None
    resource_id: str | None = None
    binding_id: str | None = None


class PreconditionDigest(AzuratorModel):
    """Digest of a canonical, secret-free planning precondition snapshot."""

    subject: str = Field(min_length=1, pattern=r"^[a-z0-9-]+$")
    algorithm: str = Field(pattern=r"^sha256$")
    digest: str = Field(pattern=r"^[0-9a-f]{64}$")


class RotationPlan(AzuratorModel):
    """Generated, secret-free read-only plan for selected Azure key slots."""

    schema_version: Literal["1"] = "1"
    tenant_id: str = Field(min_length=1)
    subscription_id: str = Field(min_length=1)
    subscription_name: str | None = None
    created_at: datetime
    source_format: PlanSource
    azure_binding_inspection: AzureBindingInspection
    source_path: str | None
    source_selectors: tuple[str, ...]
    skipped_empty_selectors: tuple[str, ...] = ()
    providers: tuple[ProviderInfo, ...]
    resources: tuple[MatchResource, ...]
    scheduled_slots: tuple[ScheduledKeySlot, ...]
    binding_inspections: tuple[BindingInspection, ...] = ()
    bindings: tuple[CredentialBinding, ...] = ()
    steps: tuple[PlanStep, ...]
    state: PlanState
    warnings: tuple[PlanWarning, ...]
    preconditions: tuple[PreconditionDigest, ...] = Field(min_length=1)


class Inventory(AzuratorModel):
    """A metadata-only inventory for one explicitly selected subscription."""

    schema_version: Literal["1"] = "1"
    subscription_id: str = Field(min_length=1)
    subscription_name: str | None = None
    generated_at: datetime
    providers: tuple[ProviderInfo, ...]
    resources: tuple[DiscoveredResource, ...]
    warnings: tuple[DiscoveryWarning, ...]

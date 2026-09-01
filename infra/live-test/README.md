# Disposable Azure live-test fixture

This Bicep fixture creates only the Azure resources needed to exercise
Azurator's reviewed Storage, Cognitive Services, Foundry project-connection,
and App Service application-settings contracts. It is development
infrastructure, not an Azurator product command.

## Contents

One deployment creates the dedicated `rg-azurator-live-test` resource group
with:

- an empty `Standard_LRS` StorageV2 rotation account with Shared Key
  authentication enabled;
- a separate empty `Standard_LRS` StorageV2 discovery account with Shared Key
  authentication disabled;
- an S0 `AIServices` Foundry project host with key authentication, project
  management, and a system-assigned managed identity enabled;
- a separate S0 `AIServices` discovery account with key authentication disabled
  plus a system-assigned managed identity, but no project, connection, or role
  assignment;
- one Foundry project under that account with its own system-assigned managed
  identity;
- an S0 key-authentication-enabled Azure OpenAI account with no model deployment;
- one project-level `AzureStorageAccount`/`AccountKey` connection initially
  containing Storage `key1`;
- one project-level `AzureOpenAI`/`ApiKey` connection initially containing
  OpenAI `Key1`;
- one empty Linux App Service app on an F1 plan with two Storage `key1`
  setting aliases, one Azure OpenAI `Key1` setting, and one unrelated setting;
- one built-in `Foundry User` role assignment for the deployment principal,
  scoped only to the disposable AI Services account.

Neither connection targets the Foundry project-host account itself. Its own
`Key1` is therefore the fixture's enabled, deliberately unbound target for the
skipped Azure-binding rotation path.

The accounts can incur usage charges if a caller stores data, invokes a service,
or creates a model deployment. This fixture does none of those things. The
resource group and every taggable resource carry explicit fixture and owner
tags. Account-level role tags distinguish rotation targets from discovery-only
disabled variants; the E2E harness validates those roles before invoking
Azurator.
The three managed identities satisfy the published Foundry account/project
creation shapes but receive no role assignments from this fixture. The
deployment principal's scoped role supplies the Foundry data actions needed for
Azurator to list project connections and re-read their credentials. An inherited
Azure `Owner` or `Contributor` role alone supplies control-plane access but not
these data actions. The role assignment is deleted with the resource group.

## Secret boundary

`resources.bicep` calls the reviewed `listKeys` operations inside Azure Resource
Manager and passes `key1` directly into the corresponding connection and App
Service setting resources.
No key is a CLI argument, parameter-file value, output, local file, or shell
variable. The two key-authentication-disabled discovery accounts are never
passed to `listKeys`, export, planning, or rotation. Do not add secret outputs
or deploy with Azure CLI `--debug`.

The Storage connection category is the single reviewed observed
`AzureStorageAccount` shape documented by the repository. The pinned public
ARM contract documents its `AccountKey` credential shape but omits that category
even though the public-cloud service returns it. The fixture does not try
alternate categories or credential fields.

The generic management schema does not declare category-specific metadata
requirements. Azure's published connection example uses `ApiType: Azure`, the
target resource's exact `ResourceId`, and its `location`; the public-cloud
service also rejects the reviewed Storage and Azure OpenAI connections when
those fields are absent. The fixture sends only that canonical metadata shape
and does not probe aliases.

## Lifecycle

Use the Nix apps from the repository root:

```sh
nix run .#live-test-what-if
nix run .#live-test-up
nix run .#live-test-e2e
nix run .#live-test-e2e -- --reuse-fixture
nix run .#live-test-recovery
nix run .#live-test-down
```

`live-test-what-if` performs local Bicep compilation and an ARM What-if only.
`live-test-up` refuses to deploy over an existing fixture group, automatically
registers only `Microsoft.CognitiveServices`, `Microsoft.Storage`, and
`Microsoft.Web` when
needed, shows a subscription-scope ARM What-if for the complete fixture, and
asks before creating anything. After confirmation it creates the exact tagged
resource group and deploys the reviewed resources at resource-group scope.
The deployment uses ARM's `deployer().objectId` contract to assign `Foundry
User` to its own principal; it does not query or persist a user identifier
locally.
Provider registration enables the resource namespaces but creates no service
instance. If the resource deployment fails after group creation, the tagged
group remains visible for inspection and `live-test-down` cleanup.
`live-test-down` validates the exact subscription, group name, and ownership
tags, lists the deletion targets, asks again, submits one deletion operation,
lets Azure CLI handle ARM's standard long-running-operation wait, and performs
one final existence check.

Each deployment name produces a new eight-character global-name suffix. Azure
may retain deleted Cognitive Services account names temporarily through its
soft-delete behavior, but a later fixture run does not reuse them. Subscription-
scope deployment history remains as secret-free audit metadata and has no
running resource cost.

Live Azure mutation is never part of automated tests. An agent must still obtain
explicit user approval immediately before running any mutating lifecycle, E2E,
or recovery app.

`live-test-e2e -- --reuse-fixture` is only for continuing with an already
deployed fixture after a pre-rotation harness failure. It rejects any group
whose subscription identity or ownership tags differ, requires the exact
eight-resource role matrix, and requires an empty valid local operation
catalog. It skips fixture deployment only. Discovery, plans, confirmations,
rotations, verification, workspace cleanup, and tagged teardown remain the same.

## Guided happy-path E2E

`live-test-e2e` is a development-only composition of the existing lifecycle and
Azurator commands. It:

1. verifies that Azurator can authenticate to the Azure CLI-selected
   subscription;
2. delegates fixture creation to `live-test-up`, including its What-if and
   confirmation;
3. runs structured metadata-only discovery and verifies enabled plus disabled
   key-authentication variants for both reviewed resource providers;
4. validates a structured direct plan for the unbound Foundry project-host
   `Key1` with `--skip-azure-bindings`, including the recorded skip mode, absent
   Azure bindings, and confirmation warning;
5. exports that one current key into a private verification snapshot, runs the
   separately confirmed direct skipped-binding rotation, and proves through
   `match --skip-azure-bindings --json` that the old value no longer matches;
6. immediately removes the pre-rotation snapshot;
7. creates a disposable private age identity and asks `azurator export
   --sops-out` to create one SOPS-encrypted dotenv file containing only the
   tagged enabled rotation Storage `key1`, Storage `key2`, and Azure OpenAI
   `Key1`; no plaintext export is created for this managed path;
8. adds one exact alias for each selected key plus an unrelated value and an
   empty assignment inside the ciphertext;
9. confirms through `match --sops-file --json` that six assignments form three
   grouped local bindings while the reviewed Foundry and App Service records
   are also identified;
10. validates the complete structured `plan --sops-file --json`, including all
    31 bridge, regeneration, and finalization steps across the seven bindings,
    including restoration of the local binding originally attributed to
    Storage `key2` onto its regenerated value;
11. lets `azurator rotate --sops-file` generate, display, validate, and confirm
    that same plan once, then checks the encrypted aliases, unrelated and empty
    assignments, both Foundry records, all three App Service key settings, and
    the unrelated App Service setting; and
12. delegates deletion to `live-test-down`, including its fresh confirmation.

The workflow does not pass `--yes`, invoke a model, store blob data, or claim a
workload health check. Only the tagged enabled Foundry host, Storage, and Azure
OpenAI accounts enter export or rotation. The disabled variants remain
discovery-only. Its temporary directory, age identity, exported files, and
managed ciphertext use private modes. The Foundry-host snapshot is removed
after verified skipped-binding rotation and on every cancelled or failed direct
path. No managed plaintext export exists. A cancelled managed export or
rotation removes the remaining workspace.
Verified success also removes it before teardown.

The current guided managed path selects both slots of the tagged Storage
Account and one slot of the tagged Azure OpenAI account. Its fake-command
contract test covers the complete two-slot order and rejects a plan that omits
or misorders the final restoration to Storage `key2`. Two-slot ordering, original-slot restoration,
grouped dotenv aliases, grouped SOPS aliases, resume reconciliation, drift
rejection, and operation redaction are also covered by product tests without
Azure mutation.

If the managed SOPS rotation fails or is interrupted after the attempt starts,
the fixture and private workspace are deliberately retained. A recovery
operation created from `--sops-file` is bound to the exact ciphertext path and
requires the retained disposable age identity. No managed plaintext copy is
retained. A failed direct skipped-binding rotation retains the fixture and any
operation for diagnosis, but removes its verification snapshot because
direct-selection recovery is not file-bound. Inspect retained state with:

```sh
azurator operation list
azurator operation show OPERATION_ID
azurator rotate --resume OPERATION_ID
```

Delete the private workspace only after recovery is complete or deliberately
abandoned, then run `nix run .#live-test-down`. This command exercises only the
verified happy path; controlled interruption is a separate command.

Explicitly approved disposable runs have exercised the complete guided path:

- enabled and disabled key-authentication discovery variants;
- direct Foundry-host rotation with Azure binding inspection skipped;
- SOPS export without a plaintext intermediary;
- six encrypted aliases grouped into three local bindings;
- the exact 31-step Storage, Azure OpenAI, Foundry, App Service, and SOPS plan;
- both Storage slots with restoration of the original `key2` binding;
- preservation of unrelated SOPS and App Service values;
- automatic operation and private-workspace cleanup; and
- tagged resource-group teardown verified through an independent ARM query.

No workload was tested. This evidence does not authorize another live
mutation; every run still requires fresh approval at each mutation boundary.

## Guided recovery E2E

`live-test-recovery` is a development-only composition for one controlled
interruption and resume. It does not change product code or add a fault-injection
option. It:

1. requires the local safe `operation list --json` projection to contain no
   valid or invalid retained entries;
2. delegates fixture creation to `live-test-up`, including What-if and
   confirmation;
3. performs metadata-only discovery;
4. starts a normal direct
   `rotate --select '<tagged-enabled-rotation-storage-id>#key1'` in the
   foreground, with its complete plan display and default-No confirmation;
5. runs a separate local watcher that uses only `operation list/show --json`
   and sends `SIGINT` when exactly one running operation exposes a pending
   checkpoint;
6. displays that retained UUID through `operation show`, then invokes the
   normal `rotate --resume OPERATION_ID` flow with a second confirmation;
7. requires successful resume to remove the operation automatically and uses a
   secret-free direct-selection plan to verify that the reviewed Foundry
   Storage connection and App Service Storage settings contain the current
   `key1`; and
8. delegates deletion to `live-test-down`, including its fresh confirmation.

The command never passes `--yes`, writes a raw-key file, reads `operation.json`
directly, invokes a workload, or treats a warning/error string as state. The
watcher workspace is mode `0700` and contains only its target PID and a bounded
status/UUID result; it is removed on every exit.

Interception is timing-dependent. If the foreground command is cancelled before
mutation or completes before a pending checkpoint can be interrupted, the
workflow says the recovery exercise was not completed. It offers normal tagged
teardown only when no operation remains. A failed or cancelled resume leaves
the retained operation and fixture in place and reports the ordinary
`operation list`/`rotate --resume` recovery path.

Only fake-command orchestration tests run under Nix or CI. A real invocation
still needs fresh approval immediately before deployment, initial rotation,
resume, and teardown.

An explicitly approved disposable run exercised the recovery path. The watcher
interrupted a pending bridge update, normal resume verified all five planned
steps, the transient operation was removed, the final Foundry Storage record
used the current `key1`, and independent checks confirmed tagged teardown and
an empty valid local operation catalog. This evidence does not authorize or
automate another run.

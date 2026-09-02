---
type: Product Semantics
title: Complete Azurator behavior
description: Detailed implemented CLI, key-resource, binding, planning, export, rotation, and recovery semantics.
tags: [product, cli, azure, rotation]
status: pre-alpha
---

# Complete Azurator behavior

Azurator is an unofficial, open-source tool for finding and safely rotating
shared-key credentials for Azure services.

## Product goal

Azurator rotates explicitly selected, retrievable Azure key slots and
updates supported configuration that stores those values. A selection can come
from exact Azure resource and slot identities or from matching supplied dotenv
values.

The core workflow is:

1. Stay within one explicitly selected Azure subscription.
2. Discover supported key resources without retrieving key values.
3. Retrieve keys only through reviewed providers when matching, exporting,
   planning, or rotation requires them.
4. Build one complete read-only plan and never require a hand-written plan.
5. Display and confirm that plan before mutation.
6. Update and verify supported stored copies while rotating each selected slot.
7. Retain secret-free recovery state only when a confirmed rotation starts.

The standalone command is `azurator`. Business logic remains independent of
`azure-cli-core`.

## Implemented scope

### Key resources

| Azure resource type | Slots |
| --- | --- |
| `Microsoft.Storage/storageAccounts` | `key1`, `key2` |
| `Microsoft.CognitiveServices/accounts` | `Key1`, `Key2` |

Metadata discovery includes reviewed resources whose key authentication is
disabled. Those resources remain visible but never enter key retrieval, export,
planning, or rotation.

### Credential bindings

Azurator can identify, update, and verify these stored key copies:

- public-cloud, project-level Foundry `AzureStorageAccount` connections using
  `AccountKey`;
- public-cloud, project-level Foundry `AzureOpenAI` connections using `ApiKey`;
- exact whole-value application settings on visible top-level App Service apps;
- exact matched assignments in one explicitly selected plaintext dotenv file;
- exact matched top-level assignments in one explicitly selected
  SOPS-encrypted dotenv file.

Export can exclusively create one new plaintext or SOPS-encrypted dotenv file
from selected retrievable slots. A secret-free key map can preserve confirmed
dotenv selector-to-resource-and-slot mappings and drive a later export. Export
does not merge or replace a file.

Use three distinct domain terms throughout the implementation:

- A **key resource** is the Azure account that owns a reviewed key pair.
- A **credential binding** is a separate Azure or local configuration record
  that stores a copy of, or reviewed reference to, one key slot.
- A **consumer** or **workload** is a running application, deployment, model,
  or process that reads a binding and uses the credential.

Models, providers, plans, operations, and structured output use `binding`.
`Consumer` is reserved for actual runtime use, which binding inspection alone
does not prove.

Every installed reviewed Azure binding provider is inspected by default.
`match`, `plan`, and direct `rotate` accept `--skip-azure-bindings` to omit all
Azure-side binding inspection. The choice is explicit in reports, plans, and
fresh validation and adds a confirmation warning. An explicit `--env-file` or
`--sops-file` remains a local binding and is still managed. Provider allowlists,
denylists, and resource-scoped binding filters are not implemented.

The Foundry Storage `AccountKey` mapping is one strict reviewed observed
contract. Its exact discrepancy and pinned scope live in
[provider contract discipline](../engineering/provider-contracts.md).
During verification, only a canonical credential with an unequal key is an
actionable mismatch. Metadata drift or a noncanonical credential is a contract
failure and must never trigger an automatic connection update.

Binding inspection proves only the stored configuration value. It does not
prove that a project feature, model, deployment, application, or process uses
that value. Broader workload inspection and health checks are not implemented.
Entra client secrets, SAS tokens, passwords, and values Azure cannot retrieve
after creation are outside the product scope.

## Pre-alpha compatibility

Azurator has not published a compatibility boundary. Keep Azurator-owned
persisted schemas and provider-contract identifiers at `1`; a breaking change
replaces the current v1 shape in place. Do not maintain readers, migrations,
aliases, or fallback parsing for artifacts produced by earlier commits. Strict
validation rejects stale shapes. Version increments begin only after the
project explicitly promises compatibility. Azure API versions, Azure SDK
versions, and the Azurator package version are separate and remain independently
pinned or versioned.

## Command contracts

The running `azurator COMMAND --help` surface defines exact option names and
accepted combinations. This section records the behavior behind those options.

### Human output detail

Human output has three secret-safe detail levels selected by the repeatable
root option before a command:

- normal output presents results, exact mutation intent, progress, failures,
  and facts that affect confirmation or execution;
- `-v` adds inspection scope, comparison counts, empty inspected binding
  categories, file mechanics, and local recovery lifecycle details;
- `-vv` additionally appends stable warning code, impact, category, provider,
  resource, and binding identifiers to rendered provider warnings when present.

The normal level avoids repeating static key-resource coverage limitations
after every successful command. Confirmation-relevant Azure binding scope
remains visible either as a concrete warning or as a compact positive statement
of what was checked. Blocking warnings, skipped Azure binding inspection, App
Service restart/concurrency warnings, and cleanup failures are never hidden by
the normal level. Plan and rotate also keep managed-file interruption state
visible.

Verbosity never permits raw keys, request or response bodies, stored error
messages, fingerprints, or tracebacks to cross the output boundary. Structured
`--json` output remains complete and identical at every verbosity level.

### Support catalog

`list` is login-free and projects the reviewed built-in contracts into separate
key-resource and credential-binding catalogs. With no filter it shows both.
`--key-resources` and `--bindings` select one category, and combining them still
shows both. Filtering changes presentation only. The command must not construct
credentials, providers, or Azure clients. Provider contracts remain the internal
authorization and execution boundary and are not flattened into one public list.

### Export

`export` crosses the key-retrieval boundary without mutating Azure. It first
performs metadata-only discovery, then uses a terminal picker, repeatable exact
`--select`, explicit `--all`, or one strict key map to produce a complete
secret-free resource/slot/selector intent. A key map must match the already
selected subscription and is mutually exclusive with the other selection
modes. Its exact selectors, resources, and slots are resolved against the
current inventory; repeated resource/slot identities intentionally preserve
aliases. It validates that `--out` names a new
plaintext file or `--sops-out` names a new encrypted file beneath an existing
resolved parent and confirms the displayed intent before retrieving any key.
Exactly one output option is required and filenames never select the mode
implicitly.
Only installed reviewed key-reading providers may stream the exact two-slot
state; the renderer retains only selected slots. Plaintext mode exclusively
creates the canonical dotenv document with mode `0600`. SOPS mode validates
SOPS 3.13.x before key retrieval, encrypts the at-most-1-MiB document from stdin
using the absolute destination as `--filename-override`, captures at most 8 MiB
of ciphertext, decrypts it again from stdin, and compares the complete
assignment map through fresh HMAC fingerprints before exclusively creating the
mode-`0600` ciphertext destination. It never prints values, writes SOPS
plaintext to disk, replaces an existing path, or writes a plan or recovery
operation.

### Matching

`match` is read-only but explicitly crosses the key-retrieval boundary. Raw
values arrive through stdin, one explicit user-owned `--env-file`, or in-memory
decryption of one explicit `--sops-file`. They become per-run HMAC fingerprints
and are compared with provider candidates in constant time. Its default output
is a sparse match list; the optional matrix uses input selectors as rows and
Azure resources, not provider implementations, as columns. Explicit
`--key-map-out` atomically writes a strict key-map JSON artifact containing only
confirmed, unambiguous selector, complete ARM resource ID, and exact slot
mappings. It fails rather than creating an empty or ambiguous map. Unmatched and
empty assignments are not included. The map contains no values, fingerprints,
source path, generated timestamp, provider output, binding data, or warning
history. Loading rejects duplicate JSON member names at every object level.

### Metadata inventory

`discover` enumerates every resource supported by an installed provider and
reports its resource ID, provider/type, known key-slot names, whether values are
retrievable, whether slots are rotatable, and permission or coverage warnings.
It must not call APIs that return key values merely to build the inventory.
Credential-binding slot attribution that requires a credential belongs in `match` or
`plan`, not metadata-only `discover`. Table output is the interactive
default and renders one `Key authentication` state: `enabled` when the exact
provider metadata permits resource-key authentication and `disabled` when it
does not. This state does not claim that a key is used or that the current
principal may retrieve or rotate it. Structured JSON uses the exact field
`key_authentication` with the same `enabled` or `disabled` values. Never suggest
that this is a complete inventory of every secret in Azure: Azure has no global
API for that, and Azurator can only report resource types implemented by its
providers.

Every runtime resource already belongs to an installed reviewed provider, so
the resource model does not duplicate that fact with a `coverage` state.
Provider scope is represented by installed provider metadata and explicit
coverage warnings; `key_authentication` represents only the reviewed Azure
resource setting. Azurator does not currently inventory unknown resources by
scanning provider-operation metadata. Operation names such as
`listKeys`, `regenerateKey`, and `rotateKey` may inform future provider research,
but they do not define API versions, request bodies, response shapes, key slots,
or safe rotation semantics. Keep any such research outside the executable
inventory until a reviewed provider exists. Only reviewed providers may call
key-returning or mutating operations.

### Planning

The implemented `plan` command supports direct and reverse-lookup selection.
With no explicit input mode it performs metadata-only discovery and presents
rotatable slots from installed reviewed providers on a controlling terminal.
Repeatable `--select 'ARM_RESOURCE_ID#SLOT'` supplies those exact identities
without a terminal. After either direct selection, Azurator retrieves the
complete reviewed two-slot state only for those resources, fingerprints it
ephemerally for binding attribution, and discards the values. With
`--stdin`, it instead runs the same reverse-lookup matching boundary as
`match`. With `--env-file`, it safely reads one explicit user-owned dotenv file,
performs the same matching, and binds matched selectors as managed file
credential bindings. With `--sops-file`, SOPS decrypts one safe encrypted
dotenv snapshot in memory and the same matcher and binding model apply. The
pinned subscription may be overridden.

### Direct key selection

When `azurator plan` runs on a controlling terminal without an explicit input
mode, it presents a numbered multi-select list of rotatable key slots reported
by installed, reviewed providers in the selected subscription. The user enters
one or more comma-separated numbers and selects exact Azure resource/slot
identities. In scripts, repeatable
`--select 'ARM_RESOURCE_ID#SLOT'` supplies the same identities without a
terminal. No raw key value is required merely to choose a rotation target.

The implemented contract is:

- list only slots from installed reviewed providers and retain the explicit
  subscription boundary;
- omit slots that the installed provider does not declare rotatable;
- keep `discover` metadata-only and retrieve key values only after selection when
  reviewed binding attribution or execution validation requires them;
- never display, persist, or accept a key value through the picker;
- keep `match --stdin` and dotenv-driven planning as a separate reverse-
  lookup workflow for users asking which Azure slot equals an existing
  application value;
- accept only a complete top-level ARM resource ID plus the exact
  provider-declared slot; the ID's subscription must equal the selected
  command scope and never switches it;
- reject partial or name-only IDs, nested IDs, unknown resources or slots,
  duplicates, and combinations with another selection source before candidate
  inspection;
- fail closed without a controlling terminal when no explicit input or
  `--select` mode was supplied;
- encode the selection source and exact resource/slot identities in the
  generated secret-free plan, then repeat metadata, binding, scope, and drift
  checks before rotation without requiring the user to resupply a raw value.

Neither picker nor `--select` fabricates dotenv selectors or synthetic matches.
Both use the same explicit selection report and a plan source of
`direct-selection`; scheduled slots have no input selectors, and the planning
precondition records the exact selected identities.

For the `plan` command, render the readable preview without creating a file when
neither `--json` nor `--out` is present. `--json` prints the complete plan to
stdout without persisting it; `--out <path>` writes the complete plan atomically
with mode `0600`. `--json` and `--out` are mutually exclusive. Plans contain no
secrets but reveal resource IDs, selectors, and infrastructure relationships,
so users should avoid capturing structured output in ordinary logs and use
`--out` for an explicitly managed rotation artifact. Serialized plans and
operations share an 8 MiB per-artifact limit. Plans use it at generation and
loading; initial rotation also preflights the operation's largest bounded state
before any mutation.

The generated plan must include a schema version, tenant and subscription IDs,
creation time, provider contract versions, selection source,
exact scheduled identities, ordered steps, typed warning impacts/categories,
and precondition digests.
Dotenv plans also include source selectors; a managed-file plan includes its
absolute source path with its full parent chain resolved without following the
final file component. It must never contain raw keys, new keys, persistent
fingerprints, session HMACs, or HMAC keys. Initial `rotate` schema-validates the
plan, validates the recorded contract version of every provider installed for
execution, and accepts only executable Storage or Cognitive Services plans
whose managed bindings are owned by installed reviewed providers. With
`--plan`, it repeats source-appropriate inspection and drift checks and rejects
stale or manually altered plans. Without `--plan`, it builds
the same current planning snapshot from the terminal selection, repeatable
`--select`, `--env-file`, or `--sops-file`, displays it, and asks for
confirmation once. Only after confirmation does it exclusively write one
operation containing that exact plan and recovery progress beneath
`platformdirs.user_state_path("azurator")/operations/<operation-id>/operation.json`.
On verified success it removes that transient artifact; on failure or
interruption it reports the operation ID for `rotate --resume`. An explicit
`plan --out` file remains user-owned and is never removed automatically. `-y`
skips only confirmation and cannot bypass any validation or block.

`operation list` and `operation show OPERATION_ID` are local read-only views
over the retained UUID-scoped recovery entries. They do not resolve
authentication, construct providers, or contact Azure. The catalog accepts only
canonical UUID names beneath the private operation root, loads each exact
`operation.json` through `OperationStore`, and applies the same intent,
fingerprint-set, lifecycle, and progress validation used by execution. A
missing root is an empty list; an unsafe root is an error and is never hardened
or created by inspection. List isolates invalid entries by UUID so one corrupt
artifact cannot hide other recoverable operations.

The rendered and JSON projections contain only operation ID, timestamps,
subscription name/ID, lifecycle, verified/total progress, pending-or-next
action, bounded error code, selected resource names/slots, and the exact
source-appropriate resume command. They omit the full embedded plan, error
message, resource IDs, binding paths, key-state salt, and recovery
fingerprints. A pristine stdin-sourced operation includes `--stdin` in
that command. This local validity does not replace the normal auth, installed
provider, source, scope, and Azure drift checks performed by actual resume.

The implemented precondition digest covers the canonical secret-free planning
snapshot: subscription, selection source, optional managed path, provider
versions, selected resource metadata, scheduled slots, and inspected
relationships. It is deliberately not a digest of raw input values. Initial
streamed rotation requires the values again and repeats matching with a fresh
session HMAC. Managed-file rotation instead safely re-reads and re-matches the
exact recorded file. Direct-selection rotation accepts no token input and repeats
discovery, complete selected-resource key inspection, binding attribution,
scope checks, and plan comparison.

## Security boundary

The complete secret-input, persistence, provider, plan, operation, drift,
redaction, and mutation controls live in the
[threat model](../security/threat-model.md). Read it before changing any of
those behaviors.

## SOPS dotenv flow

`--sops-file` is implemented for SOPS-encrypted dotenv documents:

```text
SOPS-encrypted dotenv file
  -> safe ciphertext snapshot
  -> sops 3.13.x decrypt with explicit dotenv input/output types
  -> plaintext dotenv in process memory
  -> immediate per-run HMAC-SHA-256 matching
  -> managed local binding attribution
  -> sops set --value-stdin on an encrypted temporary during rotation
  -> in-memory verification and atomic ciphertext replacement
```

```sh
azurator match --sops-file secrets.enc.env
azurator plan --sops-file secrets.enc.env --out plan.json
azurator rotate --sops-file secrets.enc.env
```

SOPS resolves age identities, hardware-backed identities, or cloud KMS access
through its normal mechanisms. Private identities and replacement keys never
belong in CLI arguments. Azurator invokes SOPS without a shell, discards command
stderr, never writes decrypted content, and delegates encryption rather than
implementing cryptography itself.

The source must be a current-user-owned regular non-symlink file no larger than
8 MiB and not writable by group or other users. Decrypted UTF-8 dotenv is limited
to 1 MiB. Updates work on a mode-`0600` encrypted temporary in the same
directory. Before atomic replacement, Azurator requires encrypted status,
verifies selected values, HMAC-compares unrelated assignments, and confirms the
original ciphertext identity and digest did not change. Source mode and
ownership are preserved.

The older explicit pipeline remains a read-only or saved-plan matching option,
but stdin has no managed path and therefore cannot be updated:

```sh
sops decrypt secrets.enc.env | azurator plan --stdin --out plan.json
```

## Managed dotenv and export files

The implemented export modes bootstrap a new private dotenv file from exact
reviewed Azure key slots:

```text
azurator export --out selected-keys.env
azurator export --sops-out selected-keys.enc.env
azurator export --select '<arm-resource-id>#key1' --out selected-keys.env
azurator export --all --sops-out selected-keys.enc.env
azurator match --sops-file existing.enc.env --key-map-out azurator.keys.json
azurator export --key-map azurator.keys.json --sops-out recreated.enc.env
```

Without `--select`, `--all`, or `--key-map`, a controlling-terminal picker lists
retrievable slots from the metadata-only inventory. Repeatable `--select`
chooses exact slots without a terminal. `--all` selects every slot displayed by
installed reviewed providers in the one selected subscription; it does not mean
every Azure secret. Deterministic selectors are derived from provider, resource
name, and slot, with stable numeric suffixes for collisions. Azurator resolves the
existing parent without following a final destination component, rejects any
existing target, displays the full secret-free mapping and mode-specific
warning, and confirms before it constructs key-reading clients or calls
`listKeys`.

After confirmation, each selected resource's exact reviewed pair is read once
and only selected slots are rendered. The complete document must satisfy the
strict canonical single-quoted dotenv and 1 MiB contracts. Plaintext mode
writes it atomically and exclusively with mode `0600`. SOPS mode first validates
the pinned executable, passes plaintext only over stdin, captures ciphertext
only from stdout, and decrypts it in memory. A fresh `EphemeralFingerprinter`
must prove the exact selector set and every value before the at-most-8-MiB
ciphertext is atomically and exclusively written with mode `0600`. The user must
provide both a SOPS creation rule or environment recipient configuration and a
locally usable decryption identity. A concurrent destination wins and Azurator
fails without replacement. Cancellation, partial provider failure, invalid key
text, SOPS or round-trip failure, and file failure produce no destination.
Values never reach stdout, logs, plans, operations, exception messages, ordinary
arguments, or a plaintext temporary. Neither mode supports merge, append, or
overwrite.

The alternative `--key-map` selection mode loads one bounded, regular,
non-symlink JSON artifact. The map schema contains only its version, one
subscription ID, and one or more selector, complete key-resource ARM ID, and
slot mappings. Before Azure access it validates the canonical subscription UUID,
dotenv selectors, complete top-level ARM ID shape, each ID's embedded
subscription, and key-slot name syntax. Selectors are unique, while multiple
selectors may intentionally refer to one slot. The selected login subscription
must match the artifact; Azurator never switches scope from the map. Every
resource and slot is resolved against fresh metadata and the current reviewed
retrievable-key contract before confirmation or key retrieval. Export retrieves
each mapped resource once and renders the mappings in artifact order. It neither
adds sibling slots nor reconstructs unmatched or unrelated dotenv assignments.

The implemented plaintext mode uses one existing dotenv file as both matching
source and managed configuration record:

```text
azurator match --env-file secrets.env
azurator plan --env-file secrets.env --out plan.json
azurator rotate --plan plan.json
azurator rotate --env-file secrets.env
```

The complete parent chain is resolved and recorded while the final file
component is never followed, then the path is safe-read as a current-user-owned
regular file of at most 1 MiB. Retargeting a parent symlink therefore cannot
redirect a later rotation. Matching uses the normal per-process HMAC boundary.
Every selector must map to at most one Azure resource/slot identity; aliases
mapping to the same slot are grouped. The private plan stores the bound absolute
path and selector names, never file content or a value digest. Group or other
read/write POSIX mode bits do not block matching, planning, or rotation and are
not persisted. They cause exactly one stderr notice per command:
`Warning: The dotenv file has broad permissions. Consider restricting access to the minimum required.`
Windows and non-mode-bit ACL or directory access are not inferred.

During rotation, each grouped assignment set is a normal managed binding. Azurator
writes the bridge key, re-reads and verifies every assignment, regenerates the
selected Azure slot, then writes and verifies its new key. The strict parser and
rewriter preserve unmatched assignments and comments, reject malformed or
duplicate assignments, and emit selected values in one canonical single-quoted
form while preserving each original LF, CRLF, or CR line ending. Writes use a
same-directory private temporary file, preserve the source POSIX mode, owner,
and group, perform file `fsync`, atomic replacement, and parent-directory
`fsync` where supported. A pending
file update uses the same verify-before-repeat resume rule as Foundry. Azurator
does not reload or health-check any application that read the file. Atomic
replacement prevents partial content but is not a lock against non-cooperating
writers, so the file must not be edited or redeployed concurrently with rotation.

This mode deliberately stores keys as plaintext. It is not a fallback from
SOPS, and the warning requires plan review. The separate implemented
`--sops-file` mode manages encrypted dotenv in place through the contract above.
SOPS YAML/JSON, export merge or overwrite, and recipient management remain
outside the current scope. Streamed stdin input has no path and therefore
cannot be rewritten.

## Engineering boundary

Module responsibilities, provider-interface rules, credential composition,
package layout, Nix source filtering, development commands, and live-test rules
live in [engineering knowledge](../engineering/).

## Rotation semantics

A match is a factual equality result, not a security classification. Azurator
must never label a supplied value or matched slot as compromised, leaked, or
unsafe. The user selects which matched slots should be rotated and may be
performing routine maintenance, incident response, or another workflow.

Use one algorithm based on the number of selected slots. Azure cannot atomically
regenerate a slot and update independent credential bindings, so the sibling temporarily
bridges that authentication gap:

1. If only `A` is selected, leave bindings already storing `B` unchanged. Move
   and verify bindings storing `A` on `B`, regenerate `A`, then move and verify
   those bindings on new `A`.
2. If both slots are selected, consolidate bindings on bridge `B`, regenerate
   `A`, move and verify every managed binding on new `A`, then regenerate `B`.
   Finally, return and verify every binding originally attributed to `B` on new
   `B`. Bindings without reviewed slot attribution remain on new `A`. The
   current Storage provider uses its declared order: `key2` bridges while
   `key1` is regenerated first.
3. If no affected binding exists, regenerate the selected slot directly.
4. If no sibling can bridge an affected binding, use the direct regenerate-
   then-update sequence and warn that an interruption is expected.
5. Never regenerate both slots together or call a slot free merely because no
   binding was discovered.
6. Directly before each regeneration, re-read every known managed binding
   against the slot expected after all preceding plan steps. Repair only an
   exact verification mismatch by setting and re-verifying that expected slot;
   any other read or verification failure blocks before regeneration.
7. A managed transition receives both the expected current key and replacement
   key. The replacement already present is a no-op, the expected value may be
   changed, and every third value blocks as drift.

App Service uses the same sequence, but its official update operation replaces
the complete application-settings dictionary and provides no reviewed
conditional-write token. Azurator copies the latest dictionary and changes only
the exact matched names. Every update restarts the app, and the plan requires
confirmation that no settings edit or deployment runs concurrently.

Credential-binding inspection is limited to installed reviewed providers.
Within that scope, attempted inspection must complete or planning blocks.
Distinguish between:

- bindings Azurator can identify, update, and verify,
- bindings it can identify but not update,
- locations it attempted but cannot inspect,
- binding categories outside installed coverage.

Every generated plan has one outcome:

- `no-changes`: complete inspection selected no key slots and there is no
  executable sequence;
- `ready`: Azurator can perform and verify the complete sequence;
- `confirmation-required`: the sequence is executable, but interruption or
  an explicit provider-coverage boundary must be acknowledged with a
  default-No prompt;
- `blocked`: Azurator cannot validly execute the Azure rotation, including when
  an attempted binding inspection is incomplete or an affected known binding
  requires an update Azurator cannot perform.

Every plan step is executed by Azurator. Plans never assign credential updates
or key regeneration to the user. If an affected known binding cannot be
updated and verified automatically, the plan is `blocked` and contains no steps
for that resource. An observed-only binding already attributed to an untouched
sibling does not block a one-slot rotation because no update is required.

Failed resource discovery, unavailable candidate comparison, or incomplete
enabled binding inspection is `blocked`, not a successful empty plan: Azurator
cannot safely account for uninspected slots or bindings.

`-y`/`--yes` accepts executable warnings and the rotation confirmation or the
fully displayed plaintext or SOPS export intent. It must never bypass a block, plan
validation, scope, drift, permissions, provider contracts, export selection or
destination validation, or secret-handling rules. The reviewed
Storage/Cognitive/Foundry/App-Service/plaintext-dotenv/SOPS-dotenv slice updates and verifies
configuration records before continuing; it does not reload or run a workload
health check.

Warning impact is part of this execution contract. Providers and planners emit
an explicit `advisory`, `confirmation`, or `blocking` impact and a category.
Planning derives state from those typed values. Warning code names remain useful
for automation and presentation but never authorize, block, confirm, replace,
or suppress behavior through a prefix or suffix convention.

## Review boundary

Candidate work and the contract required before broadening `rotate` are tracked
in the [roadmap](roadmap.md). A roadmap entry is not implemented behavior.

---
type: Threat Model
title: Azurator threat model
description: Assets, trust boundaries, controls, accepted limitations, and review gates for secret handling and Azure mutation.
tags: [security, azure, secrets, rotation]
status: pre-alpha
---

# Azurator threat model

## Status and scope

This document defines the security boundary for the implemented pre-alpha
surface described in [product behavior](../product/behavior.md). It covers:

- authentication and one-subscription Azure scope;
- metadata discovery, exact slot selection, and dotenv matching;
- reviewed Storage and Cognitive Services key retrieval and regeneration;
- Foundry, App Service, plaintext dotenv, and SOPS dotenv binding inspection
  and updates;
- exclusive plaintext and verified SOPS-encrypted dotenv export;
- generated plans, confirmed rotation, retained operations, and resume.

The model protects retrievable, high-entropy Azure-generated account keys. It
does not extend the product to passwords, SAS tokens, Entra client secrets, or
values Azure cannot retrieve after creation.

This model distinguishes the Azure **key resource** that owns a key pair from a
**credential binding**, which is a separate Azure or local configuration record
that stores a copy of or reviewed reference to one slot. A **consumer** or
**workload** is the running application, deployment, model, or process that
reads a binding. Binding inspection does not establish active workload use.
Automatic Azure binding inspection runs for all installed reviewed providers by
default. `--skip-azure-bindings` explicitly omits all Azure bindings, persists
that choice for validation, and adds a confirmation warning. It does not omit
an explicitly selected local plaintext or SOPS dotenv binding.

## Assets to protect

- raw account keys supplied for matching or selected for rotation
- current and newly generated Azure account keys
- raw account keys intentionally persisted in an explicitly managed plaintext
  dotenv file
- raw account keys intentionally persisted in an explicitly created plaintext
  dotenv export
- raw account keys held transiently while constructing and verifying an
  encrypted dotenv export
- raw SOPS-decrypted values held transiently in process memory
- the integrity of managed or newly exported SOPS ciphertext and its recipient
  metadata
- salted operation recovery fingerprints, which can verify a candidate account key
- age private identities used by SOPS
- the integrity of generated plans and transient operations
- subscription, tenant, resource, credential-binding, and document-path metadata

Plans and operations contain no usable key values, but they remain sensitive
because they map infrastructure relationships and resource identifiers.
Operations additionally contain salted verifiers for the reviewed high-entropy
account keys that existed around a rotation.

## Trust boundaries

1. **Secret input boundary.** User-supplied raw values arrive through stdin in
   streamed dotenv mode, by safe-reading the exact existing user-owned file named
   with `--env-file`, or by decrypting a safe ciphertext snapshot named with
   `--sops-file`. Direct selection accepts no raw input value; its
   ordinary process arguments contain only one exact top-level ARM resource ID
   and provider-declared slot per `--select`. SOPS replacement values travel to
   the exact reviewed command over stdin. Ordinary process arguments remain
   outside the raw-secret boundary.
2. **Process memory boundary.** Raw values, Azure candidate values, the ephemeral
   HMAC key, and session fingerprints exist only in process memory for the
   shortest practical time.
3. **Azure management boundary.** Only reviewed providers may call
   key-returning or mutating operations defined by a published official or
   explicitly accepted observed contract for one selected subscription.
4. **Foundry connection boundary.** Project connections are listed without
   credentials. Credentials may be requested only for a connection already
   linked to a directly selected or matched Storage or Cognitive Services
   account, then compared and discarded in memory.
   A reviewed rotation may update that exact connection through the management SDK
   and re-read the credential through the data plane; SDK body logging remains
   disabled on both paths. For Storage connections, the published data-plane
   `v1` union omits `AccountKey`; Azurator deliberately accepts only the
   repeatably observed public-cloud mapping `{type: "AccountKey", key: <value>}`
   as a version-scoped observed contract. It never probes alternate shapes.
   During verification, only the exact reviewed shape with an unequal key is a
   mismatch eligible for repair; metadata or credential-shape deviation blocks
   instead.
5. **App Service settings boundary.** The management API returns every
   application-setting name and value for each visible top-level app. The
   provider processes one app at a time with SDK body logging disabled. Only
   matched names, site identity, target key resource, and slot may leave this
   ephemeral boundary. Unmatched values, complete dictionaries, and their
   fingerprints never enter reports, plans, operations, output, or exceptions.
   The official update replaces the complete dictionary and has no reviewed
   conditional-write token.
6. **Persistent state boundary.** Plans, operations, logs, exceptions, and
   telemetry must never contain raw secret material or matching-session
   fingerprints. A private operation may contain versioned, per-operation salted
   SHA-256 recovery fingerprints only for reviewed high-entropy Azure-generated
   account keys. The `plan` command is preview-only by default; complete JSON
   reaches stdout or a private file only through an explicit output option.
   After validation and confirmation but before mutation, `rotate` exclusively
   writes one operation containing the exact secret-free plan and recovery
   progress to a UUID-scoped private platform user-state directory. Verified
   success removes it; failure or interruption retains it for resume.
   Local operation inspection accepts only canonical UUID-scoped entries,
   validates them through the exact private store and intent/progress contract,
   and projects no full plan, error message, resource ID, path, salt, or
   fingerprint.
7. **Managed plaintext dotenv boundary.** Only an existing regular non-symlink
   file explicitly selected with `--env-file` may receive raw keys. It must be
   owned by the current user, remain within the strict dotenv subset, and be
   replaced atomically while preserving its POSIX mode, owner, and group. Group
   or other read/write mode bits are the file owner's policy and never block or
   alter a plan. When those bits are present on POSIX, Azurator prints one local
   least-privilege notice to stderr. It does not persist the observation, modify
   permissions, emit it on Windows, or infer ACL and parent-directory access.
   The plan records the absolute path and selector names, never values, mode
   observations, or a reusable value digest. This mode deliberately provides no
   encryption at rest.
8. **Plaintext dotenv export boundary.** `export --out` may create one new
   private regular file after metadata-only discovery, complete secret-free
   selection validation, destination validation, display, and confirmation.
   Only installed reviewed key-reading providers may supply values. The
   destination is created atomically and exclusively with mode `0600`; existing
   or concurrently appearing paths are never replaced. Values are never sent to
   stdout, and cancellation or failure leaves no destination.
9. **Managed SOPS boundary.** SOPS and its configured key backends manage
   encryption at rest and recipient metadata. Azurator accepts only the reviewed
   SOPS 3.13.x dotenv status/decrypt/set command shapes. The source must be one
   current-user-owned regular non-symlink file no larger than 8 MiB and not
   writable by group or other users. Decrypted UTF-8 dotenv is limited to 1 MiB
   and remains in process memory. Azurator writes only ciphertext to disk.
10. **SOPS dotenv export boundary.** `export --sops-out` shares the plaintext
    export's discovery, selection, destination, display, confirmation, and
    key-provider checks. It validates the pinned SOPS executable before key
    retrieval, passes at most 1 MiB of canonical dotenv plaintext over stdin,
    and accepts no more than 8 MiB of ciphertext from stdout. It then decrypts that
    ciphertext through SOPS in memory and compares the exact assignment set and
    every value with a fresh process-local HMAC key. Only verified ciphertext is
    exclusively created at the destination with mode `0600`. Plaintext never
    enters a file or process argument. Cancellation, encryption or verification
    failure, and a destination race leave no destination.

## Primary threats and controls

### Secret disclosure through process inspection

Raw secrets are forbidden in CLI arguments. Streaming input avoids shell history
and normal process-list exposure. Documentation must not encourage command
substitutions that place plaintext in an argument.

### Secret disclosure through output or failures

Logs, exceptions, plans, operations, telemetry, and test snapshots must be passed
through a final redaction boundary. Providers must translate failures without
including request or response bodies that may contain keys. That translation
also covers Azure request-transport and response-transport exceptions; SDK
exception text is never propagated.
Retained-operation list/show output is built from an explicit summary model,
not by deleting fields from serialized operation JSON. It may show the bounded
error code but never the stored error message, embedded full plan, resource IDs,
binding paths, salt, or recovery fingerprints. Invalid entries are identified
only by their canonical directory UUID; their contents are never rendered.

### Secret disclosure through development build inputs

The repository may contain ignored private plans or explicit plaintext dotenv
files during local development. A raw `path:.` flake reference would copy the
whole working tree into a locally readable Nix store source path despite
`.gitignore`. Development commands therefore use the Git-aware `.` flake
reference, and the package derivation uses an explicit fileset limited to Python
package code, tests, and required build metadata. Ignored plans, dotenv files,
virtual environments, caches, documentation dependencies, and build output are
outside the package source boundary. Existing store snapshots remain until Nix
garbage collection.

### Correlation of values across runs

Raw input is converted immediately with a fresh random 256-bit HMAC key. The key
and derived session fingerprints are never persisted. Candidate comparisons use
the same per-process key and a constant-time equality function.

Azurator does not accept portable digest or persistent-HMAC input. Any future
proposal must remain limited to high-entropy Azure-generated keys, define a
versioned secret-store-backed construction for stored or shared sets, and keep
persistent and ephemeral HMAC keys separate.

Operations use a separate `sha256:v1` recovery construction. Each operation has
a fresh 256-bit salt, and the digest is domain-separated by resource ID and
slot. This prevents equality correlation between operations but does not make
the digest a secret: anyone holding both a candidate key and the operation
can test that candidate offline. The construction is accepted only because the
current providers expose Azure-generated high-entropy account keys; it must not
be generalized to passwords or low-entropy tokens. Recovery fingerprints are
never rendered and are compared in constant time.

### Over-broad or unsafe Azure operations

Every Azure operation uses the subscription explicitly selected and pinned at
login, unless the user supplies a one-command override. An omitted override
must never broaden into a multi-subscription scan. Metadata discovery does not
retrieve key values. Operation metadata can produce only a coverage lead for
provider research; it is not part of the executable inventory and
cannot authorize dynamically constructed calls. A provider must explicitly
define API versions, response shapes, slots, permissions, binding behavior,
and rotation semantics before it can retrieve or mutate.
The Foundry provider accepts only reviewed project and exact public-cloud
Storage or Azure OpenAI endpoint shapes, disables SDK HTTP logging, and renders
sanitized status-only failures rather than Azure response bodies.
Scriptable direct selection does not select a subscription: the complete ARM
ID embedded in each selector must match the already selected command scope.
Azurator resolves the ID and exact slot against the metadata-only inventory
before any candidate read and rejects partial, nested, unknown, duplicate, or
cross-subscription identities rather than guessing.

Automatic binding inspection means every installed reviewed Azure binding
provider. When `--skip-azure-bindings` is selected, none is constructed or
called, the structured report records `azure_binding_inspection: skipped`, and
the plan carries a confirmation-impact warning. A managed `--env-file` or
`--sops-file` is attached afterward as an explicit local binding. Saved-plan
and resume paths repeat the recorded mode rather than accepting a new
inspection choice.

### Unintended mutation

Discovery, matching, and planning are read-only. Mutation is isolated behind
`rotate`, a validated generated plan, current source-appropriate matching or
direct-selection inspection, drift checks, and explicit user confirmation.
`rotate --plan` revalidates an earlier private plan against a newly generated
snapshot. Flagless `rotate`, `rotate --select`, `rotate --env-file`, and
`rotate --sops-file` first generate and display that same plan from the current
inspection. Only after confirmation do shortcut modes keep that plan in memory;
cancellation or
validation failure before confirmation writes nothing. A shared 8 MiB
per-artifact bound applies to plan and operation serialization and private
loading. Before recovery-state creation or mutation, initial rotation
conservatively preflights its largest bounded operation state.
One private operation without usable key values is then created atomically and
exclusively before the first mutation. It embeds the exact plan and records a
pending step before every planned update, verification, or regeneration. Before
mutation it stores salted recovery fingerprints for both slots of each scheduled
account-key pair. Operation replacement flushes both file content and the parent
directory on platforms that support directory `fsync`; creation also flushes
each new private operation-directory entry through its parent. Verified
completion removes the operation and its UUID directory; a failed or
interrupted operation is retained for `rotate --resume OPERATION_ID`.
Processing stops on the first failed mutation. Because Azure key rotation is not
generally reversible, Azurator never claims rollback.

A match is not evidence of compromise. Output and plans use neutral terms such
as matched, selected, and scheduled for rotation. They must not assert that a
user-provided value was leaked or unsafe.

Azure cannot atomically regenerate a slot and update separate credential bindings. Plans
use a usable sibling slot as a temporary bridge: move and verify affected
bindings, regenerate the scheduled slot, then move and verify them on its new
value. If no sibling can bridge the transition, the plan reports an expected
interruption and requires explicit confirmation. When both slots are selected,
the plan consolidates bindings on one bridge, regenerates the other slot, moves
bindings to its new value, regenerates the bridge, and then returns every
binding originally attributed to the bridge slot to its new value. Bindings
without reviewed slot attribution remain on the new primary slot. It never
regenerates both together or treats incomplete discovery as proof that a slot
is free.
Immediately before each regeneration, Azurator re-reads every known managed
binding against the slot expected at that plan checkpoint. An unequal key in
the canonical reviewed credential shape is repaired and verified while the
regeneration step is already recorded pending; metadata drift,
credential-shape drift, or any other binding failure blocks before the Azure
key call.

Every managed update additionally receives the expected current key and its
replacement. A reviewed binding already storing the replacement completes as a
no-op, one storing the expected value may transition, and every third value
blocks as drift. App Service then copies the freshly read complete settings
dictionary and changes only exact selected names. Another actor can still alter
an unrelated setting between read and PUT, so affected plans require
confirmation and forbid concurrent settings edits or deployments. Re-reading
the selected names detects failed storage of Azurator's change, but it cannot
recover an unrelated concurrent value overwritten by the full PUT.

Plans distinguish `no-changes`, `ready`, `confirmation-required`, and `blocked`.
`no-changes` means complete inspection selected no key slots and is not
executable. `--yes` may acknowledge warnings on an executable plan but never
bypasses validation, scope, drift, missing permissions, or an operation
Azurator cannot complete.
Every warning carries an explicit typed impact and category. Plan state and
execution validation use that impact directly; warning code prefixes, suffixes,
and centralized code-name lists are not policy inputs.
Every emitted step is executable by Azurator. If changing a selected key would
require updating a known binding without a reviewed automatic update-and-verify
contract, planning blocks before mutation and emits no steps for that resource.
The dotenv-file provider is one such automatic contract: grouped aliases are
written in one atomic file replacement and all targeted assignments are re-read
and compared before the plan continues. This verifies the file, not a workload
that may have loaded it. Its recorded path resolves every parent component but
does not follow the final component, preventing a later parent-symlink retarget
from selecting a different file.
The SOPS dotenv-file provider uses the same expected-value transition and bridge
plan. It updates only a private encrypted temporary through `sops set
--value-stdin`, requires the result to remain SOPS-encrypted, compares selected
and unrelated assignment values with ephemeral HMAC fingerprints, checks the
source identity and ciphertext digest again, and then atomically replaces it.

### Plan tampering or staleness

Plans carry a schema version, tenant and subscription context, provider
contract versions, selection source, exact scheduled slots, optional dotenv
selectors and managed plaintext or encrypted source path, warnings, ordered steps, and precondition
digests. Initial saved-plan rotation revalidates the schema, tenant, subscription,
provider contracts, and complete secret-free planning snapshot; repeats
relevant matching with a fresh session key or direct-selection inspection
without token input; and rejects stale or manually altered plans. Shortcut
rotation validates the plan just produced by its current inspection. Streamed
dotenv values are deliberately not persisted as a digest. After confirmation,
the UUID-scoped mode-`0600` operation embeds that exact plan and an intent digest;
exclusive creation rejects a pre-existing target. Resume requires the exact
operation ID and embedded intent, validates completed-prefix progress, and
re-reads the exact reviewed key pair for every scheduled Storage or Cognitive
Services resource. A pending regeneration is complete only when the target
fingerprint changed and every sibling fingerprint remained unchanged. An
unchanged pair permits the explicitly confirmed resume to retry the one pending
slot; any sibling change blocks as drift. The same comparison runs after every
final SDK return or exception. The pinned Azure SDK policy owns transient retry
classification, counters, `Retry-After`, and backoff; Azurator does not add a
provider or executor retry loop and does not infer completion from a successful
HTTP return alone. An operation with no started step must repeat the source-
appropriate fresh matching, exact managed-file re-reading, or direct-selection
inspection.

Warning impact and category are strict plan fields. Execution rejects a plan
whose `no-changes`, `ready`, `confirmation-required`, or `blocked` state disagrees with those
impacts. Obsolete pre-alpha warning shapes are rejected rather than assigned a
default meaning.

Before Azurator publishes a compatibility boundary, schemas and provider
contracts remain at version `1` and may change in place. Strict model, plan,
provider, digest, and operation validation rejects artifacts from obsolete
pre-alpha shapes; no migration or permissive fallback is a supported recovery
path. Rotation also validates every recorded provider contract that is installed
for execution, including an inspection provider with no emitted step.

`operation list` and `operation show` perform only local model, intent-binding,
fingerprint-set, lifecycle, and progress validation. They do not construct
credentials or provider clients and do not query current Azure state. The
displayed source-appropriate resume command is therefore a safe next command,
not a promise that authentication, installed provider contracts, source
revalidation, permissions, or drift checks will pass. A mutation failure prints
that command only after the exact retained artifact passes the same local
operation validation.

### Plaintext leakage during managed dotenv updates

The plaintext dotenv mode is explicit and never presented as encrypted. Input
must be a current-user-owned regular non-symlink file with a maximum size of 1
MiB. The strict parser rejects duplicate selectors, malformed assignments,
inline comments, and NULs; it deliberately does not evaluate interpolation or
escapes. A generated Azure replacement must fit the canonical single-quoted
output form. One selector matching multiple Azure slots blocks planning. The
recorded absolute path resolves its parent chain without following the final
component. Updates preserve unmatched assignments, each original line ending,
and the source POSIX mode, owner, and group. They use a same-directory private
temporary, flush it, atomically replace the unchanged target, flush the parent
directory where supported, and then re-read every targeted assignment using
constant-time comparison.

On POSIX, group or other read/write mode bits cause exactly one stderr notice
per command: `Warning: The dotenv file has broad permissions. Consider restricting access to the minimum required.`
This is a best-effort least-privilege hint, not a security verdict or execution
precondition. It is deliberately absent from structured reports, plans, and
fresh-plan comparison. Azurator does not evaluate Windows ACLs, extended ACLs,
or parent-directory permissions through this notice.

The absolute path and selector names are sensitive metadata in the private plan.
Raw file content, old/new values, whole-file digests, and session fingerprints
are absent from plans and operations. A host process with access to the file can
still read its keys, and a running application may retain an old value until it
reloads or restarts. Atomic replacement prevents partial output but cannot
serialize a non-cooperating editor or deployment process; the managed file must
not be changed concurrently with rotation. A concurrent writer can make
verification fail or can have its edit replaced. Azurator does not claim
otherwise.

### Plaintext leakage during dotenv export

Export is an explicit bootstrap path, not a discovery output format. `--out` is
required and stdout is never a secret sink. Before any key-returning call,
Azurator resolves the existing parent while preserving the final component,
rejects an existing destination, validates every picker-, repeatable-`--select`-,
or `--all`-selected resource/slot/selector mapping against the complete metadata
inventory and installed reviewed providers, displays the mapping plus a
plaintext warning, and asks for confirmation unless `--yes` was given. `--all`
means every retrievable slot displayed by those providers in the one selected
subscription, not every Azure secret.

After confirmation, the exact reviewed pair for each selected resource is read
once and only selected slots are retained in the canonical single-quoted dotenv
document. The document is limited to 1 MiB and must be valid UTF-8. A
same-directory mode-`0600` temporary file is flushed, then linked exclusively
to the destination and the parent directory is flushed where supported.
Cancellation, incomplete or noncanonical provider output, a key outside the
dotenv contract, retrieval failure, write failure, and a destination race all
leave no destination. Export does not merge, append, overwrite, create a plan
or recovery operation, encrypt content, or infer application-specific selector names.

The resulting file is plaintext at rest and becomes the user's responsibility.
Its deterministic selectors identify provider, resource name, and slot, with a
numeric suffix if names collide. A later `--env-file` workflow may manage it,
but export itself does not rotate a key, inspect bindings, or verify that any
workload reads the file.

### Plaintext leakage during SOPS dotenv export

Encrypted export retains the same complete secret-free intent and confirmation
boundary but requires explicit `--sops-out`; Azurator never infers encryption
from a filename. Exactly one of `--out` and `--sops-out` is accepted. After
confirmation, the pinned SOPS executable is validated before Azure key
retrieval. The canonical dotenv document is limited to 1 MiB and is sent to
`sops encrypt` through stdin with an explicit destination filename override and
dotenv input/output types. It is never written to a temporary file, ordinary
process argument, stdout, log, exception, plan, or operation.

Azurator accepts no more than 8 MiB of ciphertext, passes that ciphertext to
`sops decrypt` over stdin, and keeps the resulting plaintext in memory. It
strictly parses both dotenv documents and compares their complete selector sets
and values with a fresh ephemeral HMAC key. Formatting changes are harmless;
missing, added, duplicated, empty, or changed assignments fail closed. Only
verified ciphertext reaches the same exclusive mode-`0600` destination-creation
boundary. Cancellation, SOPS failure, round-trip mismatch, write failure, and a
destination race leave no destination.

SOPS selects creation rules, recipients, and encryption backends from its own
configuration. Successful verification therefore requires the invoking user to
have both encryption configuration and immediate decrypt access. A compromised
SOPS executable, configured backend, or host can observe plaintext and remains
outside Azurator's protection boundary.

### Decrypted-content leakage during managed SOPS updates

The implemented adapter accepts SOPS-encrypted dotenv only. It invokes SOPS
without a shell and with explicit input and output types. Key replacements are
JSON strings sent through `--value-stdin`; stderr and failed command output are
discarded and translated to fixed errors. Decryption output exists only in
memory and passes through the same strict dotenv parser and ephemeral HMAC
matching boundary. No decrypted temporary file exists.

Updates begin from a descriptor-bound ciphertext snapshot. SOPS modifies a
mode-`0600` encrypted temporary in the source directory. Before commit, Azurator
requires SOPS encrypted status, verifies every selected value, compares every
unselected assignment value through process-local HMAC fingerprints, and
rechecks the original file identity, metadata, and ciphertext digest. It flushes
the temporary, preserves source mode and ownership, atomically replaces the
source, and flushes the parent where supported. Any failure before replacement
leaves the source unchanged. A crash after replacement but before progress is
recorded is safely handled by the normal expected-or-replacement no-op contract
on resume.

Azurator trusts the reviewed SOPS operation to retain encryption recipients. It
does not parse or rewrite SOPS metadata itself. A compromised SOPS executable,
identity backend, or host remains outside the protection boundary.

## Accepted limitations

- Azure has no global API for every secret. Discovery covers only resource
  types implemented by the installed reviewed providers.
- Azurator has no global rotation lock. Non-overlapping operations may run in
  parallel, but concurrent execution of the same operation ID, operations
  sharing an Azure account resource, or operations managing the same plaintext
  or SOPS dotenv file are unsupported. Drift checks reduce stale-state risk but
  do not close the read-before-mutation race or coordinate across hosts.
- Credential-binding coverage is limited to installed reviewed providers.
  Configuration outside that coverage can leave workloads unable to
  authenticate after rotation.
- Azurator can update and verify only the stored credential of reviewed Foundry
  project `AzureStorageAccount`/`AccountKey` and `AzureOpenAI`/`ApiKey`
  connections. It cannot test workloads that may use them, and it does not
  inspect `AzureBlob`/container connections, account-level Foundry connections,
  or non-Foundry key configurations.
- App Service coverage includes exact whole application-setting values on
  visible top-level apps only. It excludes deployment slots, the separate
  connection-string collection, embedded keys, Key Vault references, and apps
  the current principal cannot enumerate or read. Settings updates replace the
  complete dictionary, restart the app, and can overwrite a concurrent settings
  change because the reviewed API exposes no conditional-write token. Azurator
  verifies stored selected names, not workload health.
- Azurator verifies managed dotenv assignments on disk but does not reload,
  restart, or health-check applications that may consume them. The explicit
  mode stores keys as plaintext at rest. Atomic replacement does not coordinate
  with non-Azurator writers, so the file must not be edited concurrently with
  rotation.
- Azurator verifies managed SOPS dotenv assignments after decryption but does
  not reload or health-check their consumers. It requires SOPS 3.13.x and a
  working user-configured identity backend. It does not create recipients,
  rotate encryption identities, or merge documents.
- An `export --out` dotenv file is plaintext at rest. Azurator exclusively creates and
  reports the file but cannot prevent later permission changes, accidental
  source-control inclusion, copying, or use by unrelated processes.
- An `export --sops-out` file requires a user-configured SOPS creation rule and
  decrypt identity. Azurator does not manage recipients, merge or replace an
  existing document, or hide dotenv selector names and SOPS metadata that remain
  visible in ciphertext.
- The current Foundry data-plane endpoint allowlist covers Azure public cloud;
  unsupported cloud endpoint suffixes are reported as inspection gaps.
- Microsoft does not currently publish the Foundry data-plane `AccountKey`
  discriminator that Azurator observes in public cloud. A service or SDK shape
  change therefore stops inspection and mutation until the observed contract is
  reviewed again; Azurator does not attempt compatibility aliases.
- If no usable alternate exists, a consumer may be disconnected between key
  regeneration and its configuration update.
- If binding inspection is incomplete, continuity cannot be guaranteed even
  when no binding was discovered for a slot.
- Azure's synchronous regeneration contracts expose no cross-request
  idempotency token. The SDK may therefore send more than one regeneration
  request for one planned slot after transient failures. Azurator deliberately
  promises a verified final state rather than exactly one HTTP attempt: managed
  bindings remain on the bridge until the SDK finishes, intermediate target
  values are never distributed, and only a changed target with unchanged
  siblings completes the step. Resume uses the same state check, but neither it
  nor the SDK can distinguish an extremely delayed request from a concurrent
  external actor.
- Python and generated Azure SDKs expose returned values as immutable strings,
  so Azurator can minimize references and erase owned mutable buffers but cannot
  guarantee physical zeroization of every interpreter or SDK memory copy.
- A host compromise can observe in-memory plaintext, session keys, Azure CLI
  tokens, or SOPS identities; Azurator does not defend against a fully compromised
  execution environment.
- Resource identifiers and structured document paths can reveal sensitive
  operational context even when no key values are stored. Scriptable
  `--select` intentionally places one resource ID and slot, but never a key
  value, in ordinary process arguments.
- Local retained-operation inspection deliberately reveals operation UUIDs,
  subscription scope, resource names/slots, progress, and bounded error codes
  to the user who can already access the private state directory. It is not an
  audit history: successful operation state remains automatically deleted.

## Review gates

The Storage/Cognitive/Foundry/App-Service/plaintext-dotenv/SOPS-dotenv rotation slice and private plaintext or SOPS dotenv
export are limited to their reviewed plan, file, failure, redaction, provider,
and drift contracts. Any new rotating provider, credential-binding category, workload
verifier, or secret output must pass the same review and negative-path tests
before registration. No live Azure mutation belongs in automated tests.

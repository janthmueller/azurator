---
type: Provider Contract Research
title: App Service application-settings credential bindings
description: Official API contract, exclusions, mutation behavior, tests, and evidence for the App Service binding provider.
tags: [research, azure, app-service, bindings]
status: implemented
---

# App Service application-settings credential-binding contract

This document records the contract used by Azurator's App Service
application-settings provider. The disposable live-test fixture and fake
orchestration checks are implemented, and the live contract has been exercised.
Any future live run still requires fresh approval.

## Decision

App Service application settings are an installed reviewed binding. Like the
Foundry provider, they are inspected across the selected subscription by
default. "All Azure bindings" means all installed reviewed Azure binding
providers, not universal Azure coverage.

There is an important secret-boundary difference. Foundry exposes structured
connection metadata, so Azurator can link a connection to a selected account
before retrieving its credential. A raw App Service application-setting key
has no target-resource relationship. A reviewed Storage Shared Key connection
string supplies an account name but still requires key comparison. Finding
either shape therefore requires retrieving the complete settings dictionary of
every site, inspecting each value, and discarding everything that does not
match.

That broader ephemeral boundary is acceptable for binding inspection if
it is explicit in the threat model, SDK body logging remains disabled, values
are processed one site at a time, and unrelated values never enter models,
output, exceptions, plans, or operations. Python cannot guarantee physical
erasure of immutable strings or already decoded SDK response buffers, so the
documentation must not claim that discarded values are memory-zeroized.

The reviewed global behavior is intentionally small:

```text
default                  inspect every installed Azure binding provider
--skip-azure-bindings    inspect no Azure bindings
```

There are no provider allowlists, denylists, or App Service site filters in the
initial contract. App Service enumerates every visible top-level site in the
selected subscription. `--skip-azure-bindings` omits Foundry, App Service, and
every other installed Azure binding provider together. It does not disable an
explicitly managed `--env-file` or `--sops-file`, because those files are local
bindings selected by the user. The enabled or skipped mode is recorded in the
plan and repeated during fresh validation and resume.

## Official Azure contract

The provider uses the official Python management SDK rather than calling ARM
directly:

```text
azure-mgmt-web >= 11.0.1, < 11.1
WebSiteManagementClient API version 2025-05-01
```

Version 11.0.1 supports Python 3.10 through 3.14 and generates its Web Apps
operations from App Service API `2025-05-01`.

### Read

```text
POST /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}
     /providers/Microsoft.Web/sites/{name}/config/appsettings/list
     ?api-version=2025-05-01
```

Python SDK operation:

```python
client.web_apps.list_application_settings(resource_group_name, name)
```

The result is one `StringDictionary`. Its `properties` member is nullable and,
when present, is the complete `dict[str, str]` returned by the service. A normal
site metadata read deliberately does not return application settings because
they can contain sensitive information.

### Update

```text
PUT /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}
    /providers/Microsoft.Web/sites/{name}/config/appsettings
    ?api-version=2025-05-01
```

Python SDK operation:

```python
client.web_apps.update_application_settings(
    resource_group_name,
    name,
    StringDictionary(properties=complete_settings),
)
```

Microsoft describes this operation as replacing the application's settings.
The request therefore has to contain the complete dictionary. Azure CLI's
`az webapp config appsettings set` convenience command implements the same
read, client-side merge, and full update sequence. It is not a stronger
single-setting server operation.

The reviewed `2025-05-01` OpenAPI operation declares no ETag response property,
`If-Match` parameter, or other conditional-write token. Azurator must not send
an undocumented conditional header and assume that it prevents lost updates.

### Runtime effect

App Service exposes application settings to the workload as environment
variables. Microsoft documents that adding, removing, or editing them triggers
an app restart.

The bridge algorithm therefore normally causes two configuration updates for
each affected app and key resource:

1. move matching settings to the sibling key;
2. regenerate the selected key;
3. move those settings to the regenerated key.

Each configuration update can restart the app. SDK retries can also cause more
than one service-side attempt, so Azurator must not promise an exact restart
count. Re-reading the stored setting proves only that Azure retained the new
value. It does not prove that the workload restarted successfully or can reach
the target service.

### Permissions

The minimum relevant management actions are:

```text
Microsoft.Web/sites/read                 # default subscription-wide enumeration
Microsoft.Web/sites/config/list/action
Microsoft.Web/sites/config/write
```

The site read action is needed for subscription-wide enumeration. The config
list action permits listing security-sensitive site configuration such as
application settings. The config write action permits updating site
configuration. Broader built-in roles such as Website Contributor also contain
sufficient access, but Azurator documents the exact actions rather than
requiring a broad role.

Deployment slots have separate list and write actions and separate SDK
operations. They are outside the first contract.

## Implemented product contract

### Enumeration

The provider enumerates top-level sites visible in the selected subscription
through the pinned Web Apps SDK, then lists application settings one site at a
time. It ignores deployment slots and nested configuration resources because
they are outside this first contract. Enumeration or any individual settings
read failure makes inspection incomplete and blocks planning.

The provider uses Azure public ARM through the injected SDK client factory.
Supporting another cloud requires a separate endpoint and SDK-scope review.

### Inspection

After Azurator has selected key resources and ephemerally loaded their reviewed
two-slot values, it inspects each discovered site once. For every application
setting it compares a raw value against each selected account key using the
process-local HMAC and constant-time equality path. For a reviewed Storage
Shared Key connection string it first restricts candidates to the named
Storage account, then compares only the parsed `AccountKey`. It finishes and
releases one site's response before requesting the next site. The shared
grammar and mutation rules are defined in
[Storage connection-string research](storage-connection-string-bindings.md).

Inspection must:

- reject a null or malformed `properties` object;
- reject non-string names or values;
- treat setting names as exact, case-sensitive dictionary keys;
- reject one value that ambiguously matches more than one selected account
  slot;
- group aliases in the same site that match the same resource and slot into one
  credential binding;
- discard all raw setting values and temporary fingerprints before returning;
- return fixed, secret-free warnings for HTTP and transport failures.

Only matched setting names enter the plan. Unmatched names and all values stay
out of plans, operations, JSON output, terminal output, and exceptions.

An inspected app with no exact matches is a valid zero-binding result. A
complete scan can claim only that no exact match was found in the visible App
Service sites and shapes supported by this provider.

If an enabled provider cannot enumerate sites or read one site's
settings, its inspection is incomplete and planning blocks. It must not degrade
to a successful no-match. Explicitly skipping all Azure bindings is different:
the plan can remain executable with the existing confirmation warning.

### Deliberately excluded shapes

The provider compares exact raw keys and parses only the reviewed Azure
Storage Shared Key connection-string grammar. It does not parse or rewrite:

- malformed, SAS, `UseDevelopmentStorage=true`, identity-based, or otherwise
  unsupported Storage connection strings;
- JSON or another structured value containing a key;
- App Service's separate connection-string collection;
- a Key Vault reference such as `@Microsoft.KeyVault(...)`;
- deployment-slot settings;
- settings outside the enumerated sites;
- configuration in a process, container image, repository, pipeline, or
  external secret store.

These exclusions must be named in the plan's binding-coverage message. Another
structured value requires its own documented grammar and exact update and
redaction review. It must not be added as permissive substring replacement.

### Secret-free credential binding

One binding represents all aliases in one site that currently map
to the same Azure resource and key slot. Its persisted data may contain:

- the exact site ARM ID;
- the site name;
- the matched application-setting names;
- the target Azure account resource ID and slot;
- the App Service binding provider contract identifier.

It must not contain the complete settings dictionary, any setting value, or a
fingerprint of an unrelated setting. App-setting names and ARM IDs remain
sensitive operational metadata and inherit the existing private plan and
operation boundaries.

## Transition contract

The managed-binding update interface receives both the expected current key and
the replacement key. This is necessary because any non-empty application
setting remains structurally valid after an external change. Replacing it
blindly could overwrite an intentional move to another credential or identity
mechanism.

The executor derives the expected slot from the binding's original slot plus
preceding update steps. Raw values remain inside nested key-provider callbacks
and are never persisted.

For raw values, the resulting transition is:

1. read the current binding value;
2. compare it with the expected current key;
3. allow a no-op if it already equals the requested replacement;
4. block as binding drift if it equals neither;
5. apply the replacement;
6. re-read and verify the replacement.

This expected-to-replacement contract applies to every managed binding. It
protects Foundry and dotenv updates as well as App Service. It is not an App
Service-specific fallback or retry loop.

For a reviewed Storage connection string, the same states apply to its parsed
`AccountKey`. The account name and resource type must still match, and an
update replaces only the exact key span while preserving all other fields.

Pending-operation reconciliation then remains deterministic:

- replacement already present means the ambiguous update completed;
- expected value still present permits the recorded update to run;
- any third value blocks as drift.

## Full-dictionary concurrency boundary

Expected-to-replacement checking protects the selected settings. It cannot make
the service's full-dictionary PUT atomic with respect to unrelated settings.

The provider can read the current dictionary, validate the selected entries,
copy it, change only those entries, replace it, and re-read it. However, another
deployment or operator can update an unrelated setting between Azurator's read
and PUT. Because the official operation provides no reviewed conditional-write
token, Azurator could overwrite that concurrent change without detecting it.

An executable plan therefore needs a confirmation warning that:

- the complete dictionary is replaced;
- no app-setting deployment or edit may run concurrently for the selected
  site;
- separate Azurator operations sharing one App Service site are unsafe even if
  they rotate different Azure resources;
- Azurator does not provide rollback for an overwritten or failed update.

This limitation is displayed before an affected app is mutated, including when
that app was found by the default scan. The provider is not presented as safe
for an uncontrolled concurrent deployment pipeline.

## Plan and execution behavior

Default binding inspection and the global `--skip-azure-bindings` choice must
compose with every current selection source:

- interactive key-slot selection;
- repeatable `--select 'ARM_RESOURCE_ID#SLOT'`;
- streamed dotenv matching for a saved plan;
- a managed plaintext dotenv file;
- a managed SOPS-encrypted dotenv file.

The existing `azure_binding_inspection: enabled|skipped` plan field records the
resolved choice so saved-plan validation, direct rotation, and resume repeat
the same behavior. App Service adds no provider-specific selection or scope
field.

Fresh-plan validation must enumerate the current visible sites again and
require the same matched setting bindings before initial mutation. Resume uses the recorded plan
and existing pending-step reconciliation, while still applying normal account,
scope, provider-version, source, and drift validation.

Every update and verification remains an Azurator-executable plan step. The
human plan identifies the app and setting names without displaying values. It
includes, per affected app:

- that application-setting replacement triggers a restart;
- how many planned configuration updates target that app;
- that workload health is not checked;
- the full-dictionary concurrency warning;
- the exact binding-coverage boundary.

`--yes` may acknowledge those executable warnings. It cannot bypass an
incomplete site inspection, malformed response, binding drift, or missing
permission.

## Code mapping

The implementation fits the existing architecture:

- `azurator/clients.py`
  - defines narrow Web Apps protocols and
    `AzureClientFactory.web_site_management()`;
- `azurator/providers/app_service_settings.py`
  - owns site enumeration, full-dictionary inspection and transition,
    verification, API errors, and redaction;
- `azurator/providers/base.py`
  - defines managed updates in terms of expected and replacement values;
- `azurator/matching.py`
  - runs every installed automatic Azure binding provider while candidate HMACs
    are still alive;
  - retains the distinction between the global explicit skip and an
    incomplete enabled-provider inspection;
- `azurator/planning.py`
  - preserves the bridge algorithm and adds exact App Service warnings;
- `azurator/execution.py`
  - derives the expected pre-update slot and passes both ephemeral values;
- `azurator/cli.py`
  - requires no provider-specific selection flag; `--skip-azure-bindings`
    remains the only Azure binding control;
- `azurator/presentation.py`
  - renders App Service settings as binding records, restarts, and explicit
    coverage rather than generic provider jargon.

The App Service provider is registered as an automatic binding scanner. The
plaintext and SOPS dotenv providers remain explicit and are not part of the
automatic Azure binding set controlled by `--skip-azure-bindings`.

## Test strategy

Automated tests use fake SDK clients and have no live subscription dependency.

### Enumeration and contract tests

- default mode enumerates visible sites and inspects each exactly once;
- `--skip-azure-bindings` makes no App Service or Foundry binding call and emits
  the existing explicit coverage
  warning;
- an explicit local plaintext or SOPS dotenv binding remains included while
  Azure bindings are skipped;
- an enabled provider's partial or failed scan blocks planning;
- null, malformed, and non-string dictionaries fail closed;
- HTTP, request-transport, and response-transport errors become fixed messages;
- the SDK is constructed with API `2025-05-01` and logging disabled.

### Matching and redaction tests

- raw Storage and Cognitive key values map to the correct slots;
- aliases are grouped without duplicate update steps;
- reviewed Storage Shared Key connection strings match only their named account
  and preserve all fields except `AccountKey` during updates;
- unrelated values, Key Vault references, unsupported embedded values, and
  JSON do not match;
- an ambiguous key value blocks;
- sentinel secrets never appear in models, JSON, output, warnings, exceptions,
  operation projections, or test snapshots.

### Mutation and recovery tests

- only matched names change and unrelated settings are preserved from the
  provider's read snapshot;
- expected, replacement, and third-value states follow the transition contract;
- the complete dictionary is sent once per SDK invocation;
- SDK retries remain SDK-owned;
- update-returned-error followed by a successful re-read resumes without
  another update;
- an unapplied update resumes only from the still-expected value;
- a third value blocks without a PUT;
- verification failure retains one raw-key-free operation;
- successful completion removes it.

### CLI and planning tests

- all current selection sources compose with default Azure binding inspection
  and the global skip;
- saved plans and fresh validation preserve the exact enabled or skipped mode;
- `--skip-azure-bindings` does not disable an explicit plaintext or SOPS dotenv
  binding;
- restart, concurrency, workload, and reviewed-value coverage are clear in human
  and JSON output;
- `--yes` accepts warnings but not blocking states;
- plan and operation artifact size limits still apply.

## Disposable live-test extension

The Bicep fixture adds one tagged App Service site on an F1 plan. Microsoft
lists F1 as a free experimentation tier with no SLA. The fixture contains no
deployed workload and seeds only reviewed application settings through ARM
expressions:

- one raw Storage `key1` setting;
- one alias of that Storage key to test grouped replacement;
- one documented Storage Shared Key connection string using that same key to
  test representation-preserving grouped replacement;
- one raw Azure OpenAI `Key1` setting;
- one unrelated non-secret setting that must survive both full replacements.

The fixture does not output any setting value. `Microsoft.Web` registration is
a reviewed prerequisite of `live-test-up`, and resource-group teardown removes
the plan and site.

The implemented fixture declares the plan and site with the published, Bicep-
typed resource API `2024-11-01`. That deployment-only choice is independent of
the product provider's pinned settings read/write API `2025-05-01`.

The guided E2E harness requires the default scan to find the tagged site. It
rotates only reviewed fixture resources, verifies the new bindings through
secret-free structured output, and tears down only after a verified run. This
tests stored configuration transitions and recovery, not workload health.

Deploying the F1 fixture and running a live rotation still require fresh user
approval immediately before each Azure mutation.

## Implementation record

- [x] Harden `ManagedBindingProvider` to an expected-to-replacement
      transition and update Foundry, dotenv, executor, and tests.
- [x] Add the pinned App Service SDK client boundary.
- [x] Record default automatic Azure binding inspection and the global
      `--skip-azure-bindings` choice in reports and plans.
- [x] Add default site enumeration.
- [x] Inspect reviewed setting values while ephemeral candidate HMACs are alive.
- [x] Add App Service update, re-read verification, errors, and redaction.
- [x] Persist and revalidate secret-free App Service bindings in plan version
      `1` through the existing binding models.
- [x] Add precise restart, concurrency, workload, and coverage presentation.
- [x] Update product behavior, the threat model, provider contracts, and public
      coverage documentation before enabling the new provider.
- [x] Run Ruff, Pyright, full pytest coverage, Nix checks, and docs checks.
- [x] Extend the disposable fixture and fake-command harness tests.
- [x] Exercise the F1 contract in separately approved live runs and confirm
      tagged teardown.
- [x] Add the reviewed Storage Shared Key connection-string value shape and
      extend the fixture plus non-live harness contract.
- [x] Exercise the connection-string fixture in a separately approved live run.

## Sources

- [List application settings, REST API 2025-05-01](https://learn.microsoft.com/en-us/rest/api/appservice/web-apps/list-application-settings?view=rest-appservice-2025-05-01)
- [Update application settings, REST API 2025-05-01](https://learn.microsoft.com/en-us/rest/api/appservice/web-apps/update-application-settings?view=rest-appservice-2025-05-01)
- [App Service 2025-05-01 OpenAPI specification](https://github.com/Azure/azure-rest-api-specs/blob/main/specification/web/resource-manager/Microsoft.Web/AppService/stable/2025-05-01/openapi.json)
- [Python Web Apps operations](https://learn.microsoft.com/en-us/python/api/azure-mgmt-web/azure.mgmt.web.operations.webappsoperations?view=azure-python)
- [`azure-mgmt-web` 11.0.1](https://pypi.org/project/azure-mgmt-web/11.0.1/)
- [Configure App Service application settings](https://learn.microsoft.com/en-us/azure/app-service/configure-common?tabs=portal)
- [Service Connector permission requirements](https://learn.microsoft.com/en-us/azure/service-connector/concept-permission)
- [Azure CLI client-side application-setting merge](https://github.com/Azure/azure-cli/blob/dev/src/azure-cli/azure/cli/command_modules/appservice/custom.py#L607-L672)
- [App Service pricing](https://azure.microsoft.com/en-us/pricing/details/app-service/windows/)

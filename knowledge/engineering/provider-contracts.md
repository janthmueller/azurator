---
type: Engineering Contract
title: Provider contract discipline
description: Canonical Azure adapter, version, capability, failure, and retry rules.
tags: [engineering, providers, azure, contracts]
status: stable
---

# Provider contract discipline

Providers are internal authorization and integration boundaries. Azure provider
metadata can suggest a resource worth researching, but it never authorizes a
key-returning or mutating request. Only an installed, reviewed provider may
retrieve candidates, regenerate a slot, or update a credential binding.

## Canonical adapters

- Implement one documented request and response shape for each operation.
- Prefer the published Azure contract and pin the REST API plus compatible SDK
  range that defines it.
- If public documentation demonstrably lags repeatable service behavior, accept
  at most one explicit observed contract. Scope it to the reviewed cloud,
  endpoint, API version, and SDK range, document the discrepancy, and cover it
  with positive, negative, and redaction tests using secret-free fixtures.
- An observed contract is one strict adapter, not a fallback. Never probe field
  aliases, endpoint forms, credential shapes, or request variants until one
  works. Unknown shapes fail closed before mutation.
- Treat isolated live metadata as evidence. It does not by itself define a
  security or capability field.
- Optional presentation metadata may have a neutral default only when its
  absence cannot affect scope, identity, secret handling, binding attribution,
  permission requirements, or mutation behavior.

## Pinned Azure surfaces

| Integration | Python package range | API contract |
| --- | --- | --- |
| Storage Account discovery and keys | `azure-mgmt-storage>=25.1,<25.2` | Management API `2025-08-01` |
| Cognitive Services discovery and keys | `azure-mgmt-cognitiveservices>=14.1,<14.2` | Management API `2025-06-01` |
| Foundry project discovery and connection management | `azure-mgmt-cognitiveservices>=14.1,<14.2` | Management API `2025-06-01` |
| Foundry connection credential inspection | `azure-ai-projects>=2.3,<2.4` | Public-cloud data-plane API `v1` |
| App Service application settings | `azure-mgmt-web>=11.0.1,<11.1` | Management API `2025-05-01` |

The Foundry data-plane dependency additionally constrains
`openai>=2.8,<3`. A clean pip resolution with OpenAI 3.x leaves the
`azure-ai-projects` 2.3 SDK's direct `httpx` import unsatisfied, while the
reviewed OpenAI 2.x line supplies that runtime dependency. Clean wheel and
minimum-runtime-dependency CI jobs guard this compatibility boundary.

The published Foundry data-plane `v1` credential union omits the Storage
`AccountKey` discriminator even though the public-cloud service repeatably
returns the exact `{type: "AccountKey", key: <value>}` mapping. Azurator accepts
only that shape as the single observed contract, scoped to public-cloud
data-plane `v1` and `azure-ai-projects>=2.3,<2.4`. A different shape fails
closed before mutation; no aliases or alternate requests are attempted.

The App Service contract and evidence are described in
[App Service binding research](../research/app-service-bindings.md).

## Capability fields

Capability metadata fails closed unless the pinned contract explicitly defines
its missing or null meaning.

- Storage API `2025-08-01` defines `allowSharedKeyAccess: false` as disabled and
  `true` or `null` as enabled.
- Cognitive Services API `2025-06-01` exposes a nullable disabling predicate.
  Only `disableLocalAuth: true` disables keys. `false` or `null` means enabled.
  A missing account-properties object still fails closed.
- Missing required resource identity fields never receive presentation
  defaults and the resource is not admitted to a key-returning path.

If documentation and repeatable service behavior disagree, record one explicit
official-or-observed product decision. Ignore redundant fields rather than
adding branches that guess the intended security state.

## Failure and retry behavior

Provider boundaries translate Azure HTTP, request-transport, and
response-transport failures into fixed secret-free warnings or operation
errors. SDK exception text and response bodies never reach user output.

Key regeneration delegates transient classification, retry counts,
`Retry-After`, and backoff to the pinned Azure SDK policy. Azurator adds no
provider or executor retry loop. After the SDK finally returns or raises, the
executor re-reads the exact reviewed key pair and decides success from the
verified final state.

Azurator-owned persisted schemas and provider contract identifiers remain at
version `1` until the project deliberately publishes a compatibility boundary.
Current pre-alpha shapes replace older ones and strict validation rejects stale
artifacts instead of guessing, migrating, or accepting aliases.

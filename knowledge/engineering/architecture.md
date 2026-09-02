---
type: Software Architecture
title: Azurator architecture
description: Module boundaries, dependency direction, provider interfaces, and placement rules.
tags: [engineering, architecture]
status: stable
---

# Azurator architecture

Azurator is one flat-layout Python package and one standalone CLI. Its core is
provider-oriented, but “provider” is an internal adapter and contract term.
Public product language distinguishes key resources from credential bindings.

## Main source tree

```text
azurator/
├── auth.py
├── clients.py
├── cli.py
├── composition.py
├── discovery.py
├── execution.py
├── exporting.py
├── files.py
├── fingerprints.py
├── inputs.py
├── key_map.py
├── matching.py
├── models.py
├── operation.py
├── planning.py
├── presentation.py
├── refreshing.py
├── sops.py
├── workflows.py
└── providers/
    ├── app_service_settings.py
    ├── base.py
    ├── builtin.py
    ├── cognitive_services.py
    ├── dotenv_file.py
    ├── foundry_connections.py
    ├── resource_ids.py
    ├── sops_dotenv_file.py
    └── storage.py
```

Production code lives directly in `azurator/`, with no `src/` wrapper.

## Responsibilities

- `cli.py` owns commands, option validation, confirmation, and terminal
  interaction.
- `composition.py` constructs authenticated application services and injects
  credentials and Azure clients.
- `workflows.py` coordinates command-independent planning and fresh
  reconstruction.
- `presentation.py` owns Rich output and user-facing labels.
- `planning.py` remains mutation-free.
- `execution.py` owns guarded plan execution and provider orchestration.
- `operation.py` owns the single transient secret-free intent and recovery
  artifact.
- `files.py`, `inputs.py`, `fingerprints.py`, and `sops.py` own the reviewed
  local secret and persistence boundaries.
- `key_map.py` projects confirmed matches into the strict reusable secret-free
  mapping artifact and validates that artifact when it is loaded.
- `refreshing.py` owns strict all-or-nothing plaintext and SOPS dotenv refresh
  from current Azure values without rotation or recovery state.
- `providers/` hides Azure or local discovery, matching, transition,
  verification, API-version, response-shape, and permission contracts behind
  explicit interfaces.

## Dependency direction

Models and planning policy must not construct credentials or Azure clients.
Business logic remains independent of `azure-cli-core`. Credentials are created
at the command boundary and injected through client factories. Presentation may
consume product models but cannot decide execution policy from warning prose or
provider-name conventions.

The provider interface is an authorization boundary, not a public catalog
concept. Only registered and reviewed providers may retrieve or regenerate key
values or update bindings. A provider contract is canonical and fail-closed. It
does not probe aliases or request variants until something works.

## Credential composition

The standalone command remains independent of `azure-cli-core`. Credentials are
constructed at the command boundary and injected through `AzureClientFactory`.
`AzureCliCredential` is the default when no Azurator authentication record
exists. Browser, device-code, and `EnvironmentCredential` flows are optional
adapters.

Every `AzureCliCredential` uses a 30-second Azure CLI subprocess timeout. This
widens one SDK token-acquisition wait and is not an Azurator retry loop. Native
browser and device-code flows use Azure Identity's persistent token cache; the
Azurator authentication record itself contains account and subscription
metadata, not access or refresh tokens.

One validated subscription remains the command scope. A requested CLI option
takes precedence over its documented environment-variable equivalent. A
previously validated subscription UUID may remain usable when only its display
name cannot be refreshed, but no degraded path may infer or broaden tenant or
subscription scope.

## Placement rules

- Put terminal parsing and prompts in `cli.py` and rendering in
  `presentation.py`.
- Put orchestration that must be shared by `plan` and shortcut `rotate` in
  `workflows.py`.
- Put pure plan construction and typed plan-state policy in `planning.py`.
- Put external mutation ordering and recovery checkpoints in `execution.py`.
- Put service-specific Azure contracts in the owning provider.
- Put reusable safe file and secret-input primitives in their dedicated modules,
  not in a provider or CLI branch.
- Keep fake providers and mocked clients in tests. Automated tests never depend
  on a live Azure subscription.

The complete product semantics are in
[product behavior](../product/behavior.md), and security-sensitive dependency
constraints are authoritative in the [threat model](../security/threat-model.md).
Provider adapter rules are in
[provider contract discipline](provider-contracts.md).

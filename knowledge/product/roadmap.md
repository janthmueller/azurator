---
type: Product Roadmap
title: Azurator roadmap
description: Candidate product directions and the review gates that precede them.
tags: [product, roadmap]
status: draft
---

# Azurator roadmap

This document records candidate directions. It is not a promise that every item
will ship or that a proposed command or contract is final.

## Product guardrails

- Keep metadata discovery separate from key retrieval and mutation.
- Expand one documented key-resource or credential-binding contract at a time.
- Keep every generated plan fully executable by Azurator.
- Prefer Microsoft Entra ID where practical. Azurator remains focused on shared
  keys that applications still need to store and rotate.
- Do not claim universal Azure secret or workload discovery.
- Do not add background scheduling, permanent operation history, a global
  rotation lock, or automatic rollback without a separate product decision.

## Candidate next work

1. Choose the next Azure credential-binding category from a concrete prototype
   need and document its read, update, verification, restart, permission, and
   workload-coverage contracts.
2. Add service-specific workload checks only where the result can make a
   meaningful and bounded health claim.
3. Consider portable fingerprint input separately from the ephemeral HMAC
   boundary used for raw dotenv values.
4. Extend managed SOPS or encrypted export beyond dotenv only through a new
   reviewed format contract that never persists decrypted content.

## Review gates

Before registering a new rotatable key resource or binding integration, define:

- the exact Azure API and SDK version range;
- one canonical official or explicitly reviewed observed response shape;
- key slots, permissions, and key-authentication capability semantics;
- binding discovery completeness and out-of-coverage behavior;
- expected-value transition, drift, bridge, interruption, and recovery rules;
- redaction and fixed-error behavior at every external boundary;
- positive, negative, partial-permission, malformed-shape, and recovery tests;
- user-facing scope and limitation wording;
- an explicitly approved disposable live-test plan when mutation evidence is
  required.

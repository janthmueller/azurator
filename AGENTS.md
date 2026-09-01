# Azurator repository guidance

- Start with [`knowledge/index.md`](knowledge/index.md), then read only the
  linked material relevant to the task.
- Before changing product behavior, secret handling, provider contracts,
  plans, operations, export, or rotation, read
  [`knowledge/product/behavior.md`](knowledge/product/behavior.md) and
  [`knowledge/security/threat-model.md`](knowledge/security/threat-model.md)
  completely.
- Provider changes also require the
  [`provider contract discipline`](knowledge/engineering/provider-contracts.md)
  and any relevant document under `knowledge/research/`.
- Keep `README.md` and `docs/` concise and user-facing. Put implementation
  rationale, internal contracts, research, review notes, and agent bookkeeping
  in `knowledge/`.
- Treat CLI help and tests as evidence of implemented behavior. A roadmap or
  design note is not implementation evidence.
- Update affected user documentation and knowledge when behavior changes.
- Use the domain terms **key resource**, **credential binding**, and
  **consumer/workload** as defined in the product knowledge.
- Keep the flat `azurator/` package layout. Do not introduce a `src/` wrapper.
- Only reviewed providers may retrieve or mutate keys. Use one documented
  request and response contract per operation, fail closed on unknown shapes,
  and do not probe fallback variants.
- Never expose raw keys through logs, exceptions, ordinary command arguments,
  plans, or operations. The reviewed plaintext and SOPS file boundaries are
  defined in the threat model.
- Default to read-only behavior. Rotation requires a displayed executable plan
  and confirmation. Never perform a live Azure mutation without the user's
  explicit approval immediately before it.
- Use Git-aware local flake references such as `nix develop .` and
  `nix run .#...`. Keep ignored secrets, plans, environments, caches,
  documentation dependencies, and build output outside the Nix package source.

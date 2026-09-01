---
okf_version: "0.2"
---

# Azurator knowledge bundle

Internal product and engineering knowledge for maintainers and coding agents.
This bundle follows the [Open Knowledge Format v0.2](https://github.com/GoogleCloudPlatform/knowledge-catalog/blob/main/okf/SPEC.md).

# Start here

- [Documentation boundaries](documentation.md) defines what belongs in the
  README, public documentation, repository guidance, and this bundle.
- [Product knowledge](product/) contains the complete implemented behavior and
  candidate roadmap.
- [Security knowledge](security/) contains the mandatory threat model for
  secret handling and Azure mutation.
- [Engineering knowledge](engineering/) covers architecture, development, and
  validation boundaries.
- [Provider research](research/) records reviewed Azure contracts and evidence.

# Reading policy

Read only the concepts relevant to the task. Before changing product behavior,
secret handling, plans, operations, provider contracts, export, or rotation,
read the complete [product behavior](product/behavior.md) and
[threat model](security/threat-model.md). The running CLI and tests are
authoritative for implemented behavior. This bundle explains the durable
intent, constraints, evidence, and design decisions around it.

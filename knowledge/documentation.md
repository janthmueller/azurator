---
type: Documentation Policy
title: Documentation boundaries
description: Defines the audience and responsibility of each Azurator documentation surface.
tags: [documentation, maintenance]
status: stable
---

# Purpose

Azurator keeps user documentation separate from implementation contracts,
security rationale, research, and agent bookkeeping. A person learning the CLI
should not have to read internal history or provider mechanics.

# Surfaces

| Surface | Audience | Content |
| --- | --- | --- |
| `README.md` | First-time visitors | Purpose, installation, first rotation, current scope, and links onward |
| `docs/` | Azurator users | Task-oriented workflows, CLI guidance, supported key resources and bindings, and user-relevant safety limits |
| `CONTRIBUTING.md` | Contributors | Setup, checks, contribution rules, and links to deeper knowledge |
| `AGENTS.md` | Coding agents | Short routing rules and high-risk repository invariants |
| `knowledge/` | Maintainers and coding agents | Complete behavior, architecture, threat model, provider research, decisions, and roadmap |
| CLI `--help` | Users of an installed version | Authoritative command names, options, accepted values, and defaults |

“Internal” means maintainer-facing, not confidential. The repository is public.
Never place credentials, private subscription details, raw Azure responses, or
decrypted secret documents in the knowledge bundle.

# Rules

- Lead public pages with what a user can accomplish.
- Keep examples practical and include limitations only when they affect safe or
  successful use and correct interpretation.
- Introduce a product term before using it in public prose. Prefer plain
  language in the README and getting-started pages, then link to the exact
  reference definition.
- Keep module boundaries, plan schemas, failure analysis, provider contracts,
  live-test evidence, review checklists, and design deliberation in this bundle.
- Do not duplicate the full CLI contract across the README and public site.
  Prefer task examples and the installed `azurator --help` surface.
- Keep one canonical internal record for detailed provider evidence and link to
  it from product and security concepts.
- When behavior changes, update CLI help and tests first, then the affected
  public workflow and internal concept.
- A roadmap or design note is not evidence that behavior is implemented.
- `docs/src/content/docs/` is the only Starlight content source. Material under
  `knowledge/` is internal and is never built as current user documentation.

# Maintenance

The bundle root and subdirectory `index.md` files provide progressive
disclosure. Every other Markdown or MDX file carries OKF frontmatter with a
non-empty `type`.

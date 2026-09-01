---
type: Engineering Reference
title: Azurator development reference
description: Repository setup, checks, documentation, packaging, and live-test guidance.
tags: [engineering, development, testing, release]
status: stable
---

# Azurator development reference

Azurator is a flat-layout Python project managed with uv. Nix provides the
reproducible Python, Azure CLI, SOPS, age, Node.js, pnpm, Bicep, lint, type, and
packaging tools used by the repository.

## Set up the environment

```bash
direnv allow
uv sync --locked --extra dev
```

Without direnv:

```bash
nix develop .
uv sync --locked --extra dev
```

Use the Git-aware `.` flake reference. A raw `path:.` reference can copy ignored
plans, dotenv files, virtual environments, caches, and build output into a Nix
store source path.

## Run checks

```bash
nix develop . -c uv run --locked pytest --cov --cov-report=term-missing
nix develop . -c ruff check .
nix develop . -c ruff format --check .
nix develop . -c uv run --locked pyright
nix run .#docs-check
nix run .#docs-build
nix flake check . --print-build-logs
nix build .
uv run --locked python .github/scripts/check_knowledge.py
```

Tests use fake providers and mocked clients. They may invoke local SOPS and age
with generated test data but must never contact Azure.

## Documentation

Public Starlight content lives only in `docs/src/content/docs/`:

```bash
nix run .#docs-install
nix run .#docs-check
nix run .#docs-build
nix run .#docs-dev
```

Follow the [documentation policy](../documentation.md). Update the knowledge
bundle log for material changes to internal contracts or structure.

## Disposable Azure testing

The reviewed fixture and operational instructions live in
[`infra/live-test/README.md`](../../infra/live-test/README.md). The read-only
preview is `nix run .#live-test-what-if`. Deployment, rotation, and teardown are
development-only operations against the exact tagged fixture.

Never run `live-test-up`, `live-test-down`, `live-test-e2e`, or
`live-test-recovery` from CI or without explicit user approval immediately
before the Azure operation. A new live resource does not authorize a new
product provider. Fake-command harness tests remain part of `nix flake check`.

## Packaging and release

The Nix package source remains an explicit filtered fileset. Ignored plans,
dotenv files, virtual environments, caches, documentation dependencies, and
build output must remain outside it. CI builds and smoke-tests the locked
PyInstaller bundle on Linux, macOS, and Windows without publishing it. The
manual binary workflow can attach checksummed archives to one existing release
tag after verifying the checked-out commit. Binary archives contain the
project license and the available license or notice files for the bundled
Python runtime and packages.

The release workflow remains manual. It requires a successful Test workflow for
the current `main` revision, creates the versioned distributions and GitHub
release in a repository-write job, publishes the preserved distributions to
PyPI from a separate OIDC-only job, and then builds the release-tag binaries.
Do not dispatch it until the user explicitly declares the project ready.

GitHub Actions are pinned to exact commits and maintained by Renovate. Normal
quality, audit, package, release, and binary environments use `uv.lock`.
Cross-version tests additionally exercise the declared Python versions, and a
separate job tests the direct runtime dependency floors. The Nix checks lint
workflow syntax and validate active knowledge frontmatter and local links.

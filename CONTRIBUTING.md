# Contributing To Azurator

Azurator has a narrow pre-alpha Azure mutation slice whose safety contracts must
remain explicit as it grows. Start with `AGENTS.md` and
`knowledge/index.md`. Before changing product behavior, providers, secret
handling, plans, operations, export, or rotation, read
`knowledge/product/behavior.md` and `knowledge/security/threat-model.md`.

## Set Up The Development Environment

With Nix flakes and direnv installed:

```sh
direnv allow
uv sync --locked --extra dev
```

Without direnv, run `nix develop .` and then `uv sync --locked --extra dev`. Use the
Git-aware `.` reference exactly as shown: the raw `path:.` form can copy ignored
private plans, dotenv files, and development caches into the local Nix store.

Useful checks are:

```sh
ruff check .
ruff format --check .
pyright
uv run --locked pytest --cov --cov-report=term-missing
nix flake check . --print-build-logs
nix run .#docs-check
nix run .#docs-build
nix build .
uv run --locked python .github/scripts/check_knowledge.py
```

Use `nix run .#docs-dev` for a local Starlight documentation server.

The disposable live Azure fixture is separate from automated checks:

```sh
nix run .#live-test-what-if
nix run .#live-test-up
nix run .#live-test-down
```

Read `infra/live-test/README.md` first. `live-test-up` and `live-test-down`
mutate Azure and require explicit approval immediately before use. Never invoke
them from CI or an automated test.

## Change Guidelines

- Keep behavior read-only unless the work is explicitly within the supported
  rotation phase.
- Add providers only with documented API versions, response shapes, key slots,
  permissions, binding semantics, workload-coverage limits, and tests using
  fakes or mocks.
- Treat logs and exceptions as potential secret exfiltration paths.
- Add negative-path, malformed-input, partial-permission, and redaction tests for
  security-sensitive changes.
- Keep user documentation explicit about what is implemented and what remains a
  design contract.
- Keep `README.md` and `docs/` user-facing. Put implementation rationale,
  research, and internal contracts in `knowledge/`.
- Use conventional commit prefixes because release automation derives versions
  from commit history.

Never include real credentials, decrypted SOPS documents, Azure response bodies,
or live subscription identifiers in issues, fixtures, snapshots, or commits.

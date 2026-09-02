# Azurator

[![PyPI Latest Release](https://img.shields.io/pypi/v/azurator.svg)](https://pypi.org/project/azurator/)
[![Pepy Total Downloads](https://img.shields.io/pepy/dt/azurator)](https://pepy.tech/project/azurator)
[![GitHub License](https://img.shields.io/github/license/janthmueller/azurator)](https://github.com/janthmueller/azurator/blob/main/LICENSE)

Azurator rotates shared-key credentials for Azure services and updates
supported places where they are stored.

> [!WARNING]
> Azurator is pre-alpha. Key rotation changes Azure and cannot be rolled back.
> Review the displayed changes before confirming them.

## Installation

Python installations require Python 3.10 or newer. The default login uses the
[Azure CLI](https://learn.microsoft.com/cli/azure/install-azure-cli).

```bash
pipx install azurator
```

Other install paths:

- `pip install azurator`
- prebuilt archives from the [latest release](https://github.com/janthmueller/azurator/releases/latest)
- `nix run github:janthmueller/azurator -- --help`

The optional SOPS workflow also requires SOPS 3.13.x. See the
[installation guide](https://janthmueller.github.io/azurator/getting-started/installation/)
for details.

## Quick Start

Rotate keys already stored in a dotenv file:

```bash
azurator login
azurator rotate --env-file .env
```

Azurator matches the file values to supported Azure keys, shows every planned
change, asks once for confirmation, rotates the keys, and updates the file and
supported Azure configuration that stores the same values.

Inspect or preview first when needed:

```bash
azurator match --env-file .env
azurator plan --env-file .env
```

## Other Workflows

- `azurator rotate` selects keys interactively.
- `azurator rotate --sops-file secrets.enc.env` updates a SOPS-encrypted dotenv file.
- `azurator export --sops-out azure-keys.enc.env` creates a new SOPS-encrypted dotenv file.
- `azurator export --out azure-keys.env` creates a new dotenv file from selected keys.
- `azurator match --sops-file secrets.enc.env --key-map-out azurator.keys.json`
  saves mappings for `azurator export --key-map azurator.keys.json --sops-out recreated.enc.env`.
- `azurator refresh --key-map azurator.keys.json --sops-file secrets.enc.env`
  updates the mapped existing assignments with their current Azure values.
- `azurator discover` lists supported key resources without retrieving key values.

## Current Scope

Azurator rotates Storage Account keys and the `Key1` and `Key2` credentials
exposed by Azure AI, Cognitive Services, and Azure OpenAI. When the same key is
stored in a selected dotenv file, a supported Foundry project connection, or an
App Service application setting, Azurator can update that configuration during
the rotation.

Azurator checks only the documented configuration types. It does not discover
every Azure secret or prove that a running workload uses a key.

See [Supported Key Resources and Bindings](https://janthmueller.github.io/azurator/reference/supported-keys-and-bindings/)
for the exact current coverage.

## Shared Keys and Microsoft Entra ID

Shared keys are useful for prototypes and existing integrations, but they must
be stored, distributed, and rotated. Prefer Microsoft Entra ID when the service
and workload support it. Use Azurator when shared keys remain the practical
choice.

Read Microsoft's guidance for
[secretless authentication](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/secretless-authentication),
[Foundry authentication](https://learn.microsoft.com/en-us/azure/foundry/concepts/authentication-authorization-foundry),
and [Azure Storage Shared Key](https://learn.microsoft.com/en-us/azure/storage/common/shared-key-authorization-prevent).

## Documentation

See the [documentation](https://janthmueller.github.io/azurator/) for setup,
supported workflows, and recovery.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE)

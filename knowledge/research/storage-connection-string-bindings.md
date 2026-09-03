---
type: Credential Value Contract Research
title: Azure Storage Shared Key connection strings
description: Reviewed grammar, matching, mutation, and redaction rules for Storage Shared Key connection strings.
tags: [research, azure, storage, bindings, dotenv, app-service]
status: implemented
---

# Azure Storage Shared Key connection-string contract

This contract lets one credential-binding value contain a supported Azure
Storage connection string instead of only a raw account key. It is a value
shape shared by local dotenv, SOPS dotenv, refresh, and App Service application
settings. It is not a separate Azure binding provider.

## Official basis

Microsoft documents these Shared Key forms:

```text
DefaultEndpointsProtocol=https;AccountName=ACCOUNT;AccountKey=KEY
DefaultEndpointsProtocol=https;AccountName=ACCOUNT;AccountKey=KEY;EndpointSuffix=SUFFIX
DefaultEndpointsProtocol=https;BlobEndpoint=URI;FileEndpoint=URI;QueueEndpoint=URI;TableEndpoint=URI;AccountName=ACCOUNT;AccountKey=KEY
```

The service endpoint fields are optional individually. When present, Microsoft
requires complete HTTP or HTTPS URIs. `EndpointSuffix` supports public and
sovereign Azure environments.

This is a practical Azure binding. Microsoft documents
`AzureWebJobsStorage` as a connection string in a Function App application
setting by default and says it must be updated when Storage keys are
regenerated. Function Apps are top-level `Microsoft.Web/sites`, so they pass
through the same reviewed application-settings API as other visible App
Service sites.

## Accepted grammar

Azurator accepts a semicolon-separated string with exact canonical field
names. One trailing semicolon is allowed. Field order is preserved and does
not affect recognition.

Required exactly once:

- `DefaultEndpointsProtocol`, with value `http` or `https`;
- `AccountName`, satisfying the Azure Storage account-name grammar;
- `AccountKey`, with one non-empty value.

Optional at most once:

- `EndpointSuffix`;
- `BlobEndpoint`;
- `FileEndpoint`;
- `QueueEndpoint`;
- `TableEndpoint`.

Empty fields, duplicate fields, whitespace around a field name or value,
unknown fields, malformed endpoint URIs, and noncanonical field casing are
rejected. Explicit endpoints require an HTTP or HTTPS scheme, a host, a valid
optional numeric port, no credentials or fragment, and valid URI escaping.
Endpoint suffixes use non-empty DNS-style labels. The parser splits each field
at its first `=`, so base64 padding in `AccountKey` remains part of the key.

The contract deliberately excludes SAS connection strings, the
`UseDevelopmentStorage=true` Azurite shortcut, identity-based configuration,
JSON, arbitrary embedded values, and malformed connection strings. Azurator
does not search for `AccountKey=` as an unrestricted substring and does not
probe alternative grammars.

## Matching

For a recognized connection string Azurator:

1. reads `AccountName` and `AccountKey` only in process memory;
2. considers only a discovered `Microsoft.Storage/storageAccounts` resource
   whose exact account name matches `AccountName` case-insensitively;
3. compares `AccountKey` with that resource's reviewed slots through the same
   process-local HMAC matching boundary used for raw keys;
4. persists only the selector, resource ID, and slot after a match.

It never compares the embedded key with a different Storage account or with a
Cognitive Services account. An unrecognized value retains the existing raw-key
comparison behavior.

## Mutation and verification

A managed update replaces only the exact parsed `AccountKey` span. Every other
character in the connection-string value is retained. The surrounding dotenv
assignment may still be rendered in Azurator's normal safe quoting form.

The normal expected-to-replacement transition remains authoritative:

- the expected embedded key is replaced;
- the replacement embedded key is an idempotent no-op;
- a different embedded key, another account name, or another resource type is
  binding drift and blocks mutation;
- verification reparses the value, rechecks the account identity, and compares
  the embedded key with the expected Azure slot.

Aliases may mix raw keys and reviewed connection strings in one binding. Each
alias keeps its own representation during bridge and final updates.

## Export and refresh

`export` continues to create raw key assignments. A key map describes Azure
resource-and-slot identity, not presentation format, so it gains no schema
field for connection strings.

`refresh` preserves a recognized connection string already present at a mapped
selector and replaces only its `AccountKey`. Raw targets remain raw. A valid
connection string naming another Storage account blocks before key retrieval.
Missing selectors and all existing refresh atomicity rules remain unchanged.

## Secret boundary

The full connection string is secret-bearing because it includes the account
key. It must never enter logs, exceptions, reports, plans, operations, key
maps, or ordinary command arguments. Parser models suppress the key from their
representation. App Service reads remain one-site-at-a-time, while SOPS and
dotenv values remain within their existing reviewed plaintext boundaries.

## Evidence

Automated coverage includes:

- documented default, endpoint-suffix, and explicit-endpoint forms;
- rejection of unsupported and ambiguous forms;
- account-name-constrained matching and cross-account rejection;
- mixed raw and connection-string aliases;
- App Service, plaintext dotenv, and SOPS dotenv update plus verification;
- key-map refresh preservation and pre-retrieval cross-account blocking;
- redaction of sentinel keys;
- the disposable App Service fixture with one raw alias pair and one Storage
  connection-string alias in the same grouped binding.

The fixture, fake harness, and separately approved live run cover the complete
bridge, regeneration, final update, and representation-preservation sequence.

## Sources

- [Configure Azure Storage connection strings](https://learn.microsoft.com/en-us/azure/storage/common/storage-configure-connection-string)
- [Storage considerations for Azure Functions](https://learn.microsoft.com/en-us/azure/azure-functions/storage-considerations)
- [Automate resource deployment for a Function App](https://learn.microsoft.com/en-us/azure/azure-functions/functions-infrastructure-as-code)
- [App Service application-settings contract](app-service-bindings.md)

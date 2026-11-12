---
type: Security Contract Research
title: SOPS dotenv per-field confidentiality
description: Reviewed field representation and selection semantics required before storing managed keys through SOPS.
tags: [research, security, sops, dotenv, bindings]
status: implemented
---

# Reviewed SOPS boundary

Azurator supports SOPS 3.13.x. A document can have SOPS metadata while a
particular value is intentionally plaintext. Decrypted-value equality therefore
proves integrity, not encryption of that field. This also affects reusable maps
whose application selector ends in the default `_unencrypted` suffix.

## Official source contracts

- [The pinned dotenv store](https://github.com/getsops/sops/blob/v3.13.1/stores/dotenv/store.go)
  reads and emits one exact `NAME=VALUE` record per line. It preserves string
  values and represents embedded line breaks with escapes. Metadata uses the
  same flat store. Azurator does not reinterpret metadata as application values.
- [The pinned cipher](https://github.com/getsops/sops/blob/v3.13.1/aes/cipher.go)
  emits nonempty string values as
  `ENC[AES256_GCM,data:BASE64,iv:BASE64,tag:BASE64,type:str]`.
  Successful SOPS decryption authenticates and transforms this representation.
- [Tree selection](https://github.com/getsops/sops/blob/v3.13.1/sops.go)
  uses the same path/comment predicate during encryption and decryption. It
  considers suffixes, regular expressions and comments. Excluded values pass
  through unchanged. Azurator delegates those decisions to SOPS, avoiding
  differences between Python regex behavior and SOPS's Go implementation.
- [The set operation](https://github.com/getsops/sops/blob/v3.13.1/cmd/sops/set.go)
  decrypts the existing tree, changes the selected value and re-encrypts with
  existing metadata. The CLI writes in place. Its selector decision must be
  checked before supplying a replacement, not merely after the write.

## Implemented proof

For each managed selector, the adapter requires exactly one matching raw
ciphertext assignment with the canonical AES-GCM string envelope. It also
requires the parsed decrypted value to differ from that complete envelope.
Both conditions matter: a plaintext excluded field can contain a string that
looks like ciphertext. Such a field is unchanged by SOPS and must be rejected.

The raw lookup follows the exact pinned store syntax, without trying alternate
key names, formats, algorithms or policy interpretations. Values and unknown
representations never appear in the resulting error. This is an additional
confidentiality check alongside SOPS MAC validation and the existing complete
assignment/value verification, not a replacement for either.

Export checks all generated assignments during its in-memory decrypt round
trip, before either ciphertext or a companion map is staged. Existing files
check only the managed selectors, retaining unrelated intentionally plaintext
fields. Refresh validates them before reading current Azure keys and repeats
the check for the update snapshot, even for no-ops. Matching checks confirmed
keys before admitting local bindings into a plan. Binding updates and
verification check their complete alias group. The set adapter also verifies
its one selector immediately before handing any replacement over stdin to SOPS.

SOPS retains recipients and policy. Azurator rejects excluded managed fields
rather than silently changing those settings or claiming an unsafe update
succeeded. Same-user concurrent edits remain outside the existing file contract.

## Regression evidence

`tests/test_sops_encryption.py` checks malformed/duplicate/missing records,
unchanged ciphertext-looking values and secret-free failures. Real SOPS/age
tests in `tests/test_sops_encryption_real.py` cover the default exclusion,
both regex directions, custom suffixes and comment selection, export failure
without artifacts, refresh/no-op rejection, rotation update/verification,
pre-execution CLI rejection, aliases and unrelated plaintext fields. Existing
multi-recipient tests remain in `tests/test_refreshing.py`.

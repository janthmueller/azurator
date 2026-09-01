# Security Policy

Azurator is pre-release software and is not yet suitable for rotating production
credentials.

Report suspected vulnerabilities privately through the repository's GitHub
Security Advisory feature. Do not open a public issue containing credential
material, tenant or subscription identifiers, private resource IDs, decrypted
SOPS content, logs with raw Azure responses, or reproduction data from a live
environment.

Use synthetic high-entropy values and fake resource IDs in reproductions. If a
real key may have been exposed while testing Azurator, rotate it through the
resource owner's established incident-response process; do not wait for an
Azurator fix.

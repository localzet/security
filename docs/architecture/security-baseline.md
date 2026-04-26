# Security Baseline

## Authentication Baseline

- OIDC authorization code flow with PKCE
- device authorization flow for CLI
- passkeys as first-class factor
- TOTP fallback
- step-up MFA for sensitive actions

## Token Baseline

- short-lived access tokens
- refresh rotation enabled by default
- audience and issuer validation required
- revocation and reuse detection built into model
- no browser local storage for default web flows

## Tenant Baseline

- tenant-scoped persistence model
- tenant-aware cache keys
- tenant-aware event routing
- audit export scoped to tenant boundary
- administrative override requires reason and audit event

## Cryptography Baseline

- Argon2id for password hashing
- versioned key identifiers
- signing key rotation support
- secret redaction in logs and telemetry
- no plaintext recovery artifacts

## Operational Baseline

- structured logs
- readiness and liveness endpoints
- backup and restore procedure for self-hosted mode
- migration discipline with rollback planning
- signed release artifacts planned before production claim

# Threat Model

## Assets

- user identities
- session records
- token families
- signing keys
- policy bindings
- audit records
- tenant configuration
- service account credentials
- federation trust metadata

## Threat Actors

- anonymous internet attacker
- credential stuffing operator
- malicious tenant administrator
- compromised customer environment
- insider with elevated access
- supply-chain attacker
- attacker with read-only access to logs or backups

## Primary Threat Classes

### Identity Attacks
- credential stuffing
- phishing and token theft
- session hijacking
- MFA downgrade
- device flow phishing

### Authorization Failures
- tenant boundary bypass
- confused deputy between APIs
- scope escalation
- stale policy evaluation
- implicit privilege through missing defaults

### Cryptographic Failures
- weak password hashing
- signing key leakage
- invalid key rotation process
- token replay without family tracking

### Operational Failures
- unsafe migrations
- incomplete audit trail
- insecure backup handling
- broken self-hosted upgrades
- silent loss of revocation state

## Mandatory Mitigations

- passkeys and step-up MFA support
- refresh token rotation with reuse detection
- short-lived audience-bound access tokens
- explicit tenant checks in every layer
- immutable audit events for privileged actions
- key rotation model with active and retired states
- secure defaults for self-hosted deployments
- dependency and supply-chain review in CI

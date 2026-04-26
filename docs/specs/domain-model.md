# Domain Model

## Identity Surface

Primary entities:
- tenant
- project
- application
- user
- identity
- session
- token family
- refresh token
- service account
- policy binding
- audit event

## Modeling Rules

- tenant isolation must be explicit in every persisted aggregate
- sessions and token families are separate concerns
- token reuse detection is modeled as domain state, not only as runtime cache
- machine identities must not be overloaded onto user records
- privileged overrides must emit audit events with actor and reason

## Initial Aggregate Boundaries

### Tenant
Owns project namespace and administrative settings.

### Application
Owns OAuth/OIDC client metadata and integration mode.

### Session
Owns user-facing authentication continuity and device binding state.

### Token Family
Owns refresh token rotation, replay detection, and revocation state.

### Audit Event
Immutable event describing security-relevant activity.

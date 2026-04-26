# Persistence Layer

## Storage Principles

- PostgreSQL is the source of truth for security-critical state.
- tenant scope is enforced in repository contracts and SQL predicates.
- refresh token family state is persisted, not cached-only.
- schema changes must be additive-first and migration-safe.

## Initial Tables

- `tenants`
- `projects`
- `applications`
- `sessions`
- `refresh_tokens`

## Mapping Rules

- enum-like domain values are stored as explicit text values
- redirect URIs and auth methods are stored as JSON arrays
- every security aggregate includes `tenant_id`
- token family revocation updates only records inside the same tenant boundary

## Migration Policy

- destructive schema changes are forbidden without explicit migration plan
- every migration must be idempotent where practical
- self-hosted operators must be able to run migrations explicitly

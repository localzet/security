# MVP Scope

## Goal

Deliver a production-shaped foundation for internal and early customer deployments.

## Included

- Rust workspace for core services and shared domain crates
- reference `authd` service
- OIDC discovery endpoint
- health and readiness endpoints
- foundational domain model for tenants, projects, applications, identities, sessions, and audit events
- documented architecture and security rules

## Next Implementation Steps

1. persistence contracts and repository traits
2. session and token family domain services
3. authorization code and device flow state model
4. password hashing and credential verification interfaces
5. audit sink interface and event schema stabilization
6. tenant/project/admin APIs

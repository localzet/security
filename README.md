# Localzet Security

Localzet Security is an open-source security control plane for web applications, APIs, internal tools, customer deployments, and CLI workloads.

## Product Scope

The platform is designed as a universal protective contour rather than a single login service.

Core domains:
- identity and authentication
- authorization and policy decisions
- session and token lifecycle management
- audit and security telemetry
- tenant isolation and deployment portability
- self-hosted and federation-ready operation

## Planned Operating Modes

- Centralized: one security plane for internal projects.
- Self-hosted: full-featured customer deployment with local data ownership.
- Federated: trusted identity exchange across independent organizations.

## Repository Layout

- `docs/architecture/`: product and system architecture
- `docs/adr/`: architecture decision records
- `docs/specs/`: implementation-facing specifications
- `apps/authd/`: reference auth service
- `crates/`: shared Rust libraries
- `db/migrations/`: PostgreSQL schema migrations

## Current State

This repository contains the initial architecture baseline, security documentation, and Rust workspace skeleton for the first implementation phase.

## Design Principles

- security invariants are documented before feature growth
- portability across SaaS and self-hosted modes
- hard tenant isolation boundaries
- explicit auditability of sensitive actions
- simple core, extensible integration surface
- protocol correctness over convenience shortcuts

## Immediate Milestones

1. Build the authentication core and OIDC discovery surface.
2. Add session, device, and token family models.
3. Introduce policy evaluation and audit event ingestion.
4. Add PostgreSQL persistence, migrations, and repository adapters.
5. Harden self-hosted packaging, observability, and upgrade path.

## Documentation Index

- [Vision](docs/architecture/vision.md)
- [System Architecture](docs/architecture/system-architecture.md)
- [Threat Model](docs/architecture/threat-model.md)
- [Security Baseline](docs/architecture/security-baseline.md)
- [MVP Scope](docs/specs/mvp.md)
- [Persistence Layer](docs/specs/persistence.md)
- [OAuth Flow Baseline](docs/specs/oauth-flows.md)
- [Token Issuer Baseline](docs/specs/token-issuer.md)
- [Contribution Guide](CONTRIBUTING.md)
- [Security Policy](SECURITY.md)

## Build

Rust toolchain is required. The workspace is structured for stable Rust.

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p authd
```

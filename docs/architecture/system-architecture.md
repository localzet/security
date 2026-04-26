# System Architecture

## Logical Planes

### Control Plane

Responsible for configuration and governance:
- tenants
- projects
- applications
- policies and role bindings
- branding and integration settings
- federation metadata
- admin workflows
- export and compliance controls

### Data Plane

Responsible for runtime security decisions and identity flows:
- authentication
- session issuance and revocation
- token issuance and introspection
- device authorization flow
- step-up authentication
- risk checks
- audit ingestion

### Integration Plane

Responsible for product adoption:
- SDKs
- framework middleware
- CLI helpers
- webhook delivery
- SCIM and SAML bridge adapters
- API gateway integrations

## Core Services

- `auth-core`: OAuth 2.x and OIDC endpoints, token issuance, session coordination
- `identity`: users, credentials, passkeys, factors, devices
- `policy`: role bindings, attributes, decision engine
- `audit`: event intake, storage, export, streaming
- `admin`: tenant and project management surface
- `events`: webhook and security event distribution

## Security Boundaries

The architecture assumes explicit boundaries between:
- public internet traffic and edge ingress
- tenant-owned resources and platform-owned infrastructure
- human identity and machine identity
- authentication and authorization decisions
- runtime plane and administrative plane

## Deployment Modes

### Centralized

One authority serves multiple internal projects with shared policy and audit controls.

### Self-hosted

Customer deployment runs the same control and data plane concepts with local persistence and local operational ownership.

### Federated

Separate authorities establish explicit trust and scope exchange under allowlisted rules.

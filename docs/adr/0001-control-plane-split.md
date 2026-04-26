# ADR 0001: Control Plane and Data Plane Separation

## Status
Accepted

## Context
The platform must support both SaaS and self-hosted topologies without forking the product model. Authentication traffic, administrative configuration, and audit governance have different scaling and trust properties.

## Decision
The architecture is split into:
- control plane for configuration and governance
- data plane for authentication and runtime security flows
- integration plane for adapters and developer-facing integration surfaces

## Consequences
- deployment modes remain structurally aligned
- tenant isolation reasoning is clearer
- self-hosted packaging becomes simpler
- runtime latency-sensitive paths stay isolated from admin workflows

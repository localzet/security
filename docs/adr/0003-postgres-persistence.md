# ADR 0003: PostgreSQL as Primary Security State Store

## Status
Accepted

## Context
The platform needs a transactional source of truth for sessions, applications, refresh token families, tenant-scoped records, and future administrative state. The storage model must work for SaaS and self-hosted deployments.

## Decision
PostgreSQL is the primary persistence layer for security-critical state. Repository adapters are implemented against explicit tenant-scoped SQL queries. Migrations are maintained in-repository.

## Consequences
- transactional invariants are easier to enforce
- self-hosted packaging remains practical
- migration discipline becomes part of core engineering process
- runtime caches are treated as accelerators, not as sources of truth

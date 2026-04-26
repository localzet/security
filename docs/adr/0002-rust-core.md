# ADR 0002: Rust for Security-Critical Core

## Status
Accepted

## Context
The project requires a memory-safe implementation language, strong type modeling, static binaries for self-hosted delivery, and predictable performance for authentication and policy paths.

## Decision
Security-critical backend components are implemented in Rust.

## Consequences
- memory-safety baseline is improved
- self-hosted distribution is easier
- type-rich domain modeling is encouraged
- contributor bar for backend work is higher but justified

# Contributing

## Working Agreement

This project is a security platform. Correctness, traceability, and operational safety are mandatory.

## Repository Standards

- document architecture-impacting changes in `docs/adr/`
- keep security-relevant assumptions explicit
- prefer small, reviewable commits
- add tests with behavior changes
- keep public contracts stable or version them deliberately

## Code Style

- Rust code must pass `fmt` and `clippy`
- comments must be short and only explain non-obvious intent
- avoid hidden control flow and magic defaults
- prefer typed domain models over stringly interfaces

## Documentation Requirements

Update documentation when changing:
- trust boundaries
- token semantics
- tenant isolation model
- audit event schema
- deployment or recovery workflows

## Pull Request Checklist

- architecture impact assessed
- threat model impact assessed
- tests added or rationale documented
- migration impact assessed
- backward compatibility assessed
- observability and audit impact assessed

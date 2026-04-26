# Security Policy

## Supported Scope

This repository targets security-sensitive workloads. All changes must preserve the documented security invariants.

## Vulnerability Reporting

Do not open public issues for suspected vulnerabilities.

Report security issues through a private channel with:
- affected component
- attack preconditions
- impact assessment
- proof of concept or reproduction steps
- proposed mitigations if available

## Engineering Rules

- no security-relevant shortcut without an ADR
- no long-lived bearer tokens by default
- no client-side storage of browser access tokens in web flows
- no implicit OAuth flows
- no unaudited administrative impersonation
- no bypass of tenant boundary checks
- no plaintext secrets in repository, tests, fixtures, or logs
- no weakening of cryptographic defaults without explicit review

## Secure Development Expectations

- every public API change must document trust boundaries
- authentication and authorization changes require tests
- cryptography changes require review from maintainers responsible for security
- self-hosted changes must preserve migration and backup safety
- threat model updates are mandatory for new trust relationships

## Hardening Roadmap

- reproducible builds
- signed release artifacts
- SBOM generation
- SAST, dependency audit, secret scanning
- structured security regression suite
- external cryptography review before production claim

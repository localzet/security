# Release Security Checklist

## Before Tagging

- ADRs updated for architecture-impacting changes
- threat model updated for new trust boundaries
- dependencies reviewed
- secrets scan clean
- tests and lint green
- migration impact reviewed
- changelog prepared

## Before Production Claim

- SBOM generated
- release artifact signed
- vulnerability scan reviewed
- rollback plan documented
- operational runbooks reviewed
- default configuration hardened

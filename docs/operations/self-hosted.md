# Self-Hosted Operations

## Target Shape

Initial self-hosted distribution is expected to contain:
- auth service
- admin service
- worker service
- PostgreSQL
- Redis
- reverse proxy

## Mandatory Operator Capabilities

- bootstrap first administrator
- run reference compose stack for validation
- configure issuer and external URLs
- configure SMTP
- run migrations explicitly
- export and restore backups
- rotate credentials and signing keys
- collect logs and health status

## Safety Rules

- never rotate signing keys without overlap window
- never apply schema changes without backup validation
- never expose admin interfaces directly to the public internet without access controls
- never store credentials in plaintext deployment manifests

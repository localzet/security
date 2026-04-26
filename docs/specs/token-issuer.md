# Token Issuer Baseline

## Current Profile

- signing algorithm: `RS256`
- key selection: single active key from runtime configuration
- access token format: signed JWT
- id token format: signed JWT when `openid` scope is present
- public verification surface: JWKS and token introspection

## Configuration

The runtime currently expects either:
- `LOCALZET_SIGNING_PRIVATE_KEY_PATH` and `LOCALZET_SIGNING_PUBLIC_KEY_PATH`
- or PEM values in environment variables

## Security Notes

- development keys in `deploy/keys/` are for local validation only
- production deployments must replace development keys before exposure
- token signing availability is a hard dependency for `/oauth/token`

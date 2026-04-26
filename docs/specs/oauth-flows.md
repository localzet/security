# OAuth Flow Baseline

## Authorization Code with PKCE

Current implementation baseline:
- authorization code is issued as an opaque one-time secret
- only `code_hash` is stored in persistence
- PKCE challenge is stored and verified on consumption
- code lifetime is short-lived
- code consumption is one-time and stateful

## Refresh Token Rotation

Current implementation baseline:
- refresh token is issued as an opaque secret
- only `token_hash` is stored in persistence
- rotation creates a new token inside the same token family
- reuse of a non-active token revokes the family
- token family state remains in PostgreSQL

## Security Notes

- opaque secrets must never be logged
- bearer artifacts must be persisted only in hashed form
- replay detection is based on token family state, not cache-only checks

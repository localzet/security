# Development Environment

## Local Stack

The repository includes a reference Docker Compose stack for:
- PostgreSQL
- `authd`

## Start

```bash
docker compose -f deploy/compose/docker-compose.yml up --build
```

## Expected Endpoints

- `http://127.0.0.1:8080/health/live`
- `http://127.0.0.1:8080/health/ready`
- `http://127.0.0.1:8080/.well-known/openid-configuration`
- `http://127.0.0.1:8080/oauth/authorize`
- `http://127.0.0.1:8080/oauth/token`
- `http://127.0.0.1:8080/oauth/introspect`
- `http://127.0.0.1:8080/.well-known/jwks.json`

## Manual Flow Smoke Test

Authorization request:

```bash
curl -i "http://127.0.0.1:8080/oauth/authorize?response_type=code&client_id=web-client&redirect_uri=http%3A%2F%2F127.0.0.1%3A3000%2Fcallback&scope=openid%20offline_access&state=test-state&tenant_id=11111111-1111-1111-1111-111111111111&user_id=22222222-2222-2222-2222-222222222222&code_challenge=Ds3NpaREu9I2EYq6l0l3ZkFyv_Gt5O4EpGD6cZlY0Kg&code_challenge_method=S256"
```

Token exchange:

```bash
curl -X POST http://127.0.0.1:8080/oauth/token \
  -H 'content-type: application/x-www-form-urlencoded' \
  -d 'grant_type=authorization_code' \
  -d 'tenant_id=11111111-1111-1111-1111-111111111111' \
  -d 'client_id=web-client' \
  -d 'code=REPLACE_ME' \
  -d 'redirect_uri=http://127.0.0.1:3000/callback' \
  -d 'code_verifier=verifier-123'
```

## Notes

- `authd` runs migrations on startup by default in the compose profile.
- bootstrap tenant and client can be injected through `LOCALZET_BOOTSTRAP_*` environment variables.
- compose uses development RSA keys from `deploy/keys/`; replace them outside local development.
- production deployments should separate migration execution from steady-state runtime.
- readiness becomes degraded when database connectivity is lost.

# Signing keys for local development

This directory intentionally contains **no signing private keys** in version control.

Generate a unique development key pair:

```sh
sh scripts/generate-dev-keys.sh
# Linux: the authd container is UID 10001 and must be able to read its private key.
sudo chown 10001:10001 deploy/keys/dev-private.pem
sudo chmod 600 deploy/keys/dev-private.pem
docker compose -f deploy/compose/docker-compose.yml up --build
```

The local Compose file mounts `deploy/keys` as a read-only volume. Do not generate or bake long-lived private keys into Docker images, and never reuse the development key pair in production.

**Important:** The previously committed `dev-private.pem` remains present in Git history. Treat that value as public, never trust it, and rotate any environment that copied it. If history purge is desired, coordinate separately so existing clones and release hashes are not silently rewritten.

#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
DEST="$ROOT/deploy/keys"
mkdir -p "$DEST"
umask 077
if [ -e "$DEST/dev-private.pem" ] || [ -e "$DEST/dev-public.pem" ]; then
    echo "Keys already exist; refusing to overwrite them." >&2
    exit 1
fi

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$DEST/dev-private.pem"
openssl pkey -in "$DEST/dev-private.pem" -pubout -out "$DEST/dev-public.pem"
chmod 600 "$DEST/dev-private.pem"
chmod 644 "$DEST/dev-public.pem"

cat <<'INFO'
Generated unique local development signing keys.
The authd container uses UID 10001: make the private key readable only
to that service account before starting the dev stack, e.g. on Linux:
    sudo chown 10001:10001 deploy/keys/dev-private.pem
    sudo chmod 600 deploy/keys/dev-private.pem
These are development-only credentials. Never deploy them to production.
INFO

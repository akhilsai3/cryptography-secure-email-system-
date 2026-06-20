#!/usr/bin/env bash
#
# certs/gen_certs.sh
#
# Generates one self-signed certificate + private key per server
# (GmailServer, KeyServer, RecoveryServer), plus a trust bundle that
# concatenates all three certs together. No external/public CA is
# involved anywhere - every cert is self-signed, and the only thing
# that makes a connection "trusted" is that the peer's cert (or its
# signer) is byte-for-byte one of the certs pinned in
# certs/trusted_servers.pem.
#
# Run this once before starting the servers for the first time, or any
# time you want to rotate all three identities. It's idempotent-safe to
# re-run, but re-running INVALIDATES every previously-issued cert (any
# already-running server/client using the old cert+bundle pair will
# fail TLS verification until restarted with the new files) - that's
# expected for a rotation, not a bug.
#
# Output layout (everything lives under certs/, alongside this script):
#   certs/gmailserver_key.pem      certs/gmailserver_cert.pem
#   certs/keyserver_key.pem        certs/keyserver_cert.pem
#   certs/recoveryserver_key.pem   certs/recoveryserver_cert.pem
#   certs/trusted_servers.pem      (= the three *_cert.pem files, concatenated)
#
# These paths match the TLS_CERT_PATH / TLS_KEY_PATH / TLS_TRUSTED_BUNDLE_PATH
# #defines in gmailserver.cpp, keyserver.cpp, recovery_server.cpp, and
# client.cpp - don't rename/move files here without updating those too.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

DAYS_VALID=3650   # 10 years - this is a local dev/closed-system trust
                   # bundle, not a publicly-relied-upon cert; long validity
                   # avoids silent expiry breaking the whole system. Lower
                   # this and re-run periodically if you want rotation
                   # discipline instead.

# Subject Alternative Name covers both "by IP" and "by hostname" access
# patterns for a localhost deployment. If you later run these servers on
# separate real hosts, change each server's -addext line below to that
# host's actual IP/DNS name (and redistribute the resulting
# trusted_servers.pem to every client/server that needs to trust it).
gen_one() {
    local name="$1"        # e.g. "gmailserver"
    local cn="$2"           # certificate Common Name, just descriptive

    echo "Generating self-signed certificate for ${name}..."
    openssl req -x509 -newkey rsa:2048 \
        -keyout "${name}_key.pem" \
        -out "${name}_cert.pem" \
        -days "${DAYS_VALID}" \
        -nodes \
        -subj "/CN=${cn}" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

    chmod 600 "${name}_key.pem"
    chmod 644 "${name}_cert.pem"
}

gen_one "gmailserver"     "gmailserver.local"
gen_one "keyserver"       "keyserver.local"
gen_one "recoveryserver"  "recoveryserver.local"

echo "Building trust bundle (trusted_servers.pem)..."
cat gmailserver_cert.pem keyserver_cert.pem recoveryserver_cert.pem > trusted_servers.pem

echo ""
echo "Done. Generated:"
ls -1 ./*_key.pem ./*_cert.pem trusted_servers.pem
echo ""
echo "Each server presents its own *_cert.pem/*_key.pem pair."
echo "client.cpp, keyserver.cpp, and recovery_server.cpp all trust"
echo "exactly the certs bundled in trusted_servers.pem (no system CA store)."

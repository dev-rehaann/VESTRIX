#!/usr/bin/env bash
set -euo pipefail

CERT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
cd "$CERT_DIR"

NODE_ID="${1:-}"
if [[ ! "$NODE_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]; then
  echo "Usage: $0 <node-id>" >&2
  exit 2
fi
if [ ! -f "${NODE_ID}.crt" ]; then
  echo "Certificate not found: ${NODE_ID}.crt" >&2
  exit 2
fi

openssl ca -batch -config openssl.cnf -revoke "${NODE_ID}.crt" \
  -crl_reason keyCompromise
openssl ca -batch -config openssl.cnf -gencrl -out ca.crl

echo "[*] Revoked ${NODE_ID}; regenerated ca.crl."
echo "[*] Send SIGHUP to the collector so new connections use the updated CRL."

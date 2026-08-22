#!/usr/bin/env bash
# Vestrix — project CA + tracked per-node certificate generator.
# NOT production-hardened as-is: no HSM and no passphrase on private keys.
set -euo pipefail

CERT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
cd "$CERT_DIR"

mkdir -p newcerts
touch index.txt
[ -f serial ] || printf '1000\n' > serial
[ -f crlnumber ] || printf '1000\n' > crlnumber

if [ ! -f ca.key ]; then
  echo "[*] Generating project root CA..."
  openssl genrsa -out ca.key 4096
  openssl req -x509 -new -key ca.key -days 3650 -out ca.crt \
    -config openssl.cnf -extensions v3_ca \
    -subj "/CN=Vestrix Root CA"
else
  echo "[*] Root CA already exists, skipping."
fi

openssl ca -batch -config openssl.cnf -gencrl -out ca.crl

NODE_ID="${1:-}"
if [ -z "$NODE_ID" ]; then
  echo "Usage: $0 <node-id>   (e.g. $0 node-07)"
  exit 0
fi
if [[ ! "$NODE_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]; then
  echo "Node ID must match ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$" >&2
  exit 2
fi
if [ -e "${NODE_ID}.key" ] || [ -e "${NODE_ID}.crt" ]; then
  echo "Refusing to overwrite existing certificate or key for ${NODE_ID}." >&2
  exit 2
fi

echo "[*] Issuing cert for ${NODE_ID}..."
openssl genrsa -out "${NODE_ID}.key" 2048
openssl req -new -key "${NODE_ID}.key" -out "${NODE_ID}.csr" \
  -subj "/CN=${NODE_ID}"
openssl ca -batch -config openssl.cnf -extensions client_cert -days 365 \
  -in "${NODE_ID}.csr" -out "${NODE_ID}.crt" -notext
rm "${NODE_ID}.csr"
openssl ca -batch -config openssl.cnf -gencrl -out ca.crl

echo "[*] Done. Files: ${NODE_ID}.key ${NODE_ID}.crt"
echo "[*] Run bash check_expiry.sh to flag certificates nearing expiry."

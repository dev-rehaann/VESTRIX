#!/usr/bin/env bash
set -euo pipefail

CERT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
cd "$CERT_DIR"

DAYS="${1:-30}"
if [[ ! "$DAYS" =~ ^[0-9]+$ ]]; then
  echo "Usage: $0 [warning-days]" >&2
  exit 2
fi

threshold_seconds=$((DAYS * 86400))
status=0
shopt -s nullglob
for cert in *.crt; do
  case "$cert" in
    ca.crt|server.crt) continue ;;
  esac
  if ! openssl x509 -checkend "$threshold_seconds" -noout -in "$cert" >/dev/null; then
    expires="$(openssl x509 -enddate -noout -in "$cert" | cut -d= -f2-)"
    echo "[!] ${cert} expires within ${DAYS} days (${expires})."
    status=1
  fi
done
exit "$status"

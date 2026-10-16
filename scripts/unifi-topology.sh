#!/bin/bash
# Read-only: ask the local UniFi controller how it sees device uplinks and LLDP neighbors.
# Credentials are typed interactively, never stored or printed.
set -u
BASE=${UNIFI_URL:-https://127.0.0.1}
SITE=${UNIFI_SITE:-default}
DIR=$(mktemp -d)
trap 'rm -rf "$DIR"' EXIT
OUT="$DIR/devices.json"

read -rp "API key (Enter = log in with a local admin account instead): " -s KEY
echo
if [ -n "$KEY" ]; then
  CODE=$(curl -sk -o "$OUT" -w "%{http_code}" -H "X-API-KEY: $KEY" \
    "$BASE/proxy/network/api/s/$SITE/stat/device")
else
  read -rp "Local admin username: " USER_NAME
  read -rsp "Password: " PASS
  echo
  BODY=$(python3 -c 'import json,sys; print(json.dumps({"username": sys.argv[1], "password": sys.argv[2]}))' "$USER_NAME" "$PASS")
  unset PASS
  curl -sk -c "$DIR/cookies" -D "$DIR/headers" -o /dev/null -H "Content-Type: application/json" \
    -d "$BODY" "$BASE/api/auth/login"
  unset BODY
  CSRF=$(grep -i '^x-csrf-token:' "$DIR/headers" | tr -d '\r' | cut -d' ' -f2)
  CODE=$(curl -sk -o "$OUT" -w "%{http_code}" -b "$DIR/cookies" -H "X-CSRF-Token: $CSRF" \
    "$BASE/proxy/network/api/s/$SITE/stat/device")
fi
unset KEY
echo "HTTP $CODE"
[ "$CODE" = "200" ] || exit 1
python3 "$(dirname "$0")/unifi_topology.py" < "$OUT"

#!/bin/bash
# Interactive setup for compose.rb5009.yml / compose.maplite.yml.
# Asks only for what cannot be discovered (controller URL, router address, API user and
# password), writes the local .env file and password secret, then builds and probes the
# router read-only. Everything else (MAC, ports, PoE, neighbors) is read from RouterOS.
# Usage: scripts/setup-mikrotik.sh rb5009|maplite
set -euo pipefail
DEVICE=${1:-}
case "$DEVICE" in
  rb5009) PREFIX=MTUNIFI_RB5009 ;;
  maplite) PREFIX=MTUNIFI_MAPLITE ;;
  *) echo "Usage: $0 rb5009|maplite" >&2; exit 2 ;;
esac
cd "$(dirname "$0")/.."
ENV_FILE=".env.$DEVICE"
COMPOSE="docker compose -f compose.$DEVICE.yml --env-file $ENV_FILE"

current() { [ -f "$ENV_FILE" ] && sed -n "s/^$1=//p" "$ENV_FILE" | tail -1 || true; }
ask() {
  local prompt=$1 default=$2 answer
  read -rp "$prompt${default:+ [$default]}: " answer
  echo "${answer:-$default}"
}

URL=$(ask "Controller inform URL (http://<controller>:8080/inform)" "$(current MTUNIFI_INFORM_URL)")
HOST=$(ask "RouterOS address" "$(current "${PREFIX}_HOST")")
USER_NAME=$(ask "Read-only API user" "$(current "${PREFIX}_USER")")
[ -n "$URL" ] && [ -n "$HOST" ] && [ -n "$USER_NAME" ] || { echo "All three values are required." >&2; exit 1; }

if [ -f "$ENV_FILE" ]; then
  cp "$ENV_FILE" "$ENV_FILE.bak"
  # Keep any optional values already set, replace the three required ones.
  grep -v -E "^(MTUNIFI_INFORM_URL|${PREFIX}_HOST|${PREFIX}_USER)=" "$ENV_FILE.bak" > "$ENV_FILE"
else
  : > "$ENV_FILE"
fi
printf '%s\n' "MTUNIFI_INFORM_URL=$URL" "${PREFIX}_HOST=$HOST" "${PREFIX}_USER=$USER_NAME" >> "$ENV_FILE"
chmod 600 "$ENV_FILE"

mkdir -p .secrets && chmod 700 .secrets
SECRET=".secrets/$DEVICE-password"
if [ -s "$SECRET" ] && [ "$(ask "Keep the existing API password? (y/n)" y)" = "y" ]; then
  echo "Keeping $SECRET"
else
  read -rsp "API password for $USER_NAME: " PASSWORD && echo
  # 644 inside a 700 directory: readable by the container (UID 10001), not other users.
  (umask 022; printf "%s" "$PASSWORD" > "$SECRET")
  unset PASSWORD
fi

$COMPOSE config --quiet
$COMPOSE build "$DEVICE" | tail -1
echo "Probing RouterOS (read-only, does not contact UniFi)..."
$COMPOSE run --rm --no-deps "$DEVICE" probe-routeros 2>&1 | python3 scripts/probe_summary.py
echo
echo "Start:  $COMPOSE up -d"
echo "Then adopt the device in UniFi (Devices -> Adopt) and check:"
echo "        $COMPOSE exec $DEVICE mtunifi diagnose"

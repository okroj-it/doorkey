#!/usr/bin/env bash
# doorkey as a Home Assistant app, against a stand-in Supervisor and Ingress
# gateway: options from a temporary /data, the two listeners, who gets into
# the admin page, and the admin page in a browser under the Ingress prefix.
#
#   scripts/e2e-app.sh
#
# Needs Chrome (CHROME_PATH) and free ports 8080, 8099 (doorkey, fixed in
# app mode), 18123 (fake HA), 18124 (fake Supervisor) and 18125 (fake Ingress).
set -euo pipefail
cd "$(dirname "$0")/.."

DATA=$(mktemp -d)
LOGS=$(mktemp -d)
failed=0
pids=()
cleanup() {
  for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  rm -rf "$DATA"
}
trap cleanup EXIT

cat >"$DATA/options.json" <<'EOF'
{
  "origin": "http://localhost:8080",
  "lock_entity": "lock.front_door",
  "tap_mode": "static",
  "static_path": "abc123secretpath",
  "home_cidrs": ["127.0.0.1/32"]
}
EOF

start() { # name, command... (background, logged)
  local name=$1
  shift
  "$@" >"$LOGS/$name.log" 2>&1 &
  pids+=($!)
}

stop_doorkey() {
  [[ ${doorkey:-} ]] && kill "$doorkey" 2>/dev/null && wait "$doorkey" 2>/dev/null || true
  [[ ${supervisor:-} ]] && kill "$supervisor" 2>/dev/null && wait "$supervisor" 2>/dev/null || true
}

doorkey_app() { # extra env for the fake Supervisor, extra env for doorkey
  stop_doorkey
  env $1 bun test/fake-supervisor.ts >"$LOGS/supervisor.log" 2>&1 &
  supervisor=$!
  pids+=("$supervisor")
  env -i PATH="$PATH" HOME="$HOME" DOORKEY_MODE=app SUPERVISOR_URL=http://127.0.0.1:18124 \
    SUPERVISOR_TOKEN=test DOORKEY_DATA_DIR="$DATA" DOORKEY_INGRESS_PEER=127.0.0.1 $2 \
    bun src/index.ts >"$LOGS/doorkey.log" 2>&1 &
  doorkey=$!
  pids+=("$doorkey")
  for _ in $(seq 50); do curl -fs http://127.0.0.1:8080/healthz >/dev/null && return; sleep 0.2; done
  echo "doorkey did not start:"; cat "$LOGS/doorkey.log"; exit 1
}

run() { # name, command...
  local name=$1 out
  shift
  echo "== $name"
  if out=$("$@" 2>&1); then
    tail -n 2 <<<"$out"
  else
    tail -n 25 <<<"$out"
    echo "   ^ $name FAILED"
    failed=1
  fi
}

start fake-ha bun test/fake-ha.ts
start fake-ingress bun test/fake-ingress.ts

doorkey_app "FAKE_WS_REFUSE=0" "DOORKEY_ADMIN_USERS="
run "app mode" env DOORKEY_DATA_DIR="$DATA" bun test/app-mode-e2e.ts lookup

doorkey_app "FAKE_WS_REFUSE=1" "DOORKEY_ADMIN_USERS=alice"
run "app mode, users not readable" bun test/app-mode-e2e.ts fallback

# The CLI as the backup hook runs it (docker exec): settings from /data too.
run "CLI in app mode" env -i PATH="$PATH" HOME="$HOME" DOORKEY_MODE=app SUPERVISOR_URL=http://127.0.0.1:18124 \
  SUPERVISOR_TOKEN=test DOORKEY_DATA_DIR="$DATA" bun cli/doorkey.ts db:checkpoint

if grep -iE "unhandled" "$LOGS/doorkey.log" >/dev/null; then
  echo "== server errors"; grep -i "unhandled" "$LOGS/doorkey.log" | head; failed=1
fi
exit $failed

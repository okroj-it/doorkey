#!/usr/bin/env bash
# The data-layer checks and the three browser suites, against one database.
#
#   DATABASE_URL=sqlite:///tmp/doorkey-e2e.db scripts/e2e.sh
#   DATABASE_URL=postgres://postgres:pw@127.0.0.1:5432/postgres scripts/e2e.sh
#
# The database is emptied before every suite: the SQLite file is deleted,
# a Postgres schema is dropped and recreated. Use a throwaway database.
# Needs Chrome (CHROME_PATH, default /usr/bin/google-chrome-stable) and free
# ports 18080 (doorkey) and 18123 (the fake Home Assistant).
set -euo pipefail
cd "$(dirname "$0")/.."

: "${DATABASE_URL:?set DATABASE_URL to a throwaway sqlite:// or postgres:// database}"
ORIGIN=http://localhost:18080
LOGS=$(mktemp -d)
failed=0
pids=()

cleanup() {
  for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
}
trap cleanup EXIT

# Settings shared by every run; nothing here is a real secret.
export DATABASE_URL DOORKEY_ORIGIN=$ORIGIN DOORKEY_RP_ID=localhost
export DOORKEY_PEPPER=e2e-pepper DOORKEY_SESSION_SECRET=e2e-session DOORKEY_MIN_RESPONSE_MS=0
export HA_URL=http://127.0.0.1:18123 HA_TOKEN=e2e HA_LOCK_ENTITY=lock.front_door
export DOORKEY_HOME_CIDRS=127.0.0.1/32 PORT=18080
# SUN mode with the AN12196 example meta key; the KEK only has to be well-formed.
export DOORKEY_TAG_META_KEY=00000000000000000000000000000000
export DOORKEY_TAG_KEK=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
export DOORKEY_STATIC_PATH=abc123secretpath

reset_db() {
  case "$DATABASE_URL" in
    sqlite://*) local f=${DATABASE_URL#sqlite://}; rm -f "$f" "$f-wal" "$f-shm" ;;
    *) bun -e 'import { SQL } from "bun"; const s = new SQL(process.env.DATABASE_URL);
               await s.unsafe("drop schema public cascade; create schema public"); await s.end();' ;;
  esac
}

server() { # tap mode
  [[ ${server_pid:-} ]] && kill "$server_pid" 2>/dev/null && wait "$server_pid" 2>/dev/null || true
  DOORKEY_TAP_MODE=$1 bun src/index.ts >"$LOGS/server-$1.log" 2>&1 &
  server_pid=$!
  pids+=("$server_pid")
  for _ in $(seq 50); do curl -fs "$ORIGIN/healthz" >/dev/null && return; sleep 0.2; done
  echo "server did not start:"; cat "$LOGS/server-$1.log"; exit 1
}

cli() { DOORKEY_TAP_MODE=sun bun cli/doorkey.ts "$@"; }
token() { grep -o "$1/[^ ]*" | cut -d/ -f2; }

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

bun test/fake-ha.ts >"$LOGS/fake-ha.log" 2>&1 &
pids+=($!)

reset_db
run "data layer" env DOORKEY_TAP_MODE=sun bun test/db-functions.ts

reset_db
server sun
cli user:add owner >/dev/null && cli user:grant owner owner >/dev/null
cli user:add guest >/dev/null && cli user:grant guest guests >/dev/null
cli action:add test script.tapgate_test --label "Test tapgate" >/dev/null && cli action:allow test owner >/dev/null
owner=$(cli user:enroll owner phone | token enroll)
guest=$(cli user:enroll guest phone | token enroll)
url=$(cli action:token test | grep -o 'http[^ ]*')
run "actions" bun test/action-passkey.ts "$owner" "$guest" "$url"

reset_db
server sun
run "admin actions tab" bun test/admin-actions.ts "$(cli admin:enroll tester | token enroll)"

reset_db
server static
run "admin passkey" bun test/admin-passkey.ts "$(DOORKEY_TAP_MODE=static bun cli/doorkey.ts admin:enroll tester | token enroll)"

if grep -iE "unhandled|error:" "$LOGS"/server-*.log >/dev/null; then
  echo "== server errors"; grep -ihE "unhandled|error:" "$LOGS"/server-*.log | head; failed=1
fi
exit $failed

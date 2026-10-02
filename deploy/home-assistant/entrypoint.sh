#!/bin/sh
# doorkey as a Home Assistant app. The Supervisor creates the app's /data as
# root and rewrites options.json (root, 0600) on every start, and offers no
# way to change either. So the app image starts as root, hands /data to the
# doorkey user, and runs doorkey as that user.
set -eu
if [ "$(id -u)" = 0 ]; then
  chown -hR 1000:1000 /data
  exec su-exec 1000:1000 "$@"
fi
exec "$@"

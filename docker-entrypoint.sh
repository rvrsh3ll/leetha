#!/bin/sh
# Fix volume ownership if running as root (e.g., docker run --user root).
# When running as appuser (default), skip — capabilities are preserved.
if [ "$(id -u)" = "0" ]; then
    chown -R appuser:appuser /home/appuser/.leetha 2>/dev/null || true
fi

# The Python interpreter has file capabilities (NET_RAW, NET_ADMIN,
# NET_BIND_SERVICE) baked in via setcap. Exec'ing it will fail with
# "Operation not permitted" if any of those capabilities are missing from
# the container's bounding set. Detect that up front with a clearer error
# than the kernel's EPERM.
for cap in cap_net_raw cap_net_admin cap_net_bind_service; do
    if ! capsh --has-b="$cap" 2>/dev/null; then
        cat >&2 <<EOF
ERROR: Container is missing $cap in its bounding capability set.

Leetha's Python interpreter has file capabilities (NET_RAW, NET_ADMIN,
NET_BIND_SERVICE) baked in, so it can capture packets, enable
promiscuous mode, and bind port 443 without running as root. When the
container's bounding set doesn't include those, exec fails with
"Operation not permitted".

Run with all three capabilities:

  docker run --net=host \\
    --cap-add=NET_RAW --cap-add=NET_ADMIN --cap-add=NET_BIND_SERVICE \\
    leetha --web

Or use docker compose (docker-compose.yml already declares them).
EOF
        exit 1
    fi
done

exec leetha "$@"

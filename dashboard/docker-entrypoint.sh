#!/bin/sh
# Admina Dashboard — container init script
# Runs via /docker-entrypoint.d/ before nginx starts.
#
# With ADMINA_API_KEY set, nginx adds the key to the read-only dashboard
# routes (/api/dashboard/*, /api/stats) only, behind HTTP Basic Auth: the
# container does not start without ADMINA_DASHBOARD_PASSWORD. Without
# ADMINA_API_KEY, no key is added: the dashboard page signs in with the API
# key itself, and Basic Auth is used when a password is set. /mcp and the
# other /api/ routes are forwarded as received.
set -eu

CONF="/etc/nginx/conf.d/default.conf"
HTPASSWD="/etc/nginx/.htpasswd"
API_KEY="${ADMINA_API_KEY:-}"
DASH_USER="${ADMINA_DASHBOARD_USER:-admin}"
DASH_PASS="${ADMINA_DASHBOARD_PASSWORD:-}"

fail() {
    echo "admina-dashboard: $1" >&2
    exit 1
}

if [ -n "$API_KEY" ]; then
    [ -n "$DASH_PASS" ] || fail "ADMINA_API_KEY is set and ADMINA_DASHBOARD_PASSWORD is empty: \
set a dashboard password (./scripts/bootstrap-secrets.sh or 'make up' generate one), \
or do not pass ADMINA_API_KEY to the dashboard container."
    # The key is written into the nginx configuration as a quoted string.
    case "$API_KEY" in
        *[!A-Za-z0-9._~+/=-]*)
            fail "ADMINA_API_KEY may hold only letters, digits and . _ ~ + / = - \
for the dashboard container (openssl rand -hex 32 generates one)." ;;
    esac
fi

# Rewrites the nginx configuration with a sed script (portable: no sed -i).
edit_conf() {
    sed "$1" "$CONF" > "$CONF.tmp"
    cat "$CONF.tmp" > "$CONF"
    rm -f "$CONF.tmp"
}

# 1. The API key on the dashboard routes, or no key header at all.
if [ -n "$API_KEY" ]; then
    edit_conf "s|__ADMINA_API_KEY__|${API_KEY}|g"
else
    edit_conf "/__ADMINA_API_KEY__/d"
fi

# 2. HTTP Basic Auth.
if [ -n "$DASH_PASS" ]; then
    # The password reaches openssl on stdin, never on a command line.
    HASH=$(printf '%s' "$DASH_PASS" | openssl passwd -apr1 -stdin)
    printf '%s:%s\n' "$DASH_USER" "$HASH" > "$HTPASSWD"
    edit_conf 's|__AUTH_BASIC__|"Admina Dashboard"|g'
else
    : > "$HTPASSWD"
    edit_conf 's|__AUTH_BASIC__|off|g'
fi

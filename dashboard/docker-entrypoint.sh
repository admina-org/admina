#!/bin/sh
# Admina Dashboard — container init script
# Runs via /docker-entrypoint.d/ before nginx starts.

CONF="/etc/nginx/conf.d/default.conf"

# 1. Inject ADMINA_API_KEY into nginx config
sed -i "s|__ADMINA_API_KEY__|${ADMINA_API_KEY:-}|g" "$CONF"

# 2. Dashboard HTTP Basic Auth
DASH_USER="${ADMINA_DASHBOARD_USER:-admin}"
DASH_PASS="${ADMINA_DASHBOARD_PASSWORD:-}"

if [ -n "$DASH_PASS" ]; then
    # Generate htpasswd using openssl with password via stdin
    HASH=$(printf '%s' "$DASH_PASS" | openssl passwd -apr1 -stdin)
    printf '%s:%s\n' "$DASH_USER" "$HASH" > /etc/nginx/.htpasswd
    sed -i 's|__AUTH_BASIC__|"Admina Dashboard"|g' "$CONF"
else
    # No password — disable auth
    touch /etc/nginx/.htpasswd
    sed -i 's|__AUTH_BASIC__|off|g' "$CONF"
fi

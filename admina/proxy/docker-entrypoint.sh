#!/bin/sh
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Admina Proxy — Container Entrypoint
#
# Prints a credentials banner on startup so the user can find
# them in `docker compose logs proxy`.
# If no API key is set, prints an error with setup instructions.
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
set -e

if [ -z "$ADMINA_API_KEY" ]; then
    echo ""
    echo "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  ERROR: ADMINA_API_KEY is not set."
    echo ""
    echo "  Generate secrets first:"
    echo "    ./scripts/bootstrap-secrets.sh      # creates .env"
    echo "    docker compose up --build           # reads .env"
    echo ""
    echo "  Or use the recommended flow:"
    echo "    make up          # bootstrap + build + launch"
    echo "    admina dev       # CLI-managed launch"
    echo "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    exit 1
else
    # Mask the key — show first 8 and last 4 chars
    KEY_LEN=${#ADMINA_API_KEY}
    if [ "$KEY_LEN" -gt 12 ]; then
        KEY_PREFIX=$(echo "$ADMINA_API_KEY" | cut -c1-8)
        KEY_SUFFIX=$(echo "$ADMINA_API_KEY" | cut -c$((KEY_LEN-3))-$KEY_LEN)
        KEY_DISPLAY="${KEY_PREFIX}...${KEY_SUFFIX}"
    else
        KEY_DISPLAY="(set)"
    fi

    echo ""
    echo "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  Admina Proxy starting"
    echo ""
    echo "    API Key:    ${KEY_DISPLAY}"
    echo "    Dashboard:  http://localhost:3000  (user: admin)"
    echo "    API docs:   http://localhost:8080/docs"
    echo "    Grafana:    http://localhost:3001  (user: admin)"
    echo ""
    echo "  View full credentials:"
    echo "    cat .env"
    echo "    admina password show"
    echo "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
fi

exec "$@"

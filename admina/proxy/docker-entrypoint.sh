#!/bin/sh
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Admina Proxy — Container Entrypoint
#
# Prints a startup banner (in `docker compose logs proxy`) that says
# whether the API key is set, never any part of the key. The key comes
# from ADMINA_API_KEY or from the file named by ADMINA_API_KEY_FILE (the
# proxy reads the file). If neither is set, prints an error with setup
# instructions.
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
set -e

if [ -n "$ADMINA_API_KEY_FILE" ]; then
    KEY_STATUS="set (from ADMINA_API_KEY_FILE)"
elif [ -n "$ADMINA_API_KEY" ]; then
    KEY_STATUS="set"
else
    echo ""
    echo "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  ERROR: ADMINA_API_KEY is not set."
    echo ""
    echo "  Set ADMINA_API_KEY, or ADMINA_API_KEY_FILE to a file holding"
    echo "  the key. Generate secrets first:"
    echo "    ./scripts/bootstrap-secrets.sh      # creates .env"
    echo "    docker compose up --build           # reads .env"
    echo ""
    echo "  Or use the recommended flow:"
    echo "    make up          # bootstrap + build + launch"
    echo "    admina dev       # CLI-managed launch"
    echo "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    exit 1
fi

echo ""
echo "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Admina Proxy starting"
echo ""
echo "    API key:    ${KEY_STATUS}"
echo "    Dashboard:  http://localhost:3000  (user: admin)"
echo "    API docs:   http://localhost:8080/docs"
echo "    Grafana:    http://localhost:3001  (user: admin)"
echo ""
echo "  View full credentials:"
echo "    cat .env"
echo "    admina password show"
echo "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

exec "$@"

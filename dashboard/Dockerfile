FROM nginx:alpine
RUN apk add --no-cache openssl
# Dashboard static files
COPY dashboard/index.html /usr/share/nginx/html/index.html
COPY dashboard/heimdall.png /usr/share/nginx/html/heimdall.png
# Vendored JS dependencies — no CDN at runtime, works in air-gapped deployments
COPY dashboard/vendor/alpinejs-3.14.8.min.js /usr/share/nginx/html/vendor/alpinejs.min.js
# Inject git commit hash (auto-updated by post-commit hook)
COPY dashboard/git_commit.txt /tmp/git_commit.txt
RUN sed -i "s/%%GIT_COMMIT%%/$(cat /tmp/git_commit.txt)/g" /usr/share/nginx/html/index.html \
    && rm /tmp/git_commit.txt
# Inject version from pyproject.toml
COPY pyproject.toml /tmp/pyproject.toml
RUN VERSION=$(grep '^version' /tmp/pyproject.toml | head -1 | cut -d'"' -f2) && \
    sed -i "s/%%VERSION%%/v${VERSION}/g" /usr/share/nginx/html/index.html && \
    rm /tmp/pyproject.toml
# Nginx config with reverse proxy to admina-proxy for /api/*
COPY dashboard/nginx.conf /etc/nginx/conf.d/default.conf
# Entrypoint: inject ADMINA_API_KEY into nginx config at runtime
COPY dashboard/docker-entrypoint.sh /docker-entrypoint.d/90-api-key.sh
RUN chmod +x /docker-entrypoint.d/90-api-key.sh
EXPOSE 80
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD wget -qO- http://localhost:80/health || exit 1

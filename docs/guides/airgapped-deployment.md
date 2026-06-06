# Air-gapped deployment

Admina is designed to run in environments with no outbound Internet
access. Nothing in the running system contacts an external service:

- The dashboard ships Alpine.js as a vendored asset (no `cdn.jsdelivr.net`)
  and uses system fonts (no Google Fonts)
- The benchmark report inlines Chart.js inside the generated HTML
- All container healthchecks target `localhost` / `127.0.0.1`
- Datasource URLs in the Grafana provisioning point only at internal
  containers (`otel-collector:8889`, `clickhouse:8123`)

This guide explains how to install and operate Admina on a host that
has been disconnected from the public Internet after initial setup.

> **Status: complete for the OSS framework runtime.** The areas you
> still need to mirror yourself (PyPI, container registry, Spacy
> model, optional Rust toolchain) are external to the framework and
> covered below.

---

## What you need to mirror once

The Admina runtime itself does not download anything at startup.
Everything that needs to come from the Internet does so **at install
or build time**, and is therefore mirror-able.

### 1. Container images

Admina's `docker-compose.yml` references six base images. Pull
them on a connected host, save with `docker save`, transfer, and
load on the air-gapped host.

```bash
# On a host with Internet access:
docker pull python:3.11-slim
docker pull nginx:alpine
docker pull clickhouse/clickhouse-server:24.3
docker pull redis:7-alpine
docker pull grafana/grafana:11.0.0
docker pull otel/opentelemetry-collector-contrib:0.96.0
# Optional: an S3-compatible object store for the forensic backend
# (only if you use FORENSIC_BACKEND=s3 — see below). E.g. SeaweedFS:
#   docker pull chrislusf/seaweedfs:latest

docker save \
    python:3.11-slim \
    nginx:alpine \
    clickhouse/clickhouse-server:24.3 \
    redis:7-alpine \
    grafana/grafana:11.0.0 \
    otel/opentelemetry-collector-contrib:0.96.0 \
  | gzip > admina-images.tar.gz

# Transfer admina-images.tar.gz to the air-gapped host, then:
gunzip -c admina-images.tar.gz | docker load
```

If you operate a private registry, `docker tag` + `docker push` to
`registry.internal/admina/<image>` and update the `image:` lines in
`docker-compose.yml` accordingly.

### 2. Python wheels

`pip install admina-framework[full]` resolves ~150 wheels from PyPI.
Pre-download them once on a connected host, then point pip at the
local directory.

```bash
# On a host with Internet access:
mkdir -p admina-wheels
uv pip download \
    admina-framework[full] \
    --dest admina-wheels \
    --python-version 3.11 \
    --platform-extra manylinux2014_x86_64

# Transfer admina-wheels/ to the air-gapped host, then:
uv pip install --no-index --find-links ./admina-wheels admina-framework[full]
```

For full reproducibility, pin the lock file: `uv lock --frozen`
produces `uv.lock` which records exact hashes for every dep.

### 3. Spacy model (optional, only if you use the `[nlp]` extra)

```bash
# On a host with Internet access:
wget https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-3.7.1/en_core_web_sm-3.7.1-py3-none-any.whl

# Transfer the wheel, then on the air-gapped host:
uv pip install ./en_core_web_sm-3.7.1-py3-none-any.whl
```

Without the `[nlp]` extra, the PII scanner falls back to regex-only
mode (still detects email/phone/SSN/CC/IBAN/IP/EU national IDs).

### 4. Rust toolchain (optional, only if you build `admina-core` from source)

The pre-built `admina-core` wheels on PyPI are sufficient for most
deployments — vendor those (point 2 above). To build the Rust engine
on the air-gapped host:

```bash
# On a connected host:
cargo vendor > vendor.toml          # mirrors crates.io deps
tar czf admina-rust-vendor.tar.gz vendor/ vendor.toml
# Transfer + extract on air-gapped host, then:
maturin build --release --offline
```

---

## Forensic storage backend on air-gapped

The default `docker-compose.yml` uses the filesystem backend (zero
external dependencies). For persistent object storage, the `s3` backend
(boto3) works with any S3-compatible service. Choose one of:

### Option A — Filesystem backend (recommended for single-host)

The simplest air-gapped setup. Zero external dependencies.

```yaml
# admina.yaml
domains:
  compliance:
    forensic:
      backend: filesystem
      base_dir: /var/lib/admina/forensic
```

Records are written as JSON files with SHA-256 chained hashes. The
chain integrity check works exactly the same as the S3 backend.

### Option B — Any S3-compatible object store

Admina's S3 backend uses the `boto3` client, which works with any
S3-compatible service. Tested: AWS S3, MinIO servers, Cloudflare R2,
Backblaze B2, SeaweedFS, Garage, Ceph RGW. Mirror your choice via Docker:

```yaml
# docker-compose.yml override — drop in your S3 service
seaweedfs:
  image: chrislusf/seaweedfs:latest
  command: "server -s3 -filer"
  ports:
    - "127.0.0.1:8333:8333"   # S3 API
```

```yaml
# admina.yaml
domains:
  compliance:
    forensic:
      backend: s3
      endpoint: http://seaweedfs:8333
      bucket: forensic-blackbox
```

> **Note**: the legacy MinIO-SDK backend was removed in 0.9.5. MinIO
> servers remain fully supported through the `s3` backend — point
> `FORENSIC_S3_ENDPOINT` at your MinIO server (it speaks the S3 API).

---

## Verifying the runtime is air-gapped

After installation, run the included audit helper to prove the
running system has no outbound network calls:

```bash
# 1. From the dashboard host, confirm zero external requests
docker compose up -d
admina doctor                 # all checks should pass

# 2. Open the dashboard in a browser, then in DevTools → Network:
# - Filter by "Domain" → only `localhost` should appear
# - The vendored Alpine.js loads from /vendor/alpinejs.min.js
# - System fonts only (no Google Fonts)

# 3. Network-level verification (optional):
sudo iptables -A OUTPUT -p tcp --dport 443 -j REJECT
sudo iptables -A OUTPUT -p tcp --dport 80 -j REJECT
docker compose restart
admina doctor                 # should still pass
```

---

## Updates without Internet

Update by re-running steps 1-3 above on a connected host with the
new versions, then transferring the artifacts. Admina follows
semantic versioning: minor bumps within `0.9.x` are compatible,
major bumps will be noted in `CHANGELOG.md` with explicit migration
instructions.

For air-gapped CVE patching: subscribe to the GitHub repository's
Security Advisories on a separate machine, then pull the patched
container image / wheel as in steps 1-2.

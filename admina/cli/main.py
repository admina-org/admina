# Copyright © 2025–2026 Stefano Noferi & Admina contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Admina CLI — project scaffolding and management commands.

Entry point: ``admina = "cli.main:app"`` in pyproject.toml.
"""

from __future__ import annotations

import hashlib
import logging
import os
import shutil
import subprocess
import sys
import time
import webbrowser
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

import click
import yaml
from jinja2 import Environment, FileSystemLoader, select_autoescape

from admina import __version__
from admina.core.secrets import SecretVault, validate_password

_TEMPLATES_DIR = Path(__file__).parent / "templates"

# Domains the user can toggle on/off during ``admina init``.
AVAILABLE_DOMAINS: dict[str, str] = {
    "data_sovereignty": "PII redaction, data residency, classification",
    "ai_infra": "LLM engine, RAG pipeline, Web UI",
    "agent_security": "MCP proxy, firewall, loop breaker",
    "compliance": "Forensic black-box, EU AI Act, OTEL",
}

# Modules map to domains for the --modules shorthand.
MODULE_TO_DOMAIN: dict[str, str] = {
    "model": "ai_infra",
    "data": "data_sovereignty",
    "compliance": "compliance",
    "security": "agent_security",
}


def _bootstrap_secrets(project_dir: Path, *, force: bool = False) -> dict[str, str] | None:
    """Auto-generate secrets on first launch. Returns secrets if generated."""
    vault = SecretVault(project_dir)
    if vault.is_initialized and not force:
        return None

    generated = vault.bootstrap()

    # Write .env with vault secrets so docker compose can read them
    vault.write_dotenv(project_dir / ".env")

    click.echo()
    click.echo("  " + "=" * 54)
    click.echo("  First-boot credentials generated!")
    click.echo()
    click.echo(f"    API Key:    {generated['ADMINA_API_KEY']}")
    click.echo(f"    Password:   {generated['ADMINA_DASHBOARD_PASSWORD']}")
    click.echo("                (dashboard, Grafana, ClickHouse)")
    click.echo()
    click.echo("    Save these now — they will NOT be shown again.")
    click.echo("    View:  admina password show")
    click.echo("    Reset: admina password reset")
    click.echo("  " + "=" * 54)
    click.echo()
    return generated


def _jinja_env() -> Environment:
    """Create a Jinja2 environment pointing at the CLI templates dir.

    Templates here are YAML / Python / .env files, not HTML, so XSS
    isn't a risk. We still enable selective autoescape (html/xml) as
    a defensive default in case a future template ships HTML.
    """
    return Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
        keep_trailing_newline=True,
    )


def _prompt_domains() -> list[str]:
    """Interactively ask the user which domains to enable."""
    click.echo("\nAvailable domains:")
    keys = list(AVAILABLE_DOMAINS.keys())
    for i, (name, desc) in enumerate(AVAILABLE_DOMAINS.items(), 1):
        click.echo(f"  {i}. {name} — {desc}")
    click.echo()
    selection = click.prompt(
        "Select domains (comma-separated numbers, or 'all')",
        default="all",
    )
    if selection.strip().lower() == "all":
        return keys
    chosen: list[str] = []
    for part in selection.split(","):
        part = part.strip()
        if part.isdigit():
            idx = int(part) - 1
            if 0 <= idx < len(keys):
                chosen.append(keys[idx])
    return chosen or keys


def _resolve_domains(
    full_stack: bool,
    modules: str | None,
    interactive: bool = True,
) -> list[str]:
    """Determine which domains to enable based on CLI flags."""
    if full_stack:
        return list(AVAILABLE_DOMAINS.keys())
    if modules:
        domains: list[str] = []
        for m in modules.split(","):
            m = m.strip().lower()
            domain = MODULE_TO_DOMAIN.get(m)
            if domain and domain not in domains:
                domains.append(domain)
        return domains or list(AVAILABLE_DOMAINS.keys())
    if interactive and sys.stdin.isatty():
        return _prompt_domains()
    return list(AVAILABLE_DOMAINS.keys())


def _generate_file(
    env: Environment,
    template_name: str,
    output_path: Path,
    context: dict[str, object],
) -> None:
    """Render a Jinja2 template and write it to *output_path*."""
    tmpl = env.get_template(template_name)
    content = tmpl.render(**context)
    output_path.write_text(content)


def _scaffold_project(
    project_dir: Path,
    domains: list[str],
    project_name: str,
) -> list[str]:
    """Generate the full project skeleton and return list of created files."""
    env = _jinja_env()
    created: list[str] = []

    context: dict[str, object] = {
        "project_name": project_name,
        "domains": {d: d in domains for d in AVAILABLE_DOMAINS},
    }

    # admina.yaml
    _generate_file(env, "admina.yaml.j2", project_dir / "admina.yaml", context)
    created.append("admina.yaml")

    # docker-compose.yml
    _generate_file(
        env,
        "docker-compose.yml.j2",
        project_dir / "docker-compose.yml",
        context,
    )
    created.append("docker-compose.yml")

    # .env with placeholder secrets
    env_file = project_dir / ".env"
    if not env_file.exists():
        _generate_file(env, "env.j2", env_file, context)
        created.append(".env")

    # Example main.py
    _generate_file(env, "main.py.j2", project_dir / "main.py", context)
    created.append("main.py")

    return created


@click.group()
@click.version_option(version=__version__, prog_name="admina")
def app() -> None:
    """Admina — governed AI development framework."""


@app.command()
@click.argument("project_name", default="my-admina-project")
@click.option(
    "--full-stack",
    is_flag=True,
    default=False,
    help="Enable all domains.",
)
@click.option(
    "--modules",
    default=None,
    help="Comma-separated modules: model, data, compliance, security.",
)
@click.option(
    "--no-pull",
    is_flag=True,
    default=False,
    help="Skip docker compose pull.",
)
def init(
    project_name: str,
    full_stack: bool,
    modules: str | None,
    no_pull: bool,
) -> None:
    """Scaffold a new Admina project.

    Creates admina.yaml, docker-compose.yml, .env, and an example main.py
    inside PROJECT_NAME directory.
    """
    # 1. Resolve domains
    domains = _resolve_domains(full_stack, modules)

    click.echo(f"\n  Creating project: {project_name}")
    click.echo(f"  Domains: {', '.join(domains)}\n")

    # 2. Create project directory
    project_dir = Path.cwd() / project_name
    project_dir.mkdir(parents=True, exist_ok=True)

    # 3. Generate files
    created = _scaffold_project(project_dir, domains, project_name)
    for f in created:
        click.echo(f"  ✓ {f}")

    # 4. Bootstrap secrets (first-time setup)
    _bootstrap_secrets(project_dir)

    # 5. Docker compose pull (optional)
    if not no_pull and shutil.which("docker"):
        click.echo("\n  Pulling Docker images...")
        result = subprocess.run(
            ["docker", "compose", "pull"],
            cwd=str(project_dir),
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            click.echo("  ✓ Docker images pulled")
        else:
            click.echo("  ⚠ docker compose pull failed (you can run it later)")

    # 5. Print next steps — tailored to what the user actually has installed.
    click.echo(_format_next_steps(project_name))


def _format_next_steps(project_name: str) -> str:
    """Build the post-init "Next steps" message based on detected extras.

    Honest output: only suggest commands that will work with the user's
    current install. Missing prerequisites are surfaced explicitly with
    the exact upgrade command.
    """
    proxy_ok = _proxy_extra_installed()
    docker_ok = shutil.which("docker") is not None

    lines: list[str] = [
        "",
        "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        "  Project ready!",
        "",
        "  Next steps:",
        f"    cd {project_name}",
        "    python main.py                # SDK example — works with any install",
    ]
    if proxy_ok:
        lines.append("    admina dev                    # local proxy + dashboard on :3000")
    else:
        lines.extend(
            [
                "",
                "  To run the local proxy + dashboard (admina dev), install the [proxy] extra:",
                "    pip install 'admina-framework[proxy]' --upgrade",
            ]
        )
    if docker_ok:
        lines.append(
            "    admina dev --stack            # full Docker stack "
            "(proxy + redis + clickhouse + grafana)"
        )
    else:
        lines.extend(
            [
                "",
                "  To run the full Docker stack (admina dev --stack), install Docker:",
                "    https://docs.docker.com/get-docker/",
            ]
        )
    lines.extend(
        [
            "",
            "  Docs: https://admina.org/docs",
            "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
            "",
        ]
    )
    return "\n".join(lines)


# ── admina dev helpers ─────────────────────────────────────


# Services and their health-check URLs, keyed by compose service name.
SERVICE_ENDPOINTS: dict[str, dict[str, str]] = {
    "proxy": {
        "label": "Proxy API",
        "url": "http://localhost:8080",
        "health": "http://localhost:8080/health",
    },
    "dashboard": {
        "label": "Dashboard",
        "url": "http://localhost:3000",
        "health": "http://localhost:3000/",
    },
    "grafana": {
        "label": "Grafana",
        "url": "http://localhost:3001",
        "health": "http://localhost:3001/api/health",
    },
}


def _load_admina_yaml(project_dir: Path) -> dict[str, object]:
    """Load and return the parsed admina.yaml from *project_dir*.

    Raises:
        SystemExit: If the file does not exist.
    """
    yaml_path = project_dir / "admina.yaml"
    if not yaml_path.is_file():
        click.echo(
            "ERROR: admina.yaml not found in current directory. Run 'admina init' first.",
            err=True,
        )
        raise SystemExit(1)
    with open(yaml_path) as fh:
        data = yaml.safe_load(fh) or {}
    return data


def _yaml_hash(project_dir: Path) -> str:
    """Return a SHA-256 hex digest of admina.yaml for change detection."""
    content = (project_dir / "admina.yaml").read_bytes()
    return hashlib.sha256(content).hexdigest()


def _domains_from_yaml(data: dict[str, object]) -> list[str]:
    """Extract enabled domain names from a parsed admina.yaml dict."""
    domains_raw = data.get("domains", {})
    if not isinstance(domains_raw, dict):
        return list(AVAILABLE_DOMAINS.keys())
    enabled: list[str] = []
    for name in AVAILABLE_DOMAINS:
        section = domains_raw.get(name, {})
        if isinstance(section, dict) and section.get("enabled", False):
            enabled.append(name)
    return enabled


def _maybe_regenerate_compose(project_dir: Path, data: dict[str, object]) -> bool:
    """Re-generate docker-compose.yml if admina.yaml has changed.

    Writes a ``.admina_compose_hash`` marker to track the last YAML hash.
    Returns True if the compose file was regenerated.
    """
    current_hash = _yaml_hash(project_dir)
    hash_file = project_dir / ".admina_compose_hash"

    if hash_file.is_file() and hash_file.read_text().strip() == current_hash:
        return False

    domains = _domains_from_yaml(data)
    project_name = project_dir.name
    env = _jinja_env()
    context: dict[str, object] = {
        "project_name": project_name,
        "domains": {d: d in domains for d in AVAILABLE_DOMAINS},
        "with_llm": True,  # init scaffolds the full template; admina dev gates at runtime
    }
    _generate_file(env, "docker-compose.yml.j2", project_dir / "docker-compose.yml", context)
    hash_file.write_text(current_hash)
    return True


def _check_docker() -> bool:
    """Return True if ``docker`` is available on PATH."""
    return shutil.which("docker") is not None


def _health_check(
    url: str,
    *,
    timeout: float = 30.0,
    interval: float = 2.0,
) -> bool:
    """Poll *url* until it returns HTTP 2xx or *timeout* expires.

    Returns True if the service became healthy, False on timeout.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            resp = urlopen(url, timeout=3)  # noqa: S310 — trusted localhost URL
            if 200 <= resp.status < 400:
                return True
        except (URLError, OSError, TimeoutError):
            pass
        time.sleep(interval)
    return False


def _wait_for_services(
    services: list[dict[str, str]],
    timeout: float = 30.0,
    interval: float = 2.0,
) -> list[dict[str, object]]:
    """Poll health endpoints for each service.

    Returns a list of dicts with keys ``label``, ``url``, ``healthy``.
    """
    results: list[dict[str, object]] = []
    for svc in services:
        label = svc["label"]
        click.echo(f"  Waiting for {label}...", nl=False)
        healthy = _health_check(svc["health"], timeout=timeout, interval=interval)
        if healthy:
            click.echo(" ready")
        else:
            click.echo(" timeout")
        results.append({"label": label, "url": svc["url"], "healthy": healthy})
    return results


def _print_dev_summary(results: list[dict[str, object]]) -> None:
    """Print a summary table of running services and next steps."""
    click.echo("\n  Admina development stack is running\n")
    click.echo("  Services:")
    for r in results:
        status = "ready" if r["healthy"] else "unhealthy"
        click.echo(f"    {r['label']:<20s} {r['url']}  ({status})")
    click.echo("""
  Logs:
    docker compose logs -f

  Stop:
    docker compose down

  Next steps:
    Dashboard:  http://localhost:3000
    API docs:   http://localhost:8080/docs
    Health:     curl http://localhost:8080/health
""")


def _find_free_port(preferred: int, host: str, search_window: int = 10) -> int:
    """Return *preferred* if it can be bound on *host*, else the next free
    port in ``[preferred+1, preferred+search_window-1]``.

    Raises:
        RuntimeError: If no port in the window is free.
    """
    import socket as _socket

    bind_host = "127.0.0.1" if host in ("0.0.0.0", "::", "::0") else host
    for port in range(preferred, preferred + search_window):
        try:
            with _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM) as s:
                # Don't set SO_REUSEADDR — we want a strict "is this port
                # already serving something" check, not a "could be shared" one.
                s.bind((bind_host, port))
                return port
        except OSError:
            continue
    raise RuntimeError(
        f"No free port in [{preferred}, {preferred + search_window - 1}] on {bind_host}"
    )


def _list_local_ipv4() -> list[str]:
    """Return all IPv4 addresses reachable on this host (best-effort, stdlib only).

    Always includes 127.0.0.1. Additionally probes the default-route address
    (via UDP-connect trick) and `socket.gethostbyname_ex`, which together
    cover the common cases: LAN IP, hostname-mapped IPs, multi-NIC setups.
    """
    import socket as _socket

    ips: set[str] = {"127.0.0.1"}
    try:
        with _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM) as s:
            s.settimeout(0.5)
            s.connect(("8.8.8.8", 80))
            ips.add(s.getsockname()[0])
    except OSError:
        pass
    try:
        ips.update(_socket.gethostbyname_ex(_socket.gethostname())[2])
    except (_socket.herror, _socket.gaierror, OSError):
        pass
    # Sort: loopback first, then lexicographic
    return sorted(ips, key=lambda ip: (ip != "127.0.0.1", ip))


def _proxy_extra_installed() -> bool:
    """True if uvicorn + fastapi (the [proxy] extra) are importable."""
    try:
        import fastapi  # noqa: F401
        import uvicorn  # noqa: F401
    except ImportError:
        return False
    return True


def _require_proxy_extra_for_local_dev() -> None:
    """Exit cleanly with an actionable message when [proxy] is missing.

    Local-mode `admina dev` shells out to uvicorn, which lives only in the
    [proxy] extra. Without an early check, the user sees a cryptic
    `No module named uvicorn` from python -m uvicorn.
    """
    if _proxy_extra_installed():
        return
    click.echo("", err=True)
    click.echo("  admina dev (local mode) requires the [proxy] extra.", err=True)
    click.echo("  Install one of:", err=True)
    click.echo(
        "    pip install 'admina-framework[proxy]' --upgrade",
        err=True,
    )
    click.echo(
        "    pip install 'admina-framework[full]' --upgrade   # adds NLP + telemetry",
        err=True,
    )
    click.echo("", err=True)
    click.echo(
        "  Or run the full Docker stack (no [proxy] extra required):",
        err=True,
    )
    click.echo("    admina dev --stack", err=True)
    click.echo("", err=True)
    raise SystemExit(1)


def _run_local(
    project_dir: Path,
    vault: SecretVault,
    *,
    no_browser: bool,
    port: int,
    host: str,
) -> None:
    """Run proxy + dashboard as a single uvicorn process (no Docker)."""
    _require_proxy_extra_for_local_dev()

    # Auto-detect free port: if preferred is taken (Docker Desktop, Grafana,
    # another node dev server on :3000…), fall back to the next free port.
    try:
        actual_port = _find_free_port(port, host)
    except RuntimeError as exc:
        click.echo(f"ERROR: {exc}", err=True)
        raise SystemExit(1) from exc
    if actual_port != port:
        click.echo(f"  ⚠ Port {port} is already in use — falling back to {actual_port}.")
    port = actual_port

    env = os.environ.copy()
    env.update(vault.export_env())
    # Local dev defaults — sane for single-user localhost.
    env.setdefault("FORENSIC_BACKEND", "memory")
    env.setdefault("OTEL_ENDPOINT", "")
    env.setdefault("REDIS_URL", "")
    env.setdefault("CLICKHOUSE_HOST", "")
    env.setdefault("UPSTREAM_MCP_URL", "")
    env.setdefault("LOG_LEVEL", "INFO")

    cmd = [
        sys.executable,
        "-m",
        "uvicorn",
        "admina.proxy.main:app",
        "--host",
        host,
        "--port",
        str(port),
        "--log-level",
        "info",
    ]

    # Display URL: if listening on all interfaces, prefer localhost for the
    # banner but warn that the proxy is exposed to the LAN.
    is_public = host in ("0.0.0.0", "::", "::0")
    display_host = "localhost" if host in ("127.0.0.1", "0.0.0.0", "::", "::0") else host

    click.echo(f"\n  Starting Admina proxy + dashboard on http://{display_host}:{port}")
    click.echo("  Mode: local (no Docker)")
    click.echo("  Forensic backend: in-memory (events live for the process lifetime)")
    if is_public:
        click.echo(
            f"  ⚠ Listening on {host}:{port} — accessible from the LAN. "
            "Auth: API key required for /api/*."
        )
    click.echo("  Stop with Ctrl+C\n")

    proc = subprocess.Popen(cmd, cwd=str(project_dir), env=env)

    # Wait for /health to become reachable, then open the browser
    healthcheck_host = "127.0.0.1" if host in ("0.0.0.0", "127.0.0.1") else host
    healthy = _health_check(f"http://{healthcheck_host}:{port}/health", timeout=15.0, interval=0.5)
    if healthy:
        # When bound to all interfaces, enumerate each reachable address.
        # Otherwise show the single configured host.
        if is_public:
            click.echo("  Ready. Reachable URLs:")
            for ip in _list_local_ipv4():
                label = "localhost" if ip == "127.0.0.1" else "LAN"
                click.echo(f"    http://{ip}:{port}  ({label})")
        else:
            click.echo(f"  Ready → http://{display_host}:{port}")
        if not no_browser:
            webbrowser.open(f"http://{display_host}:{port}")
    else:
        click.echo("  WARNING: proxy did not become healthy within 15s — continuing")

    try:
        proc.wait()
    except KeyboardInterrupt:
        click.echo("\n  Stopping...")
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def _run_compose(
    project_dir: Path,
    data: dict[str, object],
    vault: SecretVault,
    *,
    no_browser: bool,
    no_build: bool,
    detach: bool,
    with_llm: bool,
) -> None:
    """Run the Docker compose stack."""
    if not _check_docker():
        click.echo(
            "ERROR: --stack requires Docker. Install Docker Desktop, "
            "or run `admina dev` without --stack for the local mode.",
            err=True,
        )
        raise SystemExit(1)

    # Regenerate compose if admina.yaml hash changed; force regenerate if
    # the with-llm tier toggles (track it in the hash so cache invalidates).
    current_hash = _yaml_hash(project_dir) + (":with_llm" if with_llm else ":stack")
    hash_file = project_dir / ".admina_compose_hash"
    regen_needed = not hash_file.is_file() or hash_file.read_text().strip() != current_hash
    if regen_needed:
        domains = _domains_from_yaml(data)
        project_name = project_dir.name
        env_j = _jinja_env()
        context: dict[str, object] = {
            "project_name": project_name,
            "domains": {d: d in domains for d in AVAILABLE_DOMAINS},
            "with_llm": with_llm,
        }
        _generate_file(env_j, "docker-compose.yml.j2", project_dir / "docker-compose.yml", context)
        hash_file.write_text(current_hash)
        click.echo("  docker-compose.yml regenerated")
    else:
        click.echo("  docker-compose.yml is up to date")
    domains = _domains_from_yaml(data)

    compose_cmd: list[str] = ["docker", "compose", "up"]
    if not no_build:
        compose_cmd.append("--build")
    if detach:
        compose_cmd.append("-d")

    compose_env = os.environ.copy()
    compose_env.update(vault.export_env())

    click.echo(f"  Running: {' '.join(compose_cmd)}\n")

    # Always start in detached mode internally so we can health-check.
    detach_cmd = compose_cmd if detach else compose_cmd + ["-d"]
    result = subprocess.run(
        detach_cmd,
        cwd=str(project_dir),
        env=compose_env,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        click.echo(
            f"ERROR: docker compose up failed.\n{result.stderr}\nTry: docker compose logs",
            err=True,
        )
        raise SystemExit(1)

    active_services: list[dict[str, str]] = []
    for svc_name, svc_info in SERVICE_ENDPOINTS.items():
        if svc_name == "proxy" and "agent_security" not in domains:
            continue
        if svc_name == "grafana" and "compliance" not in domains:
            continue
        active_services.append(svc_info)

    click.echo()
    results = _wait_for_services(active_services)

    if not no_browser:
        webbrowser.open("http://localhost:3000")

    _print_dev_summary(results)

    if not detach:
        click.echo("  Attaching to logs (Ctrl+C to stop)...\n")
        try:
            subprocess.run(["docker", "compose", "logs", "-f"], cwd=str(project_dir))
        except KeyboardInterrupt:
            click.echo("\n  Stopping...")


@app.command()
@click.option(
    "--stack",
    is_flag=True,
    default=False,
    help="Run the full Docker stack (proxy + dashboard + redis + clickhouse + otel + grafana).",
)
@click.option(
    "--with-llm",
    is_flag=True,
    default=False,
    help="Add local LLM services (ollama + chromadb + open-webui) to --stack. Implies --stack.",
)
@click.option("--no-browser", is_flag=True, default=False, help="Skip opening browser.")
@click.option("--no-build", is_flag=True, default=False, help="Use existing images (--stack only).")
@click.option("--detach", is_flag=True, default=False, help="Run in background (--stack only).")
@click.option(
    "--port",
    type=int,
    default=3000,
    help="Port for local mode (default 3000 — same as Docker stack dashboard).",
)
@click.option(
    "--host",
    type=str,
    default="127.0.0.1",
    help=(
        "Bind address for local mode (default 127.0.0.1). "
        "Use 0.0.0.0 to listen on all interfaces (LAN access)."
    ),
)
@click.option(
    "--public",
    is_flag=True,
    default=False,
    help="Shortcut for --host 0.0.0.0 (listen on all interfaces).",
)
def dev(
    stack: bool,
    with_llm: bool,
    no_browser: bool,
    no_build: bool,
    detach: bool,
    port: int,
    host: str,
    public: bool,
) -> None:
    """Start Admina locally.

    Three modes:

    \b
      admina dev              Local mode (default): one uvicorn process,
                              dashboard served on the same port. No Docker.
      admina dev --stack      Docker compose: proxy + dashboard + redis +
                              clickhouse + otel + grafana.
      admina dev --with-llm   --stack plus local LLM services
                              (ollama + chromadb + open-webui).

    Local-mode network binding:

    \b
      admina dev                          → 127.0.0.1:3000 (localhost only)
      admina dev --host 0.0.0.0           → all interfaces (LAN access)
      admina dev --public                 → shortcut for --host 0.0.0.0
      admina dev --port 9000              → custom port
    """
    project_dir = Path.cwd()

    # Common bootstrap: admina.yaml + secrets vault
    data = _load_admina_yaml(project_dir)
    click.echo("  admina.yaml loaded")

    vault = SecretVault(project_dir)
    if not vault.is_initialized:
        _bootstrap_secrets(project_dir)
    else:
        click.echo("  Secrets vault loaded")
        vault.write_dotenv(project_dir / ".env")

    if stack or with_llm:
        _run_compose(
            project_dir,
            data,
            vault,
            no_browser=no_browser,
            no_build=no_build,
            detach=detach,
            with_llm=with_llm,
        )
    else:
        bind_host = "0.0.0.0" if public else host
        _run_local(
            project_dir,
            vault,
            no_browser=no_browser,
            port=port,
            host=bind_host,
        )


# ── admina plugin helpers ──────────────────────────────────


# Maps --type flag values to the registry type keys.
PLUGIN_TYPE_CHOICES: list[str] = [
    "model_adapter",
    "data_connector",
    "governance_guard",
    "compliance_template",
    "transport_adapter",
    "forensic_store",
    "auth_provider",
    "pii_engine",
    "alert_channel",
]

# Maps type key → (base class name, name property, category dir)
_SCAFFOLD_META: dict[str, tuple[str, str, str]] = {
    "model_adapter": ("BaseModelAdapter", "name", "adapters"),
    "data_connector": ("BaseDataConnector", "name", "connectors"),
    "governance_guard": ("BaseGovernanceGuard", "name", "guards"),
    "compliance_template": ("BaseComplianceTemplate", "framework_name", "compliance"),
    "transport_adapter": ("BaseTransportAdapter", "protocol_name", "transports"),
    "forensic_store": ("BaseForensicStore", "store_name", "forensic"),
    "auth_provider": ("BaseAuthProvider", "provider_name", "auth"),
    "pii_engine": ("BasePIIEngine", "supported_languages", "pii"),
    "alert_channel": ("BaseAlertChannel", "channel_name", "alerts"),
}


def _pip_install(package: str) -> subprocess.CompletedProcess[str]:
    """Run ``pip install <package>`` and return the result."""
    return subprocess.run(
        [sys.executable, "-m", "pip", "install", package],
        capture_output=True,
        text=True,
    )


def _discover_and_list_plugins() -> dict[str, dict[str, type]]:
    """Run plugin discovery and return all registered plugins by type."""
    from admina.plugins.registry import PluginRegistry

    registry = PluginRegistry()
    registry.discover()
    return registry.list_all()


def _scaffold_plugin(
    plugin_name: str,
    plugin_type: str,
    output_dir: Path,
) -> list[str]:
    """Generate boilerplate files for a new plugin.

    Returns list of created file paths (relative to *output_dir*).
    """
    base_class, name_prop, _category = _SCAFFOLD_META[plugin_type]
    class_name = "".join(w.capitalize() for w in plugin_name.replace("-", "_").split("_"))

    output_dir.mkdir(parents=True, exist_ok=True)

    env = _jinja_env()
    context: dict[str, object] = {
        "plugin_name": plugin_name,
        "plugin_type": plugin_type,
        "base_class": base_class,
        "class_name": class_name,
        "name_property": name_prop,
        "needs_any": plugin_type in {"model_adapter", "data_connector", "transport_adapter", "auth_provider"},
    }

    created: list[str] = []

    # Main plugin module
    plugin_file = output_dir / f"{plugin_name.replace('-', '_')}.py"
    _generate_file(env, "plugin.py.j2", plugin_file, context)
    created.append(plugin_file.name)

    # Test file
    tests_dir = output_dir / "tests"
    tests_dir.mkdir(exist_ok=True)
    test_file = tests_dir / f"test_{plugin_name.replace('-', '_')}.py"
    _generate_file(env, "plugin_test.py.j2", test_file, context)
    created.append(f"tests/{test_file.name}")

    # pyproject.toml
    pyproject_file = output_dir / "pyproject.toml"
    _generate_file(env, "plugin_pyproject.toml.j2", pyproject_file, context)
    created.append("pyproject.toml")

    # README
    readme_file = output_dir / "README.md"
    _generate_file(env, "plugin_readme.md.j2", readme_file, context)
    created.append("README.md")

    return created


@app.group()
def plugin() -> None:
    """Manage Admina plugins."""


@plugin.command("install")
@click.argument("package_name")
def plugin_install(package_name: str) -> None:
    """Install an Admina plugin via pip and register it.

    PACKAGE_NAME is a pip-installable package (e.g. admina-adapter-bedrock).
    """
    click.echo(f"  Installing {package_name}...")
    result = _pip_install(package_name)

    if result.returncode != 0:
        click.echo(f"  ERROR: pip install failed.\n{result.stderr}", err=True)
        raise SystemExit(1)

    click.echo(f"  Installed {package_name}")

    # Add to admina.yaml plugins list if present
    yaml_path = Path.cwd() / "admina.yaml"
    if yaml_path.is_file():
        data = yaml.safe_load(yaml_path.read_text()) or {}
        plugins = data.get("plugins", [])
        if not isinstance(plugins, list):
            plugins = []
        module_name = package_name.replace("-", "_")
        if module_name not in plugins:
            plugins.append(module_name)
            data["plugins"] = plugins
            yaml_path.write_text(yaml.dump(data, default_flow_style=False, sort_keys=False))
            click.echo(f"  Added {module_name} to admina.yaml plugins list")

    click.echo(f"\n  Plugin {package_name} is ready to use.")


def _plugin_install_path(cls: type) -> str:
    """Return the source file path of a plugin class.

    Falls back to ``cls.__module__`` if the file cannot be resolved
    (e.g., dynamic classes or zip-imports).
    """
    import inspect

    try:
        path = Path(inspect.getfile(cls)).resolve()
    except (TypeError, OSError):
        return f"<module {cls.__module__}>"
    # Make paths under the installed admina package readable as
    # "admina/plugins/.../foo.py" rather than absolute site-packages.
    try:
        admina_pkg_root = Path(__file__).resolve().parents[1]
        return str(path.relative_to(admina_pkg_root.parent))
    except ValueError:
        return str(path)


@plugin.command("list")
def plugin_list() -> None:
    """List all installed Admina plugins by type, with their source path."""
    all_plugins = _discover_and_list_plugins()
    total = 0

    click.echo("\n  Installed plugins:\n")
    for type_key in PLUGIN_TYPE_CHOICES:
        plugins = all_plugins.get(type_key, {})
        if plugins:
            label = type_key.replace("_", " ").title()
            click.echo(f"  {label}:")
            for name, cls in sorted(plugins.items()):
                path = _plugin_install_path(cls)
                click.echo(f"    - {name}")
                click.echo(f"        module: {cls.__module__}")
                click.echo(f"        path:   {path}")
                total += 1
            click.echo()

    if total == 0:
        click.echo("  No plugins found.")
    else:
        click.echo(f"  Total: {total} plugin(s)")


@plugin.command("create")
@click.argument("plugin_name")
@click.option(
    "--type",
    "plugin_type",
    type=click.Choice(PLUGIN_TYPE_CHOICES),
    default="model_adapter",
    help="Plugin type to scaffold.",
)
def plugin_create(plugin_name: str, plugin_type: str) -> None:
    """Scaffold boilerplate for a new Admina plugin.

    Creates a directory with the plugin module, tests, pyproject.toml,
    and README.
    """
    output_dir = Path.cwd() / plugin_name

    if output_dir.exists() and any(output_dir.iterdir()):
        click.echo(f"  ERROR: Directory {plugin_name}/ already exists and is not empty.", err=True)
        raise SystemExit(1)

    click.echo(f"\n  Scaffolding plugin: {plugin_name}")
    click.echo(f"  Type: {plugin_type}\n")

    created = _scaffold_plugin(plugin_name, plugin_type, output_dir)
    for f in created:
        click.echo(f"  {f}")

    click.echo(f"""
  Plugin scaffolded in {plugin_name}/

  Next steps:
    cd {plugin_name}
    # Edit {created[0]} to implement your plugin
    pip install -e .
    admina plugin list
""")


@app.command()
def doctor() -> None:
    """Check Admina installation health.

    Verifies Python version, core dependencies, optional extras,
    governance engines, and infrastructure connectivity.
    """
    import platform

    ok_mark = "[OK]"
    warn_mark = "[WARN]"
    fail_mark = "[FAIL]"
    issues: list[str] = []

    click.echo("")
    click.echo("=" * 55)
    click.echo("  Admina Doctor — Installation Health Check")
    click.echo("=" * 55)

    # ── Python version ───────────────────────────────────────
    py_ver = platform.python_version()
    py_ok = tuple(int(x) for x in py_ver.split(".")[:2]) >= (3, 10)
    click.echo(f"\n  Python:  {py_ver}  {ok_mark if py_ok else fail_mark}")
    if not py_ok:
        issues.append("Python >= 3.10 required")

    # ── Admina version ───────────────────────────────────────
    try:
        from admina import __version__

        click.echo(f"  Admina:  {__version__}  {ok_mark}")
    except ImportError:
        click.echo(f"  Admina:  not installed  {fail_mark}")
        issues.append("Run: pip install -e .")

    # ── Core deps ────────────────────────────────────────────
    click.echo("\n  Core dependencies:")
    for mod_name, pkg_name in [("yaml", "pyyaml"), ("click", "click"), ("jinja2", "jinja2")]:
        try:
            __import__(mod_name)
            click.echo(f"    {pkg_name:20s} {ok_mark}")
        except ImportError:
            click.echo(f"    {pkg_name:20s} {fail_mark}")
            issues.append(f"Missing: pip install {pkg_name}")

    # ── Optional extras ──────────────────────────────────────
    # Each group lists (import_name, pypi_name) tuples. numpy + scikit-learn
    # are part of [proxy] (LoopBreaker requires them), not [nlp].
    click.echo("\n  Optional extras:")
    extras = {
        "proxy": [
            ("fastapi", "fastapi"),
            ("uvicorn", "uvicorn"),
            ("httpx", "httpx"),
            ("pydantic", "pydantic"),
            ("redis", "redis"),
            ("boto3", "boto3"),
            ("clickhouse_connect", "clickhouse-connect"),
            ("numpy", "numpy"),
            ("sklearn", "scikit-learn"),
        ],
        "nlp": [
            ("spacy", "spacy"),
        ],
        "telemetry": [
            ("opentelemetry", "opentelemetry-api"),
        ],
    }
    extras_status: dict[str, str] = {}
    for group, mods in extras.items():
        present = 0
        for mod_name, _ in mods:
            try:
                __import__(mod_name)
                present += 1
            except ImportError:
                pass
        if present == len(mods):
            click.echo(f"    [{group}]{' ' * (16 - len(group))} {ok_mark}  ({present}/{len(mods)})")
            extras_status[group] = "ok"
        elif present > 0:
            click.echo(
                f"    [{group}]{' ' * (16 - len(group))} {warn_mark} ({present}/{len(mods)})"
            )
            extras_status[group] = "partial"
        else:
            click.echo(f"    [{group}]{' ' * (16 - len(group))} --    not installed")
            extras_status[group] = "missing"

    if extras_status.get("proxy") != "ok":
        click.echo(
            f"    {warn_mark}  admina dev (local mode) needs the [proxy] extra — "
            "pip install 'admina-framework[proxy]' --upgrade"
        )
        issues.append(
            "admina dev (local mode) requires the [proxy] extra — "
            "run: pip install 'admina-framework[proxy]' --upgrade"
        )

    # ── spaCy NER model ──────────────────────────────────────
    click.echo("\n  NLP engine:")
    try:
        import spacy  # type: ignore[import-untyped]

        try:
            spacy.load("en_core_web_sm")
            click.echo(f"    en_core_web_sm       {ok_mark}")
        except OSError:
            # PII still works in regex-only mode without the spaCy model, so
            # this is a soft warning rather than a blocking issue.
            click.echo(
                f"    en_core_web_sm       {warn_mark}  not loadable "
                "(PII falls back to regex-only — install for NER coverage)"
            )
            # The model is not on PyPI — it ships as a direct wheel URL
            # from explosion/spacy-models on GitHub. `python -m spacy
            # download` is the canonical command but needs pip in the
            # venv; for uv venvs (which omit pip) point at the wheel URL.
            model_ver = "3.8.0"  # matches spacy>=3.8,<4 pinned in [nlp]
            wheel_url = (
                "https://github.com/explosion/spacy-models/releases/download/"
                f"en_core_web_sm-{model_ver}/en_core_web_sm-{model_ver}-py3-none-any.whl"
            )
            click.echo(f"        Install with:  {sys.executable} -m spacy download en_core_web_sm")
            click.echo(f"        For uv venvs:  uv pip install {wheel_url}")
    except ImportError:
        click.echo(
            "    spacy                --    not installed "
            "(PII falls back to regex-only — install [nlp] extra for NER)"
        )

    # ── Rust engine ──────────────────────────────────────────
    click.echo("\n  Governance engine:")
    try:
        import admina_core  # type: ignore[import-untyped]

        click.echo(f"    Rust engine          {ok_mark}  v{admina_core.version()}")
    except ImportError:
        click.echo("    Rust engine          --    not installed (using Python fallback)")
        click.echo(f"    Python fallback      {ok_mark}")

    # ── Plugin registry ──────────────────────────────────────
    click.echo("\n  Plugin registry:")
    try:
        from admina.plugins.registry import PluginRegistry

        reg = PluginRegistry()
        count = reg.discover()
        click.echo(f"    Discovered           {ok_mark}  {count} plugins")
    except Exception as exc:
        import traceback

        logging.getLogger("admina.cli").debug(
            "Plugin discovery traceback:\n%s", traceback.format_exc()
        )
        click.echo(f"    Discovered           {fail_mark}  {exc}")
        issues.append(f"Plugin discovery failed: {exc}")

    # ── Environment variables ────────────────────────────────
    click.echo("\n  Environment:")
    # Layer 1: process env. Layer 2: a .env file in cwd (the project's
    # vault-generated file). Process env wins so a deliberate override
    # is honoured.
    env = dict(os.environ)
    dotenv_loaded = False
    dotenv_path = Path.cwd() / ".env"
    if dotenv_path.is_file():
        try:
            for line in dotenv_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                k = k.strip()
                v = v.strip().strip('"').strip("'")
                env.setdefault(k, v)
            dotenv_loaded = True
        except OSError:
            pass
    if dotenv_loaded:
        click.echo("    (loaded ./.env)")

    env_checks = [
        ("ADMINA_API_KEY", True, "auth disabled — set a strong key in production"),
        ("ADMINA_GOVERNANCE_MODE", False, "default 'enforce'"),
        ("ADMINA_DASHBOARD_PASSWORD", False, "dashboard basic-auth disabled"),
    ]
    for var, required, hint in env_checks:
        val = env.get(var, "")
        if val:
            shown = val if len(val) <= 8 else f"{val[:4]}…({len(val)} chars)"
            click.echo(f"    {var:30s} {ok_mark}  {shown}")
        else:
            mark = warn_mark if not required else fail_mark
            click.echo(f"    {var:30s} {mark}  {hint}")
            if required:
                issues.append(f"Set {var} (run `admina dev` or `./scripts/bootstrap-secrets.sh`)")

    # ── Docker ───────────────────────────────────────────────
    click.echo("\n  Infrastructure:")
    docker_ok = _check_docker()
    click.echo(
        f"    Docker               {ok_mark if docker_ok else warn_mark + '  not found (needed for full stack)'}"
    )

    # ── docker compose stack ─────────────────────────────────
    if docker_ok and Path("docker-compose.yml").exists():
        try:
            ps = subprocess.run(
                ["docker", "compose", "ps", "--format", "{{.Name}}\t{{.Status}}"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if ps.returncode == 0 and ps.stdout.strip():
                lines = [ln for ln in ps.stdout.strip().split("\n") if ln.strip()]
                healthy = sum(1 for ln in lines if "healthy" in ln.lower())
                unhealthy = [ln for ln in lines if "unhealthy" in ln.lower()]
                running = len(lines)
                click.echo(
                    f"    docker compose       {ok_mark}  {running} services running, {healthy} healthy"
                )
                for ln in unhealthy:
                    name = ln.split("\t", 1)[0]
                    click.echo(f"      {warn_mark}  {name} is unhealthy")
                    issues.append(
                        f"Container {name} unhealthy — check `docker compose logs {name}`"
                    )
            else:
                click.echo("    docker compose       --    no stack running (run: admina dev)")
        except (subprocess.SubprocessError, FileNotFoundError):
            pass

    # ── Dashboard reachability ───────────────────────────────
    if docker_ok:
        try:
            import urllib.request as _req

            with _req.urlopen("http://localhost:3000/health", timeout=2) as r:
                if r.status == 200:
                    click.echo(f"    dashboard /health    {ok_mark}  http://localhost:3000")
        except (OSError, ValueError):
            click.echo(
                "    dashboard /health    --    not reachable (stack down or different port)"
            )

    # ── Proxy reachability ───────────────────────────────────
    if docker_ok:
        try:
            import urllib.request as _req

            with _req.urlopen("http://localhost:8080/health", timeout=2) as r:
                if r.status == 200:
                    click.echo(f"    proxy /health        {ok_mark}  http://localhost:8080")
        except (OSError, ValueError):
            click.echo(
                "    proxy /health        --    not reachable (stack down or different port)"
            )

    # ── Summary ──────────────────────────────────────────────
    click.echo("\n" + "=" * 55)
    if not issues:
        click.echo("  All checks passed. Admina is ready.")
    else:
        click.echo(f"  {len(issues)} issue(s) found:")
        for issue in issues:
            click.echo(f"    - {issue}")
    click.echo("=" * 55)
    click.echo("")

    if issues:
        sys.exit(1)


# ── admina password commands ──────────────────────────────


@app.group()
def password() -> None:
    """Manage Admina platform credentials."""


@password.command("show")
def password_show() -> None:
    """Display current API key and password from the vault."""
    vault = SecretVault(Path.cwd())
    if not vault.is_initialized:
        click.echo("  No vault found. Run 'admina init' or 'admina dev' first.", err=True)
        raise SystemExit(1)

    if sys.stdin.isatty():
        click.confirm("  This will display secrets in your terminal. Continue?", abort=True)

    data = vault.export_env()
    click.echo()
    click.echo(f"  API Key:    {data.get('ADMINA_API_KEY', '(not set)')}")
    click.echo(f"  Password:   {data.get('ADMINA_DASHBOARD_PASSWORD', '(not set)')}")
    click.echo("              (shared across dashboard, Grafana, ClickHouse)")
    click.echo()


@password.command("reset")
def password_reset() -> None:
    """Generate a new random password and API key."""
    vault = SecretVault(Path.cwd())
    if not vault.is_initialized:
        click.echo("  No vault found. Run 'admina init' or 'admina dev' first.", err=True)
        raise SystemExit(1)

    generated = vault.bootstrap()
    vault.write_dotenv(Path.cwd() / ".env")

    click.echo()
    click.echo("  Credentials regenerated:")
    click.echo(f"    API Key:    {generated['ADMINA_API_KEY']}")
    click.echo(f"    Password:   {generated['ADMINA_DASHBOARD_PASSWORD']}")
    click.echo()
    click.echo("  Restart services to apply: docker compose up --build -d")
    click.echo()


@password.command("set")
@click.option(
    "--password",
    "new_password",
    prompt=True,
    hide_input=True,
    confirmation_prompt=True,
    help="New password.",
)
def password_set(new_password: str) -> None:
    """Set a custom password for all web UIs."""
    ok, issues = validate_password(new_password)
    if not ok:
        click.echo("\n  Password does not meet requirements:", err=True)
        for issue in issues:
            click.echo(f"    - {issue}", err=True)
        click.echo()
        raise SystemExit(1)

    vault = SecretVault(Path.cwd())
    if not vault.is_initialized:
        click.echo("  No vault found. Run 'admina init' or 'admina dev' first.", err=True)
        raise SystemExit(1)

    vault.update_password(new_password)
    vault.write_dotenv(Path.cwd() / ".env")

    click.echo("\n  Password updated across all services.")
    click.echo("  Restart services to apply: docker compose up --build -d\n")


@app.command()
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    default=Path("admina.yaml"),
    help="Where to write the resulting YAML (default: ./admina.yaml).",
)
@click.option(
    "--non-interactive",
    is_flag=True,
    help="Skip prompts and write a default-restrictive admina.yaml.",
)
def configure(output: Path, non_interactive: bool) -> None:
    """Interactive wizard to produce an admina.yaml.

    Walks through the small set of choices that affect day-1 behaviour:
    governance mode (enforce / observe / dry-run), firewall categories
    to disable, loop-breaker thresholds, PII categories.

    Defaults are restrictive: enforce mode, all firewall categories on,
    EU-aware PII set on. The wizard never recommends a "Pro" upgrade
    or a paid feature — the OSS edition is fully usable as-is.
    """

    if output.exists():
        if not click.confirm(f"  {output} already exists. Overwrite?", default=False):
            click.echo("  Aborted. No file written.", err=True)
            raise SystemExit(1)

    click.echo("")
    click.echo("=" * 55)
    click.echo("  Admina Configuration Wizard")
    click.echo("=" * 55)
    click.echo("")
    click.echo("  Defaults are restrictive (enforce mode, all categories on).")
    click.echo("  Press Enter at any prompt to keep the default.")
    click.echo("")

    # ── Governance mode ───────────────────────────────────────
    if non_interactive:
        mode = "enforce"
    else:
        click.echo("  Governance mode:")
        click.echo("    enforce  → block flagged requests (production)")
        click.echo("    observe  → never block, log 'would have blocked'")
        click.echo("    dry-run  → like observe + tag responses")
        mode = click.prompt(
            "  Mode",
            default="enforce",
            type=click.Choice(["enforce", "observe", "dry-run"]),
            show_choices=False,
        )

    # ── Firewall categories ───────────────────────────────────
    builtin_cats = [
        "instruction_override",
        "role_hijack",
        "prompt_extraction",
        "jailbreak",
        "delimiter_injection",
        "data_exfiltration",
        "tool_abuse",
        "obfuscation",
        "multilang_evasion",
    ]
    disabled: list[str] = []
    if not non_interactive:
        click.echo("")
        click.echo("  Firewall categories (all enabled by default):")
        for cat in builtin_cats:
            click.echo(f"    - {cat}")
        raw = click.prompt(
            "  Categories to DISABLE (comma-separated, empty for none)",
            default="",
            show_default=False,
        )
        disabled = [c.strip() for c in raw.split(",") if c.strip() in builtin_cats]
        unknown = [c.strip() for c in raw.split(",") if c.strip() and c.strip() not in builtin_cats]
        if unknown:
            click.echo(f"  (ignored unknown categories: {', '.join(unknown)})", err=True)

    # ── Loop breaker thresholds ───────────────────────────────
    if non_interactive:
        loop_window, loop_thresh, loop_max = 10, 0.85, 3
    else:
        click.echo("")
        click.echo("  Loop breaker (anti-runaway agent):")
        loop_window = click.prompt("  Sliding window size", default=10, type=int)
        loop_thresh = click.prompt("  TF-IDF similarity threshold", default=0.85, type=float)
        loop_max = click.prompt("  Max consecutive similar messages", default=3, type=int)

    # ── PII categories ────────────────────────────────────────
    pii_default = [
        "email",
        "phone",
        "credit_card",
        "ssn",
        "iban",
        "ip",
        "person",
        "org",
        "it_codice_fiscale",
        "es_dni",
    ]
    if non_interactive:
        pii_categories = pii_default
    else:
        click.echo("")
        click.echo("  PII categories to redact:")
        for cat in pii_default:
            click.echo(f"    - {cat}")
        raw = click.prompt(
            "  Categories to ADD or REMOVE (e.g. '+de_personalausweis,-org')",
            default="",
            show_default=False,
        )
        pii_categories = list(pii_default)
        for token in raw.split(","):
            token = token.strip()
            if not token:
                continue
            if token.startswith("-") and token[1:] in pii_categories:
                pii_categories.remove(token[1:])
            elif token.startswith("+") and token[1:] not in pii_categories:
                pii_categories.append(token[1:])

    # ── Write YAML ────────────────────────────────────────────
    yaml_text = _render_admina_yaml(
        mode=mode,
        firewall_disabled=disabled,
        loop_window=loop_window,
        loop_thresh=loop_thresh,
        loop_max=loop_max,
        pii_categories=pii_categories,
    )
    output.write_text(yaml_text, encoding="utf-8")

    click.echo("")
    click.echo(f"  Wrote {output}")
    click.echo("")
    click.echo("  Next steps:")
    click.echo("    - Review the generated file")
    click.echo("    - Set ADMINA_API_KEY in .env (run 'admina dev' to bootstrap)")
    click.echo("    - Start the stack:  admina dev")
    click.echo("")
    if mode != "enforce":
        click.echo(
            f"  ⚠  Governance mode is '{mode}' — flagged requests will NOT "
            "be blocked. Switch to 'enforce' once you have tuned the policies."
        )
        click.echo("")


def _render_admina_yaml(
    *,
    mode: str,
    firewall_disabled: list[str],
    loop_window: int,
    loop_thresh: float,
    loop_max: int,
    pii_categories: list[str],
) -> str:
    """Render an admina.yaml from wizard inputs. Pure function for testing."""
    disabled_list = (
        "\n      ".join(f"- {c}" for c in firewall_disabled) if firewall_disabled else "[]"
    )
    pii_list = ", ".join(pii_categories)
    disabled_block = (
        f"      disabled_categories:\n      {disabled_list}"
        if firewall_disabled
        else "      disabled_categories: []"
    )
    return f"""# Generated by `admina configure`.
# Edit freely; this is the source of truth for the proxy at startup.

schema_version: 1

domains:
  data_sovereignty:
    enabled: true
    pii:
      enabled: true
      categories: [{pii_list}]
      ner_model: en_core_web_sm

  agent_security:
    enabled: true
    firewall:
      enabled: true
      mode: {mode}
{disabled_block}
      custom_patterns: []
    loop_breaker:
      enabled: true
      window_size: {loop_window}
      similarity_threshold: {loop_thresh}
      max_consecutive: {loop_max}

  compliance:
    enabled: true
    eu_ai_act:
      enabled: true

dashboard:
  enabled: true
  port: 3000

auth_provider: apikey
"""


if __name__ == "__main__":
    app()

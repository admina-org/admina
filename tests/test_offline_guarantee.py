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

"""Admina works without network access.

- The Presidio engine checks e-mail domains against the public suffix list
  that tldextract bundles: building the engine and redacting an e-mail
  address makes no name lookup and no connection, even with an empty
  tldextract cache (``TLDEXTRACT_CACHE``).
- The spacy-regex engine makes none either.
- A spaCy model that is not installed is an error, never a download.
- ``ADMINA_OFFLINE=true`` sets ``HF_HUB_OFFLINE``, ``TRANSFORMERS_OFFLINE``
  and ``HF_DATASETS_OFFLINE`` to ``1`` when a PII engine is selected and when
  the proxy starts, and the proxy starts without the OpenTelemetry exporter.

The ``no_network`` fixture (``_network_guard``) refuses network access and
records every attempt.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from admina.core.offline import OFFLINE_ENVIRONMENT, offline_mode
from admina.engines import get_pii_engine

TESTS = Path(__file__).parent
EMAIL_TEXT = "Per la pratica scrivere a prova.esempio@example.org entro lunedì."


@pytest.fixture(autouse=True)
def _clean_settings(monkeypatch, tmp_path):
    for name in ("ADMINA_PII_ENGINE", "ADMINA_PII_MASK_STYLE", "ADMINA_CONFIG", "ADMINA_OFFLINE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("ADMINA_PRESIDIO_NLP_MODELS", raising=False)
    # Placeholders: whatever the code under test sets is undone after the test.
    for name in OFFLINE_ENVIRONMENT:
        monkeypatch.setenv(name, "unset-by-test")
    monkeypatch.chdir(tmp_path)


# ── The guard ─────────────────────────────────────────────────


def test_the_guard_refuses_lookups_and_connections(no_network):
    with pytest.raises(OSError):
        socket.getaddrinfo("example.org", 443)
    with pytest.raises(OSError):
        socket.create_connection(("example.org", 443))
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock, pytest.raises(OSError):
        sock.connect(("192.0.2.1", 443))
    assert len(no_network) == 3
    left, right = socket.socketpair()
    left.close()
    right.close()
    asyncio.run(asyncio.sleep(0))


# ── ADMINA_OFFLINE ────────────────────────────────────────────


@pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", "on"])
def test_offline_values(monkeypatch, value):
    monkeypatch.setenv("ADMINA_OFFLINE", value)
    assert offline_mode() is True


@pytest.mark.parametrize("value", ["", "0", "false", "no", "off"])
def test_online_values(monkeypatch, value):
    monkeypatch.setenv("ADMINA_OFFLINE", value)
    assert offline_mode() is False


def test_unknown_value_is_an_error(monkeypatch):
    monkeypatch.setenv("ADMINA_OFFLINE", "maybe")
    with pytest.raises(ValueError, match="ADMINA_OFFLINE"):
        offline_mode()


def test_offline_sets_the_hub_variables(monkeypatch):
    monkeypatch.setenv("ADMINA_OFFLINE", "true")
    get_pii_engine("spacy-regex")
    assert {name: os.environ[name] for name in OFFLINE_ENVIRONMENT} == {
        "HF_HUB_OFFLINE": "1",
        "TRANSFORMERS_OFFLINE": "1",
        "HF_DATASETS_OFFLINE": "1",
    }


def test_without_offline_the_hub_variables_are_untouched():
    get_pii_engine("spacy-regex")
    assert all(os.environ[name] == "unset-by-test" for name in OFFLINE_ENVIRONMENT)


def test_proxy_starts_offline_without_otel(monkeypatch, no_network):
    from _proxy_app import isolate

    from admina.domains.compliance.otel import OTELGovernanceExporter
    from admina.proxy import main as proxy_main

    isolate(monkeypatch)
    monkeypatch.setattr(proxy_main, "OTELGovernanceExporter", OTELGovernanceExporter)
    monkeypatch.setenv("ADMINA_OFFLINE", "true")

    async def go():
        async with proxy_main.lifespan(proxy_main.app):
            return proxy_main.app.state.proxy

    state = asyncio.run(go())
    assert state.otel_exporter.enabled is False
    assert os.environ["HF_HUB_OFFLINE"] == "1"
    assert no_network == []


def test_otel_exporter_can_be_built_disabled():
    from admina.domains.compliance.otel import OTELGovernanceExporter

    exporter = OTELGovernanceExporter(endpoint="http://collector.invalid:4317", enabled=False)
    assert exporter.enabled is False


# ── PII engines without network ───────────────────────────────


def test_spacy_regex_makes_no_network_call(monkeypatch, no_network):
    monkeypatch.setenv("ADMINA_OFFLINE", "true")
    out = get_pii_engine("spacy-regex").redact(EMAIL_TEXT)
    assert "[EMAIL]" in out["redacted_text"]
    assert no_network == []


def test_presidio_makes_no_network_call(monkeypatch, no_network):
    pytest.importorskip("presidio_analyzer")
    from admina.engines.presidio import PresidioPIIEngine

    monkeypatch.setenv("ADMINA_OFFLINE", "true")
    try:
        engine = PresidioPIIEngine()
    except ImportError as exc:
        pytest.skip(str(exc))
    out = engine.redact(EMAIL_TEXT)
    assert "[EMAIL]" in out["redacted_text"]
    assert no_network == []


_COLD_CACHE_SCRIPT = textwrap.dedent(
    """
    import json, sys
    sys.path.insert(0, {tests!r})
    import _network_guard
    attempts = _network_guard.install()
    from admina.engines import get_pii_engine
    engine = get_pii_engine("presidio")
    out = engine.redact({text!r})
    print(json.dumps({{"attempts": attempts, "text": out["redacted_text"]}}))
    """
)


def test_presidio_makes_no_network_call_with_an_empty_suffix_cache(tmp_path):
    pytest.importorskip("presidio_analyzer")
    from _proxy_app import subprocess_env

    cache = tmp_path / "tldextract-cache"
    cache.mkdir()
    env = subprocess_env(
        "ADMINA_",
        "HF_",
        "TRANSFORMERS_",
        ADMINA_OFFLINE="true",
        TLDEXTRACT_CACHE=str(cache),
    )
    script = _COLD_CACHE_SCRIPT.format(tests=str(TESTS), text=EMAIL_TEXT)
    run = subprocess.run(
        [sys.executable, "-c", script],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
    )
    if run.returncode != 0 and "ImportError" in run.stderr:
        pytest.skip("Presidio installed without a spaCy model")
    assert run.returncode == 0, run.stderr
    result = json.loads(run.stdout.strip().splitlines()[-1])
    assert result["attempts"] == []
    assert "[EMAIL]" in result["text"]
    assert list(cache.iterdir()) == []


def test_a_missing_model_is_an_error_never_a_download(monkeypatch, no_network):
    pytest.importorskip("presidio_analyzer")
    import spacy.cli

    from admina.engines.presidio import PresidioPIIEngine

    downloads: list[str] = []
    monkeypatch.setattr(spacy.cli, "download", lambda *a, **k: downloads.append(a))
    with pytest.raises(ImportError, match="xx_example_missing_model"):
        PresidioPIIEngine(nlp_models={"it": "xx_example_missing_model"})
    assert downloads == []
    assert no_network == []

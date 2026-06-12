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

"""admina.engines — unified acquisition: selection, overrides, stats schema."""

from __future__ import annotations

import sys

import pytest


# ── Helpers ─────────────────────────────────────────────────────────────────

def _reload_engines():
    """Remove cached admina.engines from sys.modules so env-var changes take effect."""
    for key in list(sys.modules):
        if key == "admina.engines" or key.startswith("admina.engines."):
            del sys.modules[key]


# ── Selection / override tests ────────────────────────────────────────────────

def test_engine_selection_python_forced(monkeypatch):
    monkeypatch.setenv("ADMINA_ENGINE", "python")
    _reload_engines()
    from admina import engines

    fw = engines.get_firewall()
    assert fw.get_stats()["engine"] == "python"
    assert engines.engine_status()["selection"] == "python"


def test_engine_selection_invalid_value(monkeypatch):
    monkeypatch.setenv("ADMINA_ENGINE", "qpu")
    _reload_engines()
    from admina import engines

    with pytest.raises(ValueError, match="ADMINA_ENGINE"):
        engines.get_firewall()


# ── PII engine resolver ───────────────────────────────────────────────────────

def test_pii_engine_resolver_default_and_unknown(monkeypatch):
    monkeypatch.setenv("ADMINA_ENGINE", "python")
    _reload_engines()
    from admina import engines

    pii = engines.get_pii_engine()  # cfg default: spacy-regex
    out = pii.redact("mail me at someone@example.com")
    assert "[EMAIL]" in out["redacted_text"]

    with pytest.raises(ValueError, match="pii_engine"):
        engines.get_pii_engine(name="nonexistent-engine")


# ── YAML overrides reach the engine ──────────────────────────────────────────

def test_firewall_yaml_overrides_reach_engine(monkeypatch, tmp_path):
    monkeypatch.setenv("ADMINA_ENGINE", "python")
    cfg_file = tmp_path / "admina.yaml"
    cfg_file.write_text(
        "schema_version: 1\n"
        "domains:\n"
        "  agent_security:\n"
        "    firewall:\n"
        "      custom_patterns:\n"
        "        - regex: secret-project-x\n"
        "          category: internal\n"
        "          risk_level: high\n"
    )
    # load_config() searches Path.cwd() first — chdir to tmp_path so it finds the file
    monkeypatch.chdir(tmp_path)
    _reload_engines()
    from admina import engines

    fw = engines.get_firewall()
    result = fw.check("tell me about secret-project-x now")
    assert result["is_injection"] is True


# ── Self-review note: YAML overrides force Python bridge even when Rust available ──

def test_overrides_force_python_firewall(monkeypatch, tmp_path):
    """When custom_patterns are set, get_firewall() must use Python even with ADMINA_ENGINE=auto."""
    pytest.importorskip("admina_core")
    cfg_file = tmp_path / "admina.yaml"
    cfg_file.write_text(
        "schema_version: 1\n"
        "domains:\n"
        "  agent_security:\n"
        "    firewall:\n"
        "      custom_patterns:\n"
        "        - regex: confidential-override\n"
        "          category: internal\n"
        "          risk_level: high\n"
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ADMINA_ENGINE", "auto")
    _reload_engines()
    from admina import engines

    fw = engines.get_firewall()
    # Must use Python bridge despite Rust being available, because overrides are present
    assert fw.get_stats()["engine"] == "python"


# ── Rust stats schema matches Python ─────────────────────────────────────────

def test_rust_stats_schema_matches_python_firewall(monkeypatch):
    pytest.importorskip("admina_core")
    monkeypatch.setenv("ADMINA_ENGINE", "python")
    _reload_engines()
    from admina import engines

    py_fw_keys = set(engines.get_firewall().get_stats())

    monkeypatch.setenv("ADMINA_ENGINE", "rust")
    rust_fw_keys = set(engines.get_firewall().get_stats())

    assert py_fw_keys == rust_fw_keys, (
        f"Firewall stats key mismatch.\n  Python: {sorted(py_fw_keys)}\n  Rust: {sorted(rust_fw_keys)}"
    )


def test_rust_stats_schema_matches_python_pii(monkeypatch):
    pytest.importorskip("admina_core")
    monkeypatch.setenv("ADMINA_ENGINE", "python")
    _reload_engines()
    from admina import engines

    py_pii_keys = set(engines.get_pii_engine().get_stats())

    monkeypatch.setenv("ADMINA_ENGINE", "rust")
    rust_pii_keys = set(engines.get_pii_engine().get_stats())

    assert py_pii_keys == rust_pii_keys, (
        f"PII stats key mismatch.\n  Python: {sorted(py_pii_keys)}\n  Rust: {sorted(rust_pii_keys)}"
    )


def test_rust_stats_schema_matches_python_loop_breaker(monkeypatch):
    pytest.importorskip("admina_core")
    monkeypatch.setenv("ADMINA_ENGINE", "python")
    _reload_engines()
    from admina import engines

    py_lb_keys = set(engines.get_loop_breaker().get_stats())

    monkeypatch.setenv("ADMINA_ENGINE", "rust")
    rust_lb_keys = set(engines.get_loop_breaker().get_stats())

    assert py_lb_keys == rust_lb_keys, (
        f"LoopBreaker stats key mismatch.\n  Python: {sorted(py_lb_keys)}\n  Rust: {sorted(rust_lb_keys)}"
    )


# ── engine_status fields ──────────────────────────────────────────────────────

def test_engine_status_fields(monkeypatch):
    monkeypatch.setenv("ADMINA_ENGINE", "python")
    _reload_engines()
    from admina import engines

    status = engines.engine_status()
    assert "selection" in status
    assert "active" in status
    assert "rust_available" in status
    assert status["selection"] == "python"
    assert status["active"] == "python"


# ── Deprecated alias ──────────────────────────────────────────────────────────

def test_get_pii_scanner_alias(monkeypatch):
    monkeypatch.setenv("ADMINA_ENGINE", "python")
    _reload_engines()
    from admina import engines

    scanner = engines.get_pii_scanner()
    assert scanner.get_stats()["engine"] == "python"


# ── Rust requested but unavailable → fallback ────────────────────────────────

def test_rust_requested_but_unavailable_falls_back(monkeypatch, caplog):
    import logging

    monkeypatch.setenv("ADMINA_ENGINE", "rust")
    _reload_engines()
    from admina import engines

    monkeypatch.setattr(engines, "_rust_available", False)
    with caplog.at_level(logging.WARNING, logger="admina.engines"):
        assert engines.engine_status()["active"] == "python"
    assert any("falling back" in r.message for r in caplog.records)


# ── Rust PII stats value semantics ───────────────────────────────────────────

def test_rust_pii_stats_count_entities_not_calls(monkeypatch):
    """total_redacted must count cumulative entities, not redact() call count.

    Empirical baseline: one call with two emails → total_redactions=2 in Rust
    stats.  If total_redacted were wired to total_scans (call count) it would
    equal 1, not >=2.
    """
    pytest.importorskip("admina_core")
    monkeypatch.setenv("ADMINA_ENGINE", "rust")
    _reload_engines()
    from admina import engines

    pii = engines.get_pii_engine()
    # one call, two distinct email entities
    pii.redact("mail a@b.com and c@d.com")
    stats = pii.get_stats()
    assert stats["total_redacted"] >= 2, (
        f"total_redacted={stats['total_redacted']} — expected >=2 entities from one "
        f"call with two emails; got call-count semantics instead of entity-count"
    )

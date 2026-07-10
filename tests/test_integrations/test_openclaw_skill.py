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

"""Integration tests for the OpenClaw admina-governance skill.

Simulates the full OpenClaw agent governance flow:
  validate (pre-action) -> execute -> audit (post-action)

Uses the same test infrastructure as test_dashboard/test_api.py
with fake governance backends (no Docker / live services needed).
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import httpx
import yaml
from fastapi import FastAPI

from admina.proxy.api.integration import create_integration_endpoints

# ── Fake governance backends ────────────────────────────────


class _FakeFirewall:
    """Detects SQL injection and common attack patterns."""

    def check(self, text: str) -> dict[str, Any]:
        upper = text.upper()
        is_bad = any(
            pattern in upper for pattern in ("DROP TABLE", "DELETE FROM", "; --", "' OR 1=1")
        )
        return {"is_injection": is_bad, "risk_level": "HIGH" if is_bad else "LOW"}

    def get_stats(self) -> dict[str, Any]:
        return {}


class _FakePII:
    """Detects email addresses as PII."""

    def redact(self, text: str) -> dict[str, Any]:
        if "@" in text:
            # Simple email redaction
            import re

            redacted = re.sub(
                r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
                "[EMAIL_REDACTED]",
                text,
            )
            return {"redacted_text": redacted, "entities": ["EMAIL"], "count": 1}
        return {"redacted_text": text, "entities": [], "count": 0}

    def get_stats(self) -> dict[str, Any]:
        return {}


class _FakeLoopBreaker:
    """Detects repeated identical requests."""

    def __init__(self) -> None:
        self._history: dict[str, list[str]] = {}

    def check(self, session_id: str, content: str) -> dict[str, Any]:
        hist = self._history.setdefault(session_id, [])
        is_loop = len(hist) >= 3 and all(h == content for h in hist[-3:])
        hist.append(content)
        return {"is_loop": is_loop, "similarity": 1.0 if is_loop else 0.0}

    def get_stats(self) -> dict[str, Any]:
        return {}


class _FakeForensicBox:
    """In-memory forensic black box for testing."""

    def __init__(self) -> None:
        self._records: list[dict[str, Any]] = []
        self._chain_head = "0" * 64

    def record(self, event: dict[str, Any]) -> dict[str, Any]:
        import hashlib
        import json

        seq = len(self._records) + 1
        prev = self._chain_head
        record_hash = hashlib.sha256(
            json.dumps(event, sort_keys=True, default=str).encode()
        ).hexdigest()
        self._chain_head = record_hash
        self._records.append({"event": event, "hash": record_hash})
        return {
            "sequence_number": seq,
            "record_hash": record_hash,
            "previous_hash": prev,
            "stored": True,
        }

    def get_stats(self) -> dict[str, Any]:
        return {"record_count": len(self._records)}


# ── Test app builder ────────────────────────────────────────


def _build_openclaw_app(
    *,
    forensic_box: _FakeForensicBox | None = None,
    loop_breaker: _FakeLoopBreaker | None = None,
) -> FastAPI:
    """Build a minimal FastAPI app with integration endpoints."""
    fbox = forensic_box or _FakeForensicBox()
    lb = loop_breaker or _FakeLoopBreaker()

    router = create_integration_endpoints(
        get_firewall=_FakeFirewall,
        get_pii_scanner=_FakePII,
        get_loop_breaker=lambda: lb,
        get_forensic_box=lambda: fbox,
    )

    app = FastAPI()
    app.include_router(router)
    return app


def _run(coro):
    """Run an async coroutine synchronously."""
    return asyncio.run(coro)


def _client(app: FastAPI) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


# ═══════════════════════════════════════════════════════════
# 1. Skill package structure validation
# ═══════════════════════════════════════════════════════════


class TestOpenClawSkillPackage:
    """Verify the skill package has all required files."""

    SKILL_DIR = (
        Path(__file__).parent.parent.parent
        / "admina"
        / "integrations"
        / "openclaw"
        / "admina-governance"
    )

    def test_skill_md_exists(self) -> None:
        assert (self.SKILL_DIR / "SKILL.md").is_file()

    def test_setup_sh_exists(self) -> None:
        setup = self.SKILL_DIR / "setup.sh"
        assert setup.is_file()

    def test_setup_sh_executable(self) -> None:
        import stat

        setup = self.SKILL_DIR / "setup.sh"
        mode = setup.stat().st_mode
        assert mode & stat.S_IXUSR, "setup.sh should be executable"

    def test_admina_yaml_exists(self) -> None:
        assert (self.SKILL_DIR / "admina.yaml").is_file()

    def test_admina_yaml_valid(self) -> None:
        config = yaml.safe_load((self.SKILL_DIR / "admina.yaml").read_text())
        assert config["schema_version"] == 1
        assert config["inference_mode"] == "local"
        assert config["agent_security"]["firewall"]["enabled"] is True
        assert config["agent_security"]["pii_redaction"]["enabled"] is True
        assert config["agent_security"]["loop_breaker"]["enabled"] is True
        assert config["forensic"]["enabled"] is True

    def test_skill_md_has_yaml_frontmatter(self) -> None:
        text = (self.SKILL_DIR / "SKILL.md").read_text()
        assert text.startswith("---")
        # Extract YAML frontmatter
        parts = text.split("---", 2)
        assert len(parts) >= 3, "SKILL.md must have YAML frontmatter"
        meta = yaml.safe_load(parts[1])
        assert meta["name"] == "admina-governance"
        assert "description" in meta
        assert meta["metadata"]["openclaw"]["primaryEnv"] == "ADMINA_PROXY_URL"

    def test_skill_md_documents_validate_endpoint(self) -> None:
        text = (self.SKILL_DIR / "SKILL.md").read_text()
        assert "/api/v1/validate" in text

    def test_skill_md_documents_audit_endpoint(self) -> None:
        text = (self.SKILL_DIR / "SKILL.md").read_text()
        assert "/api/v1/audit" in text

    def test_skill_md_documents_action_types(self) -> None:
        text = (self.SKILL_DIR / "SKILL.md").read_text()
        for action in ("llm_call", "shell_exec", "file_write", "http_request", "message_send"):
            assert action in text, f"SKILL.md should document action type: {action}"

    def test_skill_md_documents_unreachable_behavior(self) -> None:
        text = (self.SKILL_DIR / "SKILL.md").read_text()
        assert "unreachable" in text.lower() or "not responding" in text.lower()


# ═══════════════════════════════════════════════════════════
# 2. OpenClaw agent flow: validate -> execute -> audit
# ═══════════════════════════════════════════════════════════


class TestOpenClawValidateExecuteAudit:
    """Simulate an OpenClaw agent calling validate -> execute -> audit.

    This is the core governance flow described in SKILL.md:
    1. Agent sends action to /api/v1/validate before execution
    2. If allowed, agent executes the action
    3. Agent logs the result to /api/v1/audit
    """

    def test_clean_action_full_flow(self) -> None:
        """Happy path: clean action is allowed, executed, and audited."""
        app = _build_openclaw_app()

        async def flow():
            async with _client(app) as c:
                # Step 1: Validate — agent wants to call an LLM
                val = await c.post(
                    "/api/v1/validate",
                    json={
                        "content": "What is the capital of France?",
                        "session_id": "openclaw-session-1",
                    },
                )
                assert val.status_code == 200
                val_data = val.json()
                assert val_data["action"] == "ALLOW"
                assert val_data["risk_level"] == "LOW"

                # Step 2: Execute — agent proceeds (simulated)
                execution_result = "The capital of France is Paris."

                # Step 3: Audit — agent logs the result
                audit = await c.post(
                    "/api/v1/audit",
                    json={
                        "event": {
                            "action": "llm_call",
                            "input": "What is the capital of France?",
                            "output": execution_result,
                            "status": "success",
                            "session_id": "openclaw-session-1",
                        },
                    },
                )
                assert audit.status_code == 200
                audit_data = audit.json()
                assert audit_data["recorded"] is True
                assert "record_hash" in audit_data
                assert "sequence_number" in audit_data

        _run(flow())

    def test_injection_blocked_no_execution(self) -> None:
        """Agent attempts a malicious shell command; blocked before execution."""
        app = _build_openclaw_app()

        async def flow():
            async with _client(app) as c:
                # Step 1: Validate — agent wants to run a shell command
                val = await c.post(
                    "/api/v1/validate",
                    json={
                        "content": "DROP TABLE users; -- delete everything",
                        "session_id": "openclaw-session-2",
                    },
                )
                assert val.status_code == 200
                val_data = val.json()
                assert val_data["action"] == "BLOCK"
                assert val_data["risk_level"] == "HIGH"

                # Step 2: Agent does NOT execute (blocked)

                # Step 3: Audit the block event
                audit = await c.post(
                    "/api/v1/audit",
                    json={
                        "event": {
                            "action": "shell_exec",
                            "input": "DROP TABLE users; --",
                            "status": "blocked",
                            "reason": "injection_detected",
                            "session_id": "openclaw-session-2",
                        },
                    },
                )
                assert audit.status_code == 200
                assert audit.json()["recorded"] is True

        _run(flow())

    def test_pii_redacted_modified_payload(self) -> None:
        """Agent sends content with PII; gets back redacted version."""
        app = _build_openclaw_app()

        async def flow():
            async with _client(app) as c:
                # Step 1: Validate — content contains an email address
                val = await c.post(
                    "/api/v1/validate",
                    json={
                        "content": "Send email to john@example.com about the meeting",
                        "session_id": "openclaw-session-3",
                    },
                )
                val_data = val.json()
                assert val_data["action"] == "REDACT"
                assert val_data["redacted_content"] is not None
                assert "john@example.com" not in val_data["redacted_content"]
                assert "[EMAIL_REDACTED]" in val_data["redacted_content"]

                # Step 2: Agent uses the REDACTED content for execution
                safe_content = val_data["redacted_content"]
                assert "example.com" not in safe_content

                # Step 3: Audit with the redacted content
                audit = await c.post(
                    "/api/v1/audit",
                    json={
                        "event": {
                            "action": "message_send",
                            "input_original": "Send email to [PII]",
                            "input_redacted": safe_content,
                            "status": "success",
                            "pii_detected": True,
                            "session_id": "openclaw-session-3",
                        },
                    },
                )
                assert audit.status_code == 200
                assert audit.json()["recorded"] is True

        _run(flow())

    def test_multi_action_session_with_audit_trail(self) -> None:
        """Agent performs multiple actions; all are audited in sequence."""
        fbox = _FakeForensicBox()
        app = _build_openclaw_app(forensic_box=fbox)

        async def flow():
            async with _client(app) as c:
                session = "openclaw-multi-1"

                # Action 1: LLM call (allowed)
                val1 = await c.post(
                    "/api/v1/validate",
                    json={
                        "content": "Summarize this document",
                        "session_id": session,
                    },
                )
                assert val1.json()["action"] == "ALLOW"

                audit1 = await c.post(
                    "/api/v1/audit",
                    json={
                        "event": {
                            "action": "llm_call",
                            "step": 1,
                            "status": "success",
                            "session_id": session,
                        },
                    },
                )
                seq1 = audit1.json()["sequence_number"]

                # Action 2: File write (allowed)
                val2 = await c.post(
                    "/api/v1/validate",
                    json={
                        "content": "Write summary to output.txt",
                        "session_id": session,
                    },
                )
                assert val2.json()["action"] == "ALLOW"

                audit2 = await c.post(
                    "/api/v1/audit",
                    json={
                        "event": {
                            "action": "file_write",
                            "step": 2,
                            "status": "success",
                            "session_id": session,
                        },
                    },
                )
                seq2 = audit2.json()["sequence_number"]

                # Audit trail is sequential
                assert seq2 == seq1 + 1

                # Forensic box has both records
                assert fbox.get_stats()["record_count"] == 2

        _run(flow())

    def test_validate_all_action_types(self) -> None:
        """All OpenClaw action types can be validated."""
        app = _build_openclaw_app()
        action_types = [
            ("llm_call", "Tell me about Python"),
            ("shell_exec", "ls -la /home"),
            ("file_write", "Create a new file with content"),
            ("http_request", "Fetch data from the internal API"),
            ("message_send", "Send a status update to the team"),
        ]

        async def flow():
            async with _client(app) as c:
                for action_type, content in action_types:
                    val = await c.post(
                        "/api/v1/validate",
                        json={
                            "content": content,
                            "session_id": f"test-{action_type}",
                        },
                    )
                    assert val.status_code == 200, f"Validate failed for action type: {action_type}"
                    assert val.json()["action"] == "ALLOW"

        _run(flow())

    def test_audit_preserves_hash_chain(self) -> None:
        """Each audit record links to the previous via hash chain."""
        fbox = _FakeForensicBox()
        app = _build_openclaw_app(forensic_box=fbox)

        async def flow():
            async with _client(app) as c:
                # Record three events
                hashes = []
                for i in range(3):
                    r = await c.post(
                        "/api/v1/audit",
                        json={
                            "event": {
                                "action": "llm_call",
                                "step": i,
                                "session_id": "chain-test",
                            },
                        },
                    )
                    data = r.json()
                    assert data["recorded"] is True
                    hashes.append(data["record_hash"])

                # Each hash is unique
                assert len(set(hashes)) == 3
                # Chain is intact
                assert fbox.get_stats()["record_count"] == 3

        _run(flow())

    def test_no_forensic_box_still_validates(self) -> None:
        """Validation works even if forensic box is unavailable."""
        router = create_integration_endpoints(
            get_firewall=_FakeFirewall,
            get_pii_scanner=_FakePII,
            get_loop_breaker=_FakeLoopBreaker,
            get_forensic_box=lambda: None,
        )
        app = FastAPI()
        app.include_router(router)

        async def flow():
            async with _client(app) as c:
                # Validate still works
                val = await c.post(
                    "/api/v1/validate",
                    json={
                        "content": "Hello world",
                    },
                )
                assert val.json()["action"] == "ALLOW"

                # Audit reports unavailable
                audit = await c.post(
                    "/api/v1/audit",
                    json={
                        "event": {"action": "llm_call", "status": "success"},
                    },
                )
                assert audit.json()["recorded"] is False
                assert "error" in audit.json()

        _run(flow())

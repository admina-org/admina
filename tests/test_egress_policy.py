import logging

import pytest

from admina.core.types import RiskLevel
from admina.domains.agent_security.egress import EgressPolicy, analyze, resolve_egress_mode


def _intent(params):
    return analyze(params)


class TestAllowlistMatching:
    def test_exact_host_allowed(self):
        p = EgressPolicy(allow=["api.openai.com"])
        assert p.evaluate(_intent({"url": "https://api.openai.com/v1"}), "enforce").allowed

    def test_unlisted_host_blocked(self):
        p = EgressPolicy(allow=["api.openai.com"])
        d = p.evaluate(_intent({"url": "https://publictestwiki.com/w.pl?action=edit"}), "enforce")
        assert d.allowed is False
        assert d.blocked == ["publictestwiki.com"]
        assert d.risk_level is RiskLevel.HIGH

    def test_wildcard_matches_subdomain_only(self):
        p = EgressPolicy(allow=["*.corp.internal"])
        assert p.evaluate(_intent({"host": "a.corp.internal"}), "enforce").allowed
        assert not p.evaluate(_intent({"host": "corp.internal"}), "enforce").allowed
        assert not p.evaluate(_intent({"host": "evilcorp.internal"}), "enforce").allowed

    def test_cidr_matches_ip(self):
        p = EgressPolicy(allow=["10.0.0.0/8"])
        assert p.evaluate(_intent({"host": "10.1.2.3"}), "enforce").allowed
        assert not p.evaluate(_intent({"host": "192.168.1.1"}), "enforce").allowed

    def test_malformed_allow_entry_is_skipped_not_fatal(self, caplog):
        with caplog.at_level(logging.WARNING, logger="admina.egress"):
            p = EgressPolicy(allow=["", "***", "api.openai.com"])
        assert p.evaluate(_intent({"url": "https://api.openai.com/v1"}), "enforce").allowed
        d = p.evaluate(_intent({"url": "https://evil.example"}), "enforce")
        assert d.allowed is False
        assert d.blocked == ["evil.example"]

        # "" is absent, not malformed, and must not warn; "***" must be named in
        # exactly one warning, which is the observable sign that it was rejected
        # rather than silently admitted.
        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warnings) == 1
        assert "***" in warnings[0].getMessage()

    def test_single_label_allow_entry_matches_bare_host(self):
        """Docker/compose-style single-label service names must be authorisable."""
        p = EgressPolicy(allow=["redis"])
        assert p.evaluate(_intent({"host": "redis", "port": 6379}), "enforce").allowed

    def test_single_label_allow_entry_matches_url_host(self):
        p = EgressPolicy(allow=["localhost"])
        assert p.evaluate(_intent({"url": "http://localhost:9000"}), "enforce").allowed


class TestTriStateHandling:
    def test_no_egress_always_passes(self):
        """A non-network tool must not be denied by a default-deny allowlist."""
        p = EgressPolicy(allow=[])
        assert p.evaluate(_intent({"expression": "2 + 2"}), "enforce").allowed

    def test_unresolvable_is_denied_in_enforce(self):
        p = EgressPolicy(allow=["api.openai.com"])
        d = p.evaluate(_intent({"url": "${TARGET}"}), "enforce")
        assert d.allowed is False
        assert "unresolvable" in d.reason

    def test_default_deny_with_empty_allowlist(self):
        p = EgressPolicy(allow=[])
        assert not p.evaluate(_intent({"url": "https://anything.com"}), "enforce").allowed


class TestObserveMode:
    def test_observe_never_blocks(self):
        p = EgressPolicy(allow=[])
        d = p.evaluate(_intent({"url": "https://publictestwiki.com"}), "observe")
        assert d.allowed is True
        assert d.blocked == ["publictestwiki.com"], "observe still reports what it would block"


class TestQuarantine:
    def test_quarantined_destination_blocks_write_shaped_only(self):
        p = EgressPolicy(allow=["wiki.corp"])
        p.set_quarantine(frozenset({"wiki.corp"}))
        write = _intent({"url": "https://wiki.corp/w?action=edit&text=a long enough payload"})
        read = _intent({"url": "https://wiki.corp/page"})
        assert p.evaluate(write, "enforce").allowed is False
        assert p.evaluate(write, "enforce").risk_level is RiskLevel.CRITICAL
        assert p.evaluate(read, "enforce").allowed is True, "reads survive quarantine"


class TestModeComposition:
    @pytest.mark.parametrize(
        "governance, egress, expected",
        [
            ("observe", "enforce", "observe"),  # global contract wins
            ("observe", "observe", "observe"),
            ("dry-run", "enforce", "observe"),
            ("enforce", "observe", "observe"),  # the default: records, never blocks
            ("enforce", "enforce", "enforce"),
            ("enforce", None, "observe"),  # unset defaults to observe
        ],
    )
    def test_table(self, governance, egress, expected, monkeypatch):
        monkeypatch.delenv("ADMINA_EGRESS_MODE", raising=False)
        if egress is not None:
            monkeypatch.setenv("ADMINA_EGRESS_MODE", egress)
        assert resolve_egress_mode(governance) == expected

    def test_invalid_value_falls_back_to_observe(self, monkeypatch):
        monkeypatch.setenv("ADMINA_EGRESS_MODE", "banana")
        assert resolve_egress_mode("enforce") == "observe"

    def test_explicit_argument_beats_the_environment(self, monkeypatch):
        monkeypatch.setenv("ADMINA_EGRESS_MODE", "observe")
        assert resolve_egress_mode("enforce", "enforce") == "enforce"

    @pytest.mark.parametrize("governance", ["Observe", " observe ", "OBSERVE", "Dry-Run"])
    def test_governance_mode_is_normalised_like_the_egress_mode(self, governance, monkeypatch):
        """The §5.4 ceiling must not be defeated by capitalisation.

        `GovernedModel.__init__` stores `mode` verbatim and never validates
        it, so a caller writing mode="Observe" reaches here unchanged. If
        only `egress_mode` is normalised, that caller gets enforcing egress
        while believing it is observing.
        """
        monkeypatch.setenv("ADMINA_EGRESS_MODE", "enforce")
        assert resolve_egress_mode(governance) == "observe"

    def test_enforce_is_still_normalised_and_still_enforces(self, monkeypatch):
        monkeypatch.setenv("ADMINA_EGRESS_MODE", "enforce")
        assert resolve_egress_mode("Enforce") == "enforce"

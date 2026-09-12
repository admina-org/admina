from admina.core.types import RiskLevel
from admina.domains.agent_security.egress import EgressPolicy, analyze


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

    def test_malformed_allow_entry_is_skipped_not_fatal(self):
        p = EgressPolicy(allow=["", "***", "api.openai.com"])
        assert p.evaluate(_intent({"url": "https://api.openai.com/v1"}), "enforce").allowed


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

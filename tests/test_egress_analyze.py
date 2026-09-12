from admina.domains.agent_security.egress import EgressStatus, analyze


class TestDestinationExtraction:
    def test_full_url(self):
        i = analyze({"url": "https://api.openai.com/v1/chat"})
        assert i.status is EgressStatus.RESOLVED
        assert i.destinations == ["api.openai.com"]

    def test_scheme_less_host(self):
        i = analyze({"endpoint": "publictestwiki.com"})
        assert i.status is EgressStatus.RESOLVED
        assert i.destinations == ["publictestwiki.com"]

    def test_literal_ipv4_and_ipv6(self):
        assert analyze({"host": "10.0.0.5"}).destinations == ["10.0.0.5"]
        assert analyze({"host": "::1"}).destinations == ["::1"]

    def test_composite_destination_split_across_fields(self):
        i = analyze({"host": "cache.corp.internal", "port": 6379})
        assert i.status is EgressStatus.RESOLVED
        assert i.destinations == ["cache.corp.internal"]

    def test_nested_and_deduplicated(self):
        i = analyze({"a": {"b": [{"url": "https://x.com/1"}, {"url": "https://x.com/2"}]}})
        assert i.destinations == ["x.com"]


class TestTriState:
    def test_pure_computation_tool_is_not_an_egress_attempt(self):
        """A tool with no network-shaped argument must never be denied."""
        i = analyze({"expression": "2 + 2", "precision": 4})
        assert i.status is EgressStatus.NO_EGRESS
        assert i.destinations == []

    def test_network_key_with_unresolvable_value(self):
        i = analyze({"url": "${TARGET_ENDPOINT}"})
        assert i.status is EgressStatus.UNRESOLVABLE

    def test_unresolvable_wins_over_a_resolved_sibling(self):
        """One undeterminable destination taints the call."""
        i = analyze({"url": "https://ok.com", "host": "${SECRET_HOST}"})
        assert i.status is EgressStatus.UNRESOLVABLE

    def test_prose_containing_no_host_is_not_egress(self):
        i = analyze({"text": "please summarise the quarterly report"})
        assert i.status is EgressStatus.NO_EGRESS

    def test_depth_limit_does_not_crash(self):
        deep = {"k": {}}
        cur = deep["k"]
        for _ in range(50):
            cur["k"] = {}
            cur = cur["k"]
        cur["url"] = "https://deep.com"
        assert analyze(deep).status is EgressStatus.NO_EGRESS

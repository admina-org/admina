from admina.domains.agent_security.egress import EgressStatus, analyze


class TestWriteShaped:
    def test_query_string_makes_a_call_payload_bearing(self):
        i = analyze({"url": "https://wiki.com/w.pl?action=edit&text=hello+there+everyone"})
        assert i.write_shaped is True

    def test_url_without_query_is_not_payload_bearing(self):
        i = analyze({"url": "https://docs.python.org/3/library/json.html"})
        assert i.write_shaped is False

    def test_body_field_makes_a_call_payload_bearing(self):
        i = analyze({"url": "https://api.corp/x", "body": {"note": "a sufficiently long value"}})
        assert i.write_shaped is True

    def test_substantial_free_string_beside_a_destination(self):
        i = analyze({"url": "https://api.corp/x", "note": "task 42 done, results in ZZZ_Page"})
        assert i.write_shaped is True

    def test_short_incidental_values_are_not_payloads(self):
        i = analyze({"url": "https://api.corp/x", "retries": 3, "mode": "fast"})
        assert i.write_shaped is False

    def test_read_only_tools_override_wins(self):
        i = analyze(
            {"url": "https://search.corp/q?query=how+do+i+configure+this"},
            tool_name="docs_search",
            read_only_tools=frozenset({"docs_search"}),
        )
        assert i.write_shaped is False
        assert i.evidence["write_shaped_reason"] == "read_only_tools override"

    def test_remote_read_only_hint_is_evidence_but_never_decisive(self):
        """The resource under evaluation does not get to clear itself."""
        i = analyze({"url": "https://wiki.com/w.pl?action=edit&text=payload", "readOnlyHint": True})
        assert i.write_shaped is True
        assert i.evidence["remote_read_only_hint"] is True

    def test_no_egress_call_is_never_write_shaped(self):
        assert analyze({"expression": "2 + 2"}).write_shaped is False


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

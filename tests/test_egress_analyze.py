import pytest

from admina.domains.agent_security.egress import EgressStatus, analyze


def _nest(levels: int, leaf: dict) -> dict:
    """Wrap *leaf* in *levels* plain dicts, so leaf keys sit at that depth."""
    root: dict = {}
    cur = root
    for _ in range(levels):
        cur["k"] = {}
        cur = cur["k"]
    cur.update(leaf)
    return root


class TestWriteShaped:
    def test_query_string_makes_a_call_payload_bearing(self):
        i = analyze({"url": "https://wiki.com/w.pl?action=edit&text=hello+there+everyone"})
        assert i.write_shaped is True

    def test_trivial_query_string_is_not_payload_bearing(self):
        """Short query strings like ?id=1 are ordinary reads, not payloads."""
        assert analyze({"url": "https://api.corp/items?id=1"}).write_shaped is False
        assert analyze({"url": "https://api.corp/p?page=2"}).write_shaped is False
        assert analyze({"url": "https://api.corp/x?q=a"}).write_shaped is False

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


class TestSingleLabelHosts:
    """Single-label hostnames (Docker/compose service names) resolve, but only
    when they sit under a key that declares a network destination."""

    def test_bare_single_label_host_under_network_key_resolves(self):
        i = analyze({"host": "redis", "port": 6379})
        assert i.status is EgressStatus.RESOLVED
        assert i.destinations == ["redis"]

    def test_placeholder_under_network_key_is_still_unresolvable(self):
        """The single-label pattern must not accept shell/template placeholders."""
        i = analyze({"url": "${TARGET_ENDPOINT}"})
        assert i.status is EgressStatus.UNRESOLVABLE

    def test_single_label_value_outside_a_network_key_is_not_a_destination(self):
        i = analyze({"note": "hello"})
        assert i.status is EgressStatus.NO_EGRESS
        assert i.destinations == []

    def test_write_shaped_classification_unaffected_by_single_label_word(self):
        """A bare word must not become a 'host' for write-shaped purposes."""
        i = analyze({"url": "https://api.corp/x", "note": "hello"})
        assert i.write_shaped is False
        assert i.destinations == ["api.corp"]

    def test_long_free_form_word_beside_destination_is_still_write_shaped(self):
        """A single long word is a payload by length; it must not be swallowed by
        host-shaped handling meant only for network-key values."""
        i = analyze({"url": "https://api.corp/x", "note": "supercalifragilistic"})
        assert i.write_shaped is True


class TestBareDottedTokens:
    """A dotted token is a destination only when the argument name says so.

    ``_HOST_RX`` accepts any dotted token with an alphabetic tail, so
    "notes.txt" and "os.path" parse as hostnames. Accepting them anywhere in
    the arguments makes every local-file, database and module-name tool an
    egress attempt, and under default-deny that refuses the call — while
    spec §5.2's table says a local file tool must pass through. It also
    poisons `admina egress suggest-allowlist`, which proposes exactly the
    destinations observed here.
    """

    @pytest.mark.parametrize(
        "tool, params",
        [
            ("read_file", {"path": "notes.txt"}),
            ("write_file", {"filename": "report.docx"}),
            ("db_query", {"table": "users.accounts"}),
            ("import_module", {"module": "os.path"}),
            ("archive", {"src": "backup.tar.gz", "dest_name": "backup.old"}),
        ],
    )
    def test_local_tools_are_not_egress_attempts(self, tool, params):
        i = analyze(params, tool)
        assert i.status is EgressStatus.NO_EGRESS
        assert i.destinations == []

    def test_a_full_url_under_a_non_network_key_is_still_caught(self):
        """The gate is on bare tokens only: a scheme makes a value unambiguous."""
        i = analyze({"note": "https://publictestwiki.com/w.pl?action=edit"})
        assert i.status is EgressStatus.RESOLVED
        assert i.destinations == ["publictestwiki.com"]

    def test_an_ip_literal_under_a_non_network_key_is_still_caught(self):
        i = analyze({"note": "10.0.0.5"})
        assert i.status is EgressStatus.RESOLVED
        assert i.destinations == ["10.0.0.5"]

    def test_a_bare_host_under_a_network_key_still_resolves(self):
        """The gate must not cost the scheme-less host form of §5.1."""
        i = analyze({"endpoint": "publictestwiki.com"})
        assert i.status is EgressStatus.RESOLVED
        assert i.destinations == ["publictestwiki.com"]

    def test_a_file_name_under_a_network_key_is_still_a_destination(self):
        """The argument name is what declares intent, so this must resolve —
        the operator named the field, not the analyzer."""
        assert analyze({"url": "notes.txt"}).destinations == ["notes.txt"]


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

    def test_truncated_scan_is_unresolvable_not_no_egress(self):
        """A destination buried past the depth cap must not read as "no egress".

        NO_EGRESS is the outcome the policy passes through unconditionally,
        so reporting it for a scan that simply stopped early would let an
        agent that controls its own argument shape walk past the control by
        nesting the URL deep enough. Spec §5.2: an egress attempt whose
        target cannot be established is denied.
        """
        deep = _nest(50, {"url": "https://deep.com"})
        intent = analyze(deep)
        assert intent.status is EgressStatus.UNRESOLVABLE
        assert intent.evidence["scan_truncated"] is True

    def test_truncated_scan_is_denied_under_enforce(self):
        from admina.domains.agent_security.egress import EgressPolicy

        policy = EgressPolicy(allow=["api.openai.com"])
        decision = policy.evaluate(analyze(_nest(50, {"url": "https://deep.com"})), "enforce")
        assert decision.allowed is False
        assert "unresolvable" in decision.reason

    def test_truncated_scan_records_without_blocking_under_observe(self):
        from admina.domains.agent_security.egress import EgressPolicy

        policy = EgressPolicy(allow=["api.openai.com"])
        decision = policy.evaluate(analyze(_nest(50, {"url": "https://deep.com"})), "observe")
        assert decision.allowed is True

    @pytest.mark.parametrize("nesting", [7, 8, 11, 30])
    def test_first_unscanned_level_and_beyond_all_fail_closed(self, nesting):
        """Level 6 is still scanned; 7 is the first level past the walk.

        Before this was fixed, 7 and everything below it reported NO_EGRESS
        and were allowed under default-deny.
        """
        assert analyze(_nest(nesting, {"url": "https://deep.com"})).status is (
            EgressStatus.UNRESOLVABLE
        )

    @pytest.mark.parametrize("nesting", [0, 3, 6])
    def test_levels_within_the_scan_still_resolve_the_destination(self, nesting):
        intent = analyze(_nest(nesting, {"url": "https://deep.com"}))
        assert intent.status is not EgressStatus.NO_EGRESS
        assert "scan_truncated" not in intent.evidence

    def test_truncation_outranks_a_destination_resolved_above_it(self):
        """A decoy allowlisted host must not buy passage for a buried one.

        `analyze()` already lets one unresolvable *field* beat a resolved
        sibling; a region the walk never reached is the same situation and
        must rank the same way. Otherwise "allowlisted host at the top, real
        destination below the depth cap" is a one-line evasion of a
        default-deny control.
        """
        from admina.domains.agent_security.egress import EgressPolicy

        decoy = {
            "url": "https://api.openai.com/v1",
            "x": _nest(7, {"url": "https://evil.example/x"}),
        }
        intent = analyze(decoy)
        assert intent.status is EgressStatus.UNRESOLVABLE
        assert intent.evidence["scan_truncated"] is True
        assert EgressPolicy(allow=["api.openai.com"]).evaluate(intent, "enforce").allowed is False

    def test_the_decoy_case_is_recorded_not_blocked_under_observe(self):
        from admina.domains.agent_security.egress import EgressPolicy

        decoy = {
            "url": "https://api.openai.com/v1",
            "x": _nest(7, {"url": "https://evil.example/x"}),
        }
        decision = EgressPolicy(allow=["api.openai.com"]).evaluate(analyze(decoy), "observe")
        assert decision.allowed is True
        assert "nested past the scan depth limit" in decision.reason

    def test_the_denial_reason_names_truncation_not_the_allowlist(self):
        """An operator must be able to tell a depth refusal from an
        allowlist refusal, from the response or the forensic record alone."""
        from admina.domains.agent_security.egress import EgressPolicy

        policy = EgressPolicy(allow=["api.openai.com"])
        depth = policy.evaluate(analyze(_nest(8, {"url": "https://evil.example/x"})), "enforce")
        allowlist = policy.evaluate(analyze({"url": "https://evil.example/x"}), "enforce")
        assert "nested past the scan depth limit" in depth.reason
        assert "nested past the scan depth limit" not in allowlist.reason
        assert allowlist.reason == "destination not on the egress allowlist"

    def test_truncation_and_an_unresolvable_field_are_both_named(self):
        from admina.domains.agent_security.egress import EgressPolicy

        params = {"host": "${SECRET}", "x": _nest(7, {"url": "https://evil.example/x"})}
        reason = EgressPolicy(allow=[]).evaluate(analyze(params), "enforce").reason
        assert "nested past the scan depth limit" in reason
        assert "'host'" in reason

    def test_shallow_non_network_call_is_still_no_egress(self):
        """Truncation is the trigger, not depth: a shallow computation tool
        must keep passing through untouched under default-deny."""
        assert analyze({"expression": "2 + 2"}).status is EgressStatus.NO_EGRESS

    def test_deep_but_complete_non_network_call_is_still_no_egress(self):
        """Nesting that stays within the cap is not truncation."""
        assert analyze(_nest(5, {"expression": "2 + 2"})).status is EgressStatus.NO_EGRESS

from admina.domains.agent_security.fingerprint import (
    MIN_SHARED_SHINGLES,
    load_fingerprint_key,
    matches,
    overlap,
    sketch,
)

_KEY = b"deployment-secret"
_TEXT = (
    "task 42 completed, the results are on ZZZ_Results_42, "
    "whoever picks up 43 should start from the second column"
)


class TestSketch:
    def test_identical_text_gives_identical_sketch(self):
        assert sketch(_TEXT, _KEY) == sketch(_TEXT, _KEY)

    def test_reformatted_text_still_overlaps_strongly(self):
        """Text survives a round trip through an agent reformatting it."""
        reflowed = _TEXT.replace(", ", ",\n  ").upper()
        assert overlap(sketch(_TEXT, _KEY), sketch(reflowed, _KEY)) > 0.6

    def test_unrelated_text_barely_overlaps(self):
        other = "the quarterly revenue report shows a decline in the northern region"
        assert overlap(sketch(_TEXT, _KEY), sketch(other, _KEY)) < 0.1

    def test_a_different_key_gives_a_different_sketch(self):
        """Without this, sketches would be comparable across deployments."""
        assert sketch(_TEXT, _KEY) != sketch(_TEXT, b"other-secret")

    def test_short_text_yields_an_empty_sketch(self):
        assert sketch("too short", _KEY) == frozenset()

    def test_sketch_is_bounded(self):
        long_text = " ".join(f"word{i}" for i in range(5000))
        assert len(sketch(long_text, _KEY)) <= 512

    def test_sketch_holds_no_plaintext(self):
        """The hard requirement: a sketch must not be reversible by inspection."""
        s = sketch(_TEXT, _KEY)
        assert all(isinstance(v, int) for v in s)
        assert "ZZZ_Results_42" not in str(s)


class TestOverlap:
    def test_empty_sketches_do_not_match(self):
        assert overlap(frozenset(), frozenset()) == 0.0
        assert overlap(sketch(_TEXT, _KEY), frozenset()) == 0.0


class TestKeyLoading:
    def test_absent_key_is_none(self, monkeypatch):
        monkeypatch.delenv("ADMINA_EGRESS_FINGERPRINT_KEY", raising=False)
        assert load_fingerprint_key() is None

    def test_present_key_is_bytes(self, monkeypatch):
        monkeypatch.setenv("ADMINA_EGRESS_FINGERPRINT_KEY", "s3cret")
        assert load_fingerprint_key() == b"s3cret"

    def test_blank_key_is_treated_as_absent(self, monkeypatch):
        monkeypatch.setenv("ADMINA_EGRESS_FINGERPRINT_KEY", "   ")
        assert load_fingerprint_key() is None


class TestContainment:
    def test_message_embedded_in_long_page(self):
        """Containment: text found inside a longer message scores high.

        This is the core scenario the detector exists for. An agent writes
        a message, later another agent receives a page containing that
        message. The sketches must indicate containment despite the length
        difference.

        Fails with Jaccard overlap because truncation samples different
        quantile ranges; Szymkiewicz–Simpson (containment coefficient)
        solves it.
        """
        message = _TEXT
        # Long page with the message embedded and reformatted
        page = (
            "The task update is as follows:\n\n"
            + message.upper()
            + "\n\n"
            + " ".join(f"filler{i}" for i in range(100))
        )
        assert matches([sketch(message, _KEY)], [sketch(page, _KEY)]) is True
        assert overlap(sketch(message, _KEY), sketch(page, _KEY)) > 0.6

    def test_boilerplate_phrase_does_not_match(self):
        """Boilerplate alone is not containment.

        Two unrelated short texts sharing only a common courtesy phrase
        score high on overlap but low on intersection count. The dual
        condition (both overlap and MIN_SHARED_SHINGLES) discriminates.

        Fails without MIN_SHARED_SHINGLES check because overlap alone
        allows the false positive.
        """
        text_a = "The quarterly report is attached. Please let me know if you need anything else."
        text_b = "The deployment is complete. Please let me know if you need anything else."
        shared = len(sketch(text_a, _KEY) & sketch(text_b, _KEY))
        # Overlap may be high but intersection is small
        assert overlap(sketch(text_a, _KEY), sketch(text_b, _KEY)) >= 0.5
        assert shared < 12  # Below MIN_SHARED_SHINGLES
        assert matches([sketch(text_a, _KEY)], [sketch(text_b, _KEY)]) is False

    def test_tail_truncation_does_not_fire_for_spec_input(self):
        """SKETCH_SIZE=512 does not truncate in-spec input.

        A 2000-character tail (~263 shingles) is the bound the detector
        passes. Truncation must not fire for it, or comparison degrades.
        This test asserts the constant is large enough.

        Fails if SKETCH_SIZE is too small: the sketch would be incomplete.
        """
        # Approximately 2000 characters
        words = [f"word{i}" for i in range(400)]  # ~400 words = ~2400 chars
        tail = " ".join(words)
        s = sketch(tail, _KEY)
        # No truncation means len(s) ≤ number of shingles, not ≤ SKETCH_SIZE
        shingles_approx = len(words) - 5 + 1  # SHINGLE_WORDS=5
        assert len(s) <= shingles_approx
        # Verify SKETCH_SIZE is not the limiting factor
        assert len(s) < 512

    def test_a_shared_footer_between_two_long_texts_does_not_match(self):
        """The condition the intersection floor cannot carry on its own.

        Two long messages with nothing in common but an automated footer
        clear MIN_SHARED_SHINGLES on the footer alone — a 24-word footer is
        20 shingles. What rejects them is containment: 20 shingles out of
        200 is not one text appearing inside another. Set the threshold to
        0 and this pair confirms an echo between two agents who never
        exchanged anything.
        """
        footer = (
            "this message was generated automatically by the reporting service please do not"
            " reply to it directly and instead open a ticket with the platform team"
        )
        assert len(footer.split()) >= 16, "the footer must clear the shingle floor alone"
        text_a = " ".join(f"alpha{i}" for i in range(200)) + " " + footer
        text_b = " ".join(f"bravo{i}" for i in range(200)) + " " + footer
        a, b = sketch(text_a, _KEY), sketch(text_b, _KEY)

        assert len(a & b) >= MIN_SHARED_SHINGLES, "the floor is not what rejects this pair"
        assert overlap(a, b) < 0.4
        assert matches([a], [b]) is False

    def test_the_threshold_argument_is_what_rejects_it(self):
        """Names the condition under test, so the pair above cannot be read
        as a second test of the shingle floor."""
        footer = (
            "this message was generated automatically by the reporting service please do not"
            " reply to it directly and instead open a ticket with the platform team"
        )
        a = sketch(" ".join(f"alpha{i}" for i in range(200)) + " " + footer, _KEY)
        b = sketch(" ".join(f"bravo{i}" for i in range(200)) + " " + footer, _KEY)
        assert matches([a], [b], threshold=0.4) is False
        assert matches([a], [b], threshold=0.0) is True, "only the ratio separates them"


class TestKeyLength:
    def test_a_short_key_is_reported(self, monkeypatch, caplog):
        """The key's whole purpose is to make the shingles of a common phrase
        un-enumerable; a key of a few bytes does not."""
        import logging

        monkeypatch.setenv("ADMINA_EGRESS_FINGERPRINT_KEY", "s3cret")
        with caplog.at_level(logging.WARNING, logger="admina.coordination"):
            assert load_fingerprint_key() == b"s3cret"
        assert any("dictionary attack" in rec.getMessage() for rec in caplog.records)

    def test_a_long_enough_key_is_not_reported(self, monkeypatch, caplog):
        import logging

        monkeypatch.setenv("ADMINA_EGRESS_FINGERPRINT_KEY", "x" * 32)
        with caplog.at_level(logging.WARNING, logger="admina.coordination"):
            assert load_fingerprint_key() == b"x" * 32
        assert caplog.records == []

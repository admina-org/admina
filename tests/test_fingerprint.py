from admina.domains.agent_security.fingerprint import (
    load_fingerprint_key,
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
        assert len(sketch(long_text, _KEY)) <= 64

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

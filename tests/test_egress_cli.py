import json
import os
import time

from click.testing import CliRunner

from admina.cli.main import app
from admina.domains.compliance.forensic import ForensicBlackBox


def _record(tmp_path, name, dests, write_shaped=True):
    """Helper to create a flat test record (for dedup/sort/empty tests)."""
    (tmp_path / name).write_text(
        json.dumps(
            {
                "event_id": name,
                "checks": {
                    "egress": {
                        "status": "resolved",
                        "destinations": dests,
                        "write_shaped": write_shaped,
                        "allowed": True,
                    }
                },
            }
        )
    )


class TestSuggestAllowlist:
    def test_prints_observed_destinations_as_yaml(self, tmp_path):
        _record(tmp_path, "a.json", ["api.openai.com"])
        _record(tmp_path, "b.json", ["api.openai.com", "docs.corp.internal"])
        result = CliRunner().invoke(
            app, ["egress", "suggest-allowlist", "--forensic-dir", str(tmp_path)]
        )
        assert result.exit_code == 0
        assert "api.openai.com" in result.output
        assert "docs.corp.internal" in result.output
        assert "domains:" in result.output
        assert "agent_security:" in result.output

    def test_destinations_are_deduplicated_and_sorted(self, tmp_path):
        _record(tmp_path, "a.json", ["z.com", "a.com"])
        _record(tmp_path, "b.json", ["a.com"])
        out = (
            CliRunner()
            .invoke(app, ["egress", "suggest-allowlist", "--forensic-dir", str(tmp_path)])
            .output
        )
        assert out.index("a.com") < out.index("z.com")
        assert out.count("- a.com") == 1

    def test_empty_directory_explains_rather_than_printing_an_empty_block(self, tmp_path):
        result = CliRunner().invoke(
            app, ["egress", "suggest-allowlist", "--forensic-dir", str(tmp_path)]
        )
        assert result.exit_code == 0
        assert "No egress observations" in result.output

    def test_output_states_that_promotion_is_a_human_decision(self, tmp_path):
        _record(tmp_path, "a.json", ["api.openai.com"])
        out = (
            CliRunner()
            .invoke(app, ["egress", "suggest-allowlist", "--forensic-dir", str(tmp_path)])
            .output
        )
        assert "review" in out.lower()

    def test_malformed_record_is_skipped(self, tmp_path):
        (tmp_path / "bad.json").write_text("{not json")
        _record(tmp_path, "good.json", ["api.openai.com"])
        result = CliRunner().invoke(
            app, ["egress", "suggest-allowlist", "--forensic-dir", str(tmp_path)]
        )
        assert result.exit_code == 0
        assert "api.openai.com" in result.output

    def test_wrapped_record_from_real_forensic_blackbox(self, tmp_path):
        """Test against real ForensicBlackBox record shape (wrapped under 'event')."""
        fb = ForensicBlackBox(filesystem_dir=str(tmp_path))
        fb.record(
            {
                "checks": {
                    "egress": {
                        "status": "resolved",
                        "destinations": ["api.anthropic.com", "api.openai.com"],
                        "write_shaped": True,
                        "allowed": True,
                    }
                }
            }
        )
        result = CliRunner().invoke(
            app, ["egress", "suggest-allowlist", "--forensic-dir", str(tmp_path)]
        )
        assert result.exit_code == 0
        assert "api.anthropic.com" in result.output
        assert "api.openai.com" in result.output

    def test_since_excludes_old_records(self, tmp_path):
        """Test that --since filters records by modification time."""
        _record(tmp_path, "recent.json", ["api.openai.com"])
        old_file = tmp_path / "old.json"
        _record(tmp_path, "old.json", ["very-old-api.com"])
        # Set modification time to 10 days ago
        old_mtime = time.time() - (10 * 86400)
        os.utime(str(old_file), (old_mtime, old_mtime))

        # With --since 7, old file excluded
        result = CliRunner().invoke(
            app,
            [
                "egress",
                "suggest-allowlist",
                "--forensic-dir",
                str(tmp_path),
                "--since",
                "7",
            ],
        )
        assert result.exit_code == 0
        assert "api.openai.com" in result.output
        assert "very-old-api.com" not in result.output

    def test_since_includes_old_records_with_larger_window(self, tmp_path):
        """Test that --since includes records when window is large enough."""
        _record(tmp_path, "recent.json", ["api.openai.com"])
        old_file = tmp_path / "old.json"
        _record(tmp_path, "old.json", ["very-old-api.com"])
        # Set modification time to 10 days ago
        old_mtime = time.time() - (10 * 86400)
        os.utime(str(old_file), (old_mtime, old_mtime))

        # With --since 11, old file included
        result = CliRunner().invoke(
            app,
            [
                "egress",
                "suggest-allowlist",
                "--forensic-dir",
                str(tmp_path),
                "--since",
                "11",
            ],
        )
        assert result.exit_code == 0
        assert "api.openai.com" in result.output
        assert "very-old-api.com" in result.output

    def test_non_dict_record_is_skipped(self, tmp_path):
        """Test that non-dict records (e.g., [1,2,3]) are skipped without crash."""
        (tmp_path / "array.json").write_text(json.dumps([1, 2, 3]))
        _record(tmp_path, "good.json", ["api.openai.com"])
        result = CliRunner().invoke(
            app, ["egress", "suggest-allowlist", "--forensic-dir", str(tmp_path)]
        )
        assert result.exit_code == 0
        assert "api.openai.com" in result.output

    def test_malformed_nested_shapes_are_skipped(self, tmp_path):
        """Test that unexpected nested shapes are skipped gracefully."""
        # Record with checks not being a dict
        (tmp_path / "bad_checks.json").write_text(json.dumps({"event": {"checks": "not a dict"}}))
        # Record with egress not being a dict
        (tmp_path / "bad_egress.json").write_text(
            json.dumps({"event": {"checks": {"egress": [1, 2, 3]}}})
        )
        _record(tmp_path, "good.json", ["api.openai.com"])
        result = CliRunner().invoke(
            app, ["egress", "suggest-allowlist", "--forensic-dir", str(tmp_path)]
        )
        assert result.exit_code == 0
        assert "api.openai.com" in result.output
        assert "[1, 2, 3]" not in result.output

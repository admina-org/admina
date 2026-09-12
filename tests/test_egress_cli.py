import json

from click.testing import CliRunner

from admina.cli.main import app


def _record(tmp_path, name, dests, write_shaped=True):
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

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

"""``admina forensic export`` and ``admina forensic verify``.

``export --from-seq N --format jsonl`` writes the records of a filesystem
store from sequence number N on, in sequence order, one per line: the bytes
of each record file as they are, then a newline. Nothing is added or
changed. ``verify`` checks the chain of a store directory without writing
to it and prints the result as JSON.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from _forensic_chain import STATE, flip_byte, record_file, record_files, write_chain
from click.testing import CliRunner

from admina.cli.main import app
from admina.domains.compliance.forensic import ForensicBlackBox


@pytest.fixture
def runner(monkeypatch) -> CliRunner:
    for name in (
        "FORENSIC_BASE_DIR",
        "ADMINA_FORENSIC_STATE_KEY",
        "ADMINA_FORENSIC_STATE_KEY_FILE",
    ):
        monkeypatch.delenv(name, raising=False)
    return CliRunner()


def _snapshot(base: Path) -> dict[str, bytes]:
    return {str(p.relative_to(base)): p.read_bytes() for p in base.rglob("*") if p.is_file()}


def _export(runner: CliRunner, *args: str, env: dict | None = None):
    return runner.invoke(app, ["forensic", "export", *args], env=env, catch_exceptions=False)


def test_export_from_a_sequence_number_as_jsonl(tmp_path, runner):
    base = tmp_path / "forensic"
    write_chain(base, 25, per_dir=4)
    before = _snapshot(base)

    result = _export(runner, "--from-seq", "3", "--format", "jsonl", "--dir", str(base))

    assert result.exit_code == 0, result.output
    expected = b"".join(p.read_bytes() + b"\n" for p in record_files(base)[2:])
    assert result.stdout_bytes == expected
    lines = result.stdout_bytes.splitlines()
    assert [json.loads(line)["sequence_number"] for line in lines] == list(range(3, 26))
    assert _snapshot(base) == before


def test_export_of_records_written_by_the_store(tmp_path, runner):
    base = tmp_path / "forensic"
    box = ForensicBlackBox(filesystem_dir=str(base))
    for i in range(4):
        box.record({"event_id": f"e{i}", "note": "line\nbreak and ünïcode"})

    result = _export(runner, "--dir", str(base))

    assert result.exit_code == 0
    assert result.stdout_bytes == b"".join(p.read_bytes() + b"\n" for p in record_files(base))


def test_export_defaults_to_the_forensic_base_dir(tmp_path, runner):
    base = tmp_path / "forensic"
    write_chain(base, 5)
    result = _export(runner, "--from-seq", "4", env={"FORENSIC_BASE_DIR": str(base)})
    assert result.exit_code == 0
    assert len(result.stdout_bytes.splitlines()) == 2


def test_export_to_a_file(tmp_path, runner):
    base = tmp_path / "forensic"
    write_chain(base, 9, per_dir=2)
    out = tmp_path / "out" / "records.jsonl"
    out.parent.mkdir()

    result = _export(runner, "--dir", str(base), "--out", str(out))

    assert result.exit_code == 0
    assert result.stdout_bytes == b""
    assert out.read_bytes() == b"".join(p.read_bytes() + b"\n" for p in record_files(base))
    assert sorted(p.name for p in out.parent.iterdir()) == ["records.jsonl"]


def test_export_past_the_last_record_is_empty(tmp_path, runner):
    base = tmp_path / "forensic"
    write_chain(base, 3)
    result = _export(runner, "--from-seq", "4", "--dir", str(base))
    assert result.exit_code == 0
    assert result.stdout_bytes == b""


def test_export_skips_state_and_temporary_files(tmp_path, runner):
    base = tmp_path / "forensic"
    write_chain(base, 3)
    last = record_files(base)[-1]
    (last.parent / ".00000004.json.0a1b2c3d.tmp").write_bytes(b'{"partial"')
    (base / "_chain_state.json.sig").write_text("0" * 64)

    result = _export(runner, "--dir", str(base))

    assert [json.loads(line)["sequence_number"] for line in result.stdout_bytes.splitlines()] == [
        1,
        2,
        3,
    ]


@pytest.mark.parametrize("kind", ["missing", "file"])
def test_export_of_an_invalid_directory_fails(tmp_path, runner, kind):
    target = tmp_path / "nowhere"
    if kind == "file":
        target.write_text("not a directory")
    result = runner.invoke(app, ["forensic", "export", "--dir", str(target)])
    assert result.exit_code != 0
    assert "nowhere" in result.output


def test_export_without_a_directory_fails(runner):
    result = runner.invoke(app, ["forensic", "export"])
    assert result.exit_code != 0
    assert "FORENSIC_BASE_DIR" in result.output


def test_export_supports_jsonl_only(tmp_path, runner):
    base = tmp_path / "forensic"
    write_chain(base, 2)
    result = runner.invoke(app, ["forensic", "export", "--dir", str(base), "--format", "csv"])
    assert result.exit_code != 0


def test_export_refuses_a_record_that_is_not_one_line(tmp_path, runner):
    base = tmp_path / "forensic"
    write_chain(base, 3)
    path = record_file(base, 2)
    path.write_bytes(path.read_bytes() + b"\n")
    result = runner.invoke(app, ["forensic", "export", "--dir", str(base)])
    assert result.exit_code != 0
    assert "2" in result.output


# ── verify ────────────────────────────────────────────────────


def _verify(runner: CliRunner, base: Path, *args: str):
    result = runner.invoke(app, ["forensic", "verify", "--dir", str(base), *args])
    return result, json.loads(result.stdout) if result.stdout.startswith("{") else None


def test_verify_a_valid_store(tmp_path, runner):
    base = tmp_path / "forensic"
    head = write_chain(base, 12, per_dir=5)
    before = _snapshot(base)

    result, body = _verify(runner, base)

    assert result.exit_code == 0
    assert body["valid"] is True
    assert body["records"] == 12
    assert body["checkpoint"] == {"sequence_number": 12, "record_hash": head}
    assert _snapshot(base) == before


def test_verify_reports_a_changed_record(tmp_path, runner):
    base = tmp_path / "forensic"
    write_chain(base, 6)
    flip_byte(record_file(base, 4), b'"ALLOW"')
    result, body = _verify(runner, base)
    assert result.exit_code == 1
    assert (body["valid"], body["reason"], body["sequence_number"]) == (False, "hash_mismatch", 4)


def test_verify_from_a_checkpoint(tmp_path, runner):
    base = tmp_path / "forensic"
    write_chain(base, 10)
    third = json.loads(record_file(base, 3).read_bytes())["record_hash"]
    flip_byte(record_file(base, 2), b'"ALLOW"')

    result, body = _verify(runner, base, "--checkpoint", f"3:{third}")

    assert result.exit_code == 0
    assert body["records"] == 7


@pytest.mark.parametrize(
    "value",
    [
        "3",
        "x:" + "0" * 64,
        "3:nothex",
        "0:" + "0" * 64,
        pytest.param("9" * 5000 + ":" + "0" * 64, id="long-seq"),
    ],
)
def test_verify_rejects_a_malformed_checkpoint(tmp_path, runner, value):
    base = tmp_path / "forensic"
    write_chain(base, 3)
    result = runner.invoke(app, ["forensic", "verify", "--dir", str(base), "--checkpoint", value])
    assert result.exit_code == 2


def test_verify_compares_with_the_chain_state(tmp_path, runner):
    base = tmp_path / "forensic"
    write_chain(base, 5)
    record_file(base, 5).unlink()
    result, body = _verify(runner, base)
    assert result.exit_code == 1
    assert body["valid"] is False
    assert (base / STATE).is_file()

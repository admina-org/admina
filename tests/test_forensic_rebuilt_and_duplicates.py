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

"""A rebuilt chain state stays visible; a record with a duplicated key does not verify.

After the chain state is rebuilt from the records, ``chain_status`` stays
``rebuilt`` across restarts (the chain state carries it) until an operator
acknowledges the rebuild once the whole chain verifies
(``ForensicBlackBox.acknowledge_rebuild()``, ``admina forensic
acknowledge-rebuild``). A record whose JSON repeats a key is reported as
``hash_mismatch``: a parser that keeps the first value would read another
record than the one that was hashed.
"""

from __future__ import annotations

import json
import secrets

from _forensic_chain import STATE, STATE_SIG, record_file

from admina.domains.compliance.forensic import ForensicBlackBox, verify_directory


def _key() -> str:
    return "canary-" + secrets.token_hex(16)


def _rebuilt_store(tmp_path, key: str) -> ForensicBlackBox:
    base = tmp_path / "forensic"
    box = ForensicBlackBox(filesystem_dir=str(base), state_signing_key=key)
    for i in range(3):
        box.record({"event_id": f"e{i}", "action": "ALLOW"})
    (base / STATE).unlink()
    (base / STATE_SIG).unlink()
    box = ForensicBlackBox(filesystem_dir=str(base), state_signing_key=key)
    assert box.chain_status == "rebuilt"
    return box


def test_rebuilt_survives_a_restart(tmp_path):
    key = _key()
    _rebuilt_store(tmp_path, key)
    again = ForensicBlackBox(filesystem_dir=str(tmp_path / "forensic"), state_signing_key=key)
    assert again.chain_status == "rebuilt"
    again.record({"event_id": "later"})
    third = ForensicBlackBox(filesystem_dir=str(tmp_path / "forensic"), state_signing_key=key)
    assert third.chain_status == "rebuilt"


def test_acknowledging_a_verified_rebuild_clears_it(tmp_path):
    key = _key()
    box = _rebuilt_store(tmp_path, key)
    result = box.acknowledge_rebuild()
    assert result["acknowledged"] is True
    assert result["records"] == box.record_count
    assert box.chain_status == "ok"
    again = ForensicBlackBox(filesystem_dir=str(tmp_path / "forensic"), state_signing_key=key)
    assert again.chain_status == "ok"


def test_a_chain_that_does_not_verify_is_not_acknowledged(tmp_path):
    key = _key()
    box = _rebuilt_store(tmp_path, key)
    path = record_file(tmp_path / "forensic", 2)
    record = json.loads(path.read_text())
    record["action"] = "BLOCK"
    path.write_text(json.dumps(record))
    result = box.acknowledge_rebuild()
    assert result["acknowledged"] is False
    assert result["reason"] == "hash_mismatch"
    assert box.chain_status == "rebuilt"


def test_nothing_to_acknowledge_on_an_ok_chain(tmp_path):
    box = ForensicBlackBox(filesystem_dir=str(tmp_path / "forensic"), state_signing_key=_key())
    box.record({"event_id": "e1"})
    assert box.acknowledge_rebuild() == {"acknowledged": False, "reason": "not_rebuilt"}


def test_the_cli_acknowledges_a_rebuild(tmp_path, monkeypatch):
    from click.testing import CliRunner

    from admina.cli.main import app

    key = _key()
    _rebuilt_store(tmp_path, key)
    monkeypatch.setenv("ADMINA_FORENSIC_STATE_KEY", key)
    run = CliRunner().invoke(
        app, ["forensic", "acknowledge-rebuild", "--dir", str(tmp_path / "forensic")]
    )
    assert run.exit_code == 0, run.output
    assert "acknowledged" in run.output
    again = ForensicBlackBox(filesystem_dir=str(tmp_path / "forensic"), state_signing_key=key)
    assert again.chain_status == "ok"


def test_a_record_with_a_duplicated_key_does_not_verify(tmp_path):
    key = _key()
    base = tmp_path / "forensic"
    box = ForensicBlackBox(filesystem_dir=str(base), state_signing_key=key)
    for i in range(3):
        box.record({"event_id": f"e{i}", "action": "ALLOW"})
    path = record_file(base, 2)
    text = path.read_text()
    # A first "event" that says BLOCK; a parser that keeps the last value
    # reads the record that was hashed, one that keeps the first does not.
    assert text.startswith('{"event": ')
    path.write_text('{"event": {"action": "BLOCK", "event_id": "e1"}, ' + text[1:])
    result = verify_directory(base, state_key=key)
    assert (result["valid"], result["reason"], result["sequence_number"]) == (
        False,
        "hash_mismatch",
        2,
    )

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

"""Each forensic record carries a signature.

With a chain-state key (``ADMINA_FORENSIC_STATE_KEY[_FILE]``), ``record_sig``
is the HMAC-SHA256 of the record's ``record_hash`` (its 64 ASCII hex
characters) under a key derived from the state key, and ``record_sig_alg``
is ``hmac-sha256``; without a key, ``record_sig_alg`` is ``none``.
``record_hash`` is the SHA-256 of the record without ``record_hash``,
``record_sig`` and ``record_sig_alg``. Verification checks the signatures
when it has the key; the key is never written to the store or the logs.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import secrets

import pytest
from _forensic_chain import (
    STATE,
    STATE_SIG,
    load,
    record_file,
    record_files,
    rewrite,
    sign_state,
    write_chain,
)

from admina.domains.compliance.forensic import ForensicBlackBox, verify_directory
from admina.domains.compliance.forensic_integrity import (
    HASH_EXCLUDED_FIELDS,
    compute_record_hash,
    record_signing_key,
    sign_record_hash,
)

LABEL = b"admina-forensic/1 record signature"


def _key() -> str:
    return "canary-" + secrets.token_hex(16)


def _signed_store(tmp_path, key: str, count: int = 4) -> ForensicBlackBox:
    box = ForensicBlackBox(filesystem_dir=str(tmp_path / "forensic"), state_signing_key=key)
    for i in range(count):
        box.record({"event_id": f"e{i}", "action": "ALLOW", "note": f"note-{i}"})
    return box


def _verify(box: ForensicBlackBox) -> dict:
    return asyncio.run(box.verify_chain())


def test_the_hash_leaves_out_the_hash_and_signature_fields():
    assert HASH_EXCLUDED_FIELDS == ("record_hash", "record_sig", "record_sig_alg")


def test_every_record_is_signed(tmp_path):
    key = _key()
    _signed_store(tmp_path, key)
    records = [load(p) for p in record_files(tmp_path / "forensic")]
    assert len(records) == 4
    for record in records:
        assert record["record_sig_alg"] == "hmac-sha256"
        assert len(record["record_sig"]) == 64
        assert record["record_sig"] == record["record_sig"].lower()


def test_the_signature_is_an_hmac_of_the_record_hash_with_a_derived_key(tmp_path):
    key = _key()
    _signed_store(tmp_path, key)
    derived = hmac.new(key.encode("utf-8"), LABEL, hashlib.sha256).digest()
    assert record_signing_key(key) == derived
    for record in (load(p) for p in record_files(tmp_path / "forensic")):
        expected = hmac.new(derived, record["record_hash"].encode("ascii"), hashlib.sha256)
        assert record["record_sig"] == expected.hexdigest()
        assert sign_record_hash(derived, record["record_hash"]) == record["record_sig"]


@pytest.mark.parametrize("signed", [True, False])
def test_record_hash_recomputes_with_the_documented_exclusion_list(tmp_path, signed):
    _signed_store(tmp_path, _key() if signed else None)
    for record in (load(p) for p in record_files(tmp_path / "forensic")):
        kept = {
            k: v
            for k, v in record.items()
            if k not in ("record_hash", "record_sig", "record_sig_alg")
        }
        digest = hashlib.sha256(
            json.dumps(kept, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()
        assert digest == record["record_hash"] == compute_record_hash(record)


def test_signed_records_verify(tmp_path):
    box = _signed_store(tmp_path, _key())
    result = _verify(box)
    assert result["valid"] is True
    assert (result["signed"], result["unsigned"], result["signatures_verified"]) == (4, 0, True)


def test_a_wrong_key_does_not_verify(tmp_path):
    _signed_store(tmp_path, _key())
    result = verify_directory(tmp_path / "forensic", state_key=_key())
    assert (result["valid"], result["reason"], result["sequence_number"]) == (
        False,
        "signature_invalid",
        1,
    )


def test_a_changed_signature_does_not_verify(tmp_path):
    key = _key()
    box = _signed_store(tmp_path, key)
    path = record_file(tmp_path / "forensic", 3)
    record = load(path)
    record["record_sig"] = sign_record_hash(record_signing_key(_key()), record["record_hash"])
    rewrite(path, record)
    result = _verify(box)
    assert (result["valid"], result["reason"], result["sequence_number"]) == (
        False,
        "signature_invalid",
        3,
    )


def test_an_unknown_signature_algorithm_does_not_verify(tmp_path):
    box = _signed_store(tmp_path, _key())
    path = record_file(tmp_path / "forensic", 2)
    record = load(path)
    record["record_sig_alg"] = "hmac-md5"
    rewrite(path, record)
    result = _verify(box)
    assert (result["reason"], result["sequence_number"]) == ("signature_invalid", 2)


def test_a_signed_chain_does_not_accept_a_record_without_signature(tmp_path):
    box = _signed_store(tmp_path, _key())
    path = record_file(tmp_path / "forensic", 2)
    record = load(path)
    del record["record_sig"]
    record["record_sig_alg"] = "none"
    rewrite(path, record)
    result = _verify(box)
    assert (result["valid"], result["reason"], result["sequence_number"]) == (
        False,
        "unsigned",
        2,
    )


def test_records_written_without_a_key_are_reported_as_unsigned(tmp_path, monkeypatch):
    monkeypatch.delenv("ADMINA_FORENSIC_STATE_KEY", raising=False)
    monkeypatch.delenv("ADMINA_FORENSIC_STATE_KEY_FILE", raising=False)
    box = _signed_store(tmp_path, None)
    for record in (load(p) for p in record_files(tmp_path / "forensic")):
        assert record["record_sig_alg"] == "none"
        assert "record_sig" not in record
    result = _verify(box)
    assert result["valid"] is True
    assert (result["signed"], result["unsigned"], result["signatures_verified"]) == (0, 4, False)


def test_the_key_is_never_written_to_the_store_or_the_logs(tmp_path, caplog):
    key = _key()
    with caplog.at_level(logging.DEBUG):
        box = _signed_store(tmp_path, key)
        ForensicBlackBox(filesystem_dir=str(tmp_path / "forensic"), state_signing_key=key)
        _verify(box)
    derived = record_signing_key(key).hex()
    logged = "\n".join(f"{r.getMessage()} {r.exc_text or ''}" for r in caplog.records)
    for secret in (key, derived):
        assert secret not in logged
        for path in (tmp_path / "forensic").rglob("*"):
            if path.is_file():
                assert secret.encode() not in path.read_bytes()


def test_records_written_before_a_key_was_set_stay_readable(tmp_path):
    """A chain whose state was signed with the key but whose earlier records
    carry no signature: the records written from then on are signed and
    verified, the earlier ones are counted as unsigned."""
    key = _key()
    base = tmp_path / "forensic"
    write_chain(base, 3)
    sign_state(base, key)

    box = ForensicBlackBox(filesystem_dir=str(base), state_signing_key=key)
    box.record({"event_id": "e4"})
    box.record({"event_id": "e5"})

    result = _verify(box)
    assert result["valid"] is True
    assert (result["signed"], result["unsigned"]) == (2, 3)
    # A record without signature after them is not accepted.
    path = record_file(base, 5)
    record = load(path)
    del record["record_sig"]
    record["record_sig_alg"] = "none"
    rewrite(path, record)
    assert (_verify(box)["reason"], _verify(box)["sequence_number"]) == ("unsigned", 5)


def test_the_directory_verification_uses_the_key_from_the_environment(tmp_path, monkeypatch):
    from click.testing import CliRunner

    from admina.cli.main import app

    key = _key()
    _signed_store(tmp_path, key)
    runner = CliRunner()
    args = ["forensic", "verify", "--dir", str(tmp_path / "forensic")]
    good = runner.invoke(app, args, env={"ADMINA_FORENSIC_STATE_KEY": key})
    assert good.exit_code == 0
    assert json.loads(good.stdout)["signed"] == 4
    bad = runner.invoke(app, args, env={"ADMINA_FORENSIC_STATE_KEY": _key()})
    assert bad.exit_code == 1
    assert json.loads(bad.stdout)["reason"] == "signature_invalid"
    assert key not in bad.stdout


def test_a_key_file_inside_the_store_directory_is_refused(tmp_path, monkeypatch):
    from admina.core.secretfile import SecretFileError

    base = tmp_path / "forensic"
    (base / "keys").mkdir(parents=True)
    key_file = base / "keys" / "state_key"
    key_file.write_text(_key())
    monkeypatch.setenv("ADMINA_FORENSIC_STATE_KEY_FILE", str(key_file))
    monkeypatch.delenv("ADMINA_FORENSIC_STATE_KEY", raising=False)
    with pytest.raises(SecretFileError, match="outside the forensic directory"):
        ForensicBlackBox(filesystem_dir=str(base))


def test_a_key_file_outside_the_store_directory_is_used(tmp_path, monkeypatch):
    key = _key()
    key_file = tmp_path / "secrets" / "state_key"
    key_file.parent.mkdir()
    key_file.write_text(key)
    monkeypatch.setenv("ADMINA_FORENSIC_STATE_KEY_FILE", str(key_file))
    monkeypatch.delenv("ADMINA_FORENSIC_STATE_KEY", raising=False)
    box = ForensicBlackBox(filesystem_dir=str(tmp_path / "forensic"))
    box.record({"event_id": "e1"})
    assert _verify(box)["signed"] == 1


# ── Signatures that are not 64 lowercase hex characters ───────

NOT_HEX_SIGNATURES = {
    "not-ascii": "é" * 64,
    "not-hex": "Z" * 64,
    "upper-case": "A" * 64,
    "short": "0" * 63,
    "long": "0" * 65,
    "empty": "",
}


@pytest.mark.parametrize("signature", NOT_HEX_SIGNATURES.values(), ids=NOT_HEX_SIGNATURES)
@pytest.mark.parametrize("with_key", [True, False])
def test_a_signature_that_is_not_lowercase_hex_is_invalid(tmp_path, signature, with_key):
    key = _key()
    _signed_store(tmp_path, key)
    path = record_file(tmp_path / "forensic", 2)
    record = load(path)
    record["record_sig"] = signature
    rewrite(path, record)
    result = verify_directory(tmp_path / "forensic", state_key=key if with_key else None)
    assert (result["valid"], result["reason"], result["sequence_number"]) == (
        False,
        "signature_invalid",
        2,
    )


@pytest.mark.parametrize("seq", [2, 4])
@pytest.mark.parametrize("state", ["kept", "deleted"])
def test_the_store_starts_with_a_signature_that_is_not_hex(tmp_path, seq, state):
    key = _key()
    _signed_store(tmp_path, key)
    base = tmp_path / "forensic"
    path = record_file(base, seq)
    record = load(path)
    record["record_sig"] = "é" * 64
    rewrite(path, record)
    if state == "deleted":
        (base / STATE).unlink()
    box = ForensicBlackBox(filesystem_dir=str(base), state_signing_key=key)
    if seq == 2 and state == "kept":
        # Startup checks the head record only; verification finds record 2.
        assert box.chain_status == "ok"
    else:
        assert box.chain_status == "invalid"
        assert box.chain_error == {"reason": "signature_invalid", "sequence_number": seq}
    result = _verify(box)
    assert (result["valid"], result["reason"]) == (False, "signature_invalid")


CHAIN_STATE_SIGNATURES = {
    "not-ascii": "é".encode() * 32,
    "not-utf-8": b"\xff" * 64,
    "upper-case": b"A" * 64,
    "short": b"0" * 63,
}


@pytest.mark.parametrize("name", list(CHAIN_STATE_SIGNATURES))
def test_a_chain_state_signature_that_is_not_hex_is_invalid(tmp_path, name):
    key = _key()
    _signed_store(tmp_path, key)
    base = tmp_path / "forensic"
    (base / STATE_SIG).write_bytes(CHAIN_STATE_SIGNATURES[name])
    result = verify_directory(base, state_key=key)
    assert (result["valid"], result["reason"]) == (False, "state_invalid")
    # At startup the chain state is not used; the records all verify with
    # the key, so the state is rebuilt from them.
    box = ForensicBlackBox(filesystem_dir=str(base), state_signing_key=key)
    assert box.chain_status == "rebuilt"
    assert box.record_count == 5  # 4 records and the chain_state_rebuilt one


def test_a_chain_state_signature_with_white_space_around_it_verifies(tmp_path):
    key = _key()
    _signed_store(tmp_path, key)
    base = tmp_path / "forensic"
    digest = (base / STATE_SIG).read_bytes().strip()
    (base / STATE_SIG).write_bytes(b" " + digest + b"\n")
    assert verify_directory(base, state_key=key)["valid"] is True
    assert ForensicBlackBox(filesystem_dir=str(base), state_signing_key=key).chain_status == "ok"


def test_hex_digests_are_compared_as_ascii():
    from admina.domains.compliance.forensic_integrity import hex_digest_matches, stored_hex_digest

    digest = "ab" * 32
    assert hex_digest_matches(digest, digest) is True
    for value in ("é" * 64, "AB" * 32, digest[:-1], None, 42, b"ab" * 32):
        assert hex_digest_matches(value, digest) is False
    assert stored_hex_digest(f" {digest}\n".encode()) == digest
    for data in ("é".encode() * 32, b"\xff" * 64, b"", ("AB" * 32).encode()):
        assert stored_hex_digest(data) is None

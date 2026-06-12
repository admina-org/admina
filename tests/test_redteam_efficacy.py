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
"""CI gate: detection efficacy must not regress below the committed baseline.

Soft gate: the scorecard is always printed; the build fails only on a real
recall/type_recall regression or a new false positive, per detector+engine, vs
baselines/baseline.json. The comparison policy lives in (and is unit-tested via)
``admina.redteam.gate.compare``:

* Python detectors are **mandatory** — a baseline-declared python entry that did
  not run fails the gate (it is the worst-case regression, not a skip).
* Rust is an **optional** accelerator — a missing rust entry is skipped silently
  (mirrors test_firewall_parity.py: admina_core may be absent).
* PII metrics are **environment-pinned** — the baseline records the redactor's
  measurement mode (``nlp:<model>@<version>`` vs ``regex``). If a mandatory
  (Python) detector's pinned mode is not reproduced the gate fails with an
  actionable message; a mismatch on the optional Rust engine is a note. A python
  entry that ran but is absent from the baseline also fails (reverse coverage).
"""

from __future__ import annotations

import json
from pathlib import Path

from admina import redteam
from admina.redteam import gate

_BASELINE = Path(redteam.__file__).parent / "baselines" / "baseline.json"


def test_efficacy_does_not_regress():
    committed = json.loads(_BASELINE.read_text(encoding="utf-8"))
    card = redteam.run_suite()
    print("\n" + redteam.to_markdown(card))  # always surface the scorecard in the CI log
    current = redteam.make_baseline(card)

    result = gate.compare(committed, current)
    if result["notes"]:
        # Transparent, auditable skips (e.g. PII env-mode mismatch) — surfaced in
        # the CI log so a silenced check is never invisible, but not a failure.
        print("\n[redteam] gate notes (not regressions):\n  " + "\n  ".join(result["notes"]))
    assert not result["failures"], "efficacy regression:\n" + "\n".join(result["failures"])

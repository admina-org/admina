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
"""Compare a freshly measured baseline against the committed one. Pure; no I/O.

Soft-gate policy (see tests/test_redteam_efficacy.py):

* **Python detectors are mandatory.** A detector+engine that the committed
  baseline declares for the ``python`` engine but the current run did not
  produce is the worst-case regression — the detector silently stopped running
  (e.g. an optional extra went missing) — and *fails* the gate. It is never
  treated as a skip.
* **Rust is an optional accelerator.** A missing ``rust`` entry is skipped
  silently, mirroring the rest of the suite (the Rust engine is absent whenever
  ``admina_core`` is not installed).
* **PII metrics are environment-pinned.** The Python redactor's recall and
  false-positive counts differ between spaCy-NER (``nlp:<model>@<version>``) and
  ``regex`` mode, so the baseline pins the measurement mode. If a **mandatory
  (python)** detector's pinned mode is not reproduced, its metrics cannot be
  verified, so the gate *fails* with an actionable message (match the env or
  regenerate the baseline) — it never silently skips, otherwise a real
  regression measured in the wrong mode would pass green. A mode mismatch on an
  **optional (rust)** engine is downgraded to a note.
* A real ``recall``/``type_recall`` drop or a new false positive (measured in
  the pinned mode) fails the gate.
* **Reverse coverage.** A python entry that actually ran but is absent from the
  committed baseline fails the gate too, so a truncated/empty baseline cannot
  silently shrink what is enforced.

``compare()`` returns ``{"failures": [...], "notes": [...]}``: ``failures`` are
hard gate violations (the build must go red); ``notes`` are transparent,
auditable skips that callers should surface but not fail on.
"""

from __future__ import annotations

from .report import recall_item

# Recall is a float in [0, 1]; only a drop beyond this tolerance is a regression
# (guards against float round-trip noise through JSON).
_RECALL_EPS = 1e-9


def compare(committed: dict, current: dict) -> dict:
    """Diff a current baseline against the committed one under the soft-gate policy.

    Both arguments are baseline-shaped: ``{detector: {engine: entry}}`` where
    ``entry`` carries a recall metric (``recall`` or ``type_recall``), ``fp``,
    ``fp_samples`` and optionally ``mode``. Iteration is driven by ``committed``
    so the gate enforces exactly what the baseline declares.
    """
    failures: list[str] = []
    notes: list[str] = []

    for detector, engines in committed.items():
        for engine, base in engines.items():
            cur = current.get(detector, {}).get(engine)

            if cur is None:
                # Python is mandatory: a declared-but-absent python entry means
                # the detector did not run at all — the worst-case regression.
                # Rust is optional: its absence is an accepted skip.
                if engine == "python":
                    failures.append(
                        f"{detector}/python declared in the baseline but did not run "
                        "(Python detectors are mandatory; install the full env / extras)"
                    )
                continue

            # Metrics measured in a different environment are not comparable.
            # The PII Python engine pins 'nlp:<model>@<version>' vs 'regex'. For a
            # MANDATORY (python) entry a mismatch is a failure: the pinned env was
            # not reproduced, so the detector's metrics cannot be verified, and
            # silently skipping would let a real regression measured in the wrong
            # mode pass green. An OPTIONAL (rust) engine downgrades it to a note.
            base_mode, cur_mode = base.get("mode"), cur.get("mode")
            if base_mode != cur_mode:
                msg = (
                    f"{detector}/{engine}: pinned measurement environment not reproduced — "
                    f"baseline mode '{base_mode}' vs current '{cur_mode}'. Match the env "
                    "(e.g. `python -m spacy download en_core_web_sm`) or regenerate the baseline."
                )
                (failures if engine == "python" else notes).append(msg)
                continue

            base_key, base_recall = recall_item(base)
            cur_key, cur_recall = recall_item(cur)
            if base_key != cur_key:
                # The recall metric itself changed shape (e.g. a detector switched
                # kind binary<->pii): not comparable — flag rather than mis-compare.
                failures.append(
                    f"{detector}/{engine} recall metric changed: baseline "
                    f"'{base_key}' vs current '{cur_key}' (regenerate the baseline)"
                )
                continue
            if (
                base_recall is not None
                and cur_recall is not None
                and cur_recall < base_recall - _RECALL_EPS
            ):
                failures.append(
                    f"{detector}/{engine} {base_key} {cur_recall:.4f} < baseline {base_recall:.4f}"
                )

            base_fp, cur_fp = base.get("fp"), cur.get("fp")
            if base_fp is not None and cur_fp is not None and cur_fp > base_fp:
                failures.append(f"{detector}/{engine} fp {cur_fp} > baseline {base_fp}")

    # Reverse coverage: a python entry that actually ran but is NOT declared in
    # the committed baseline means the baseline is truncated/incomplete. Fail
    # loudly so a bad regeneration cannot silently shrink what the gate enforces.
    for detector, engines in current.items():
        for engine in engines:
            if engine == "python" and committed.get(detector, {}).get(engine) is None:
                failures.append(
                    f"{detector}/python ran but the committed baseline does not declare it "
                    "(baseline incomplete — regenerate it)"
                )

    return {"failures": failures, "notes": notes}

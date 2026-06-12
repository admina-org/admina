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
"""Run a detector over a corpus on one engine, aggregating confusion buckets."""

from __future__ import annotations


def _zero_binary() -> dict:
    return {"tp": 0, "fp": 0, "fn": 0, "tn": 0}


def _zero_pii() -> dict:
    return {"expected_total": 0, "intersect_total": 0, "neg_samples": 0, "neg_flagged": 0}


def _cell(is_positive: bool, predicted: bool) -> str:
    if is_positive:
        return "tp" if predicted else "fn"
    return "fp" if predicted else "tn"


def _evaluate_binary(adapter, engine: str, samples: list[dict]) -> dict:
    overall, by_tag, by_lang = _zero_binary(), {}, {}
    for s in samples:
        is_pos = s["label"] == adapter.positive_label
        predicted = adapter.predict(engine, s)["detected"]
        cell = _cell(is_pos, predicted)
        overall[cell] += 1
        by_tag.setdefault(s["tag"], _zero_binary())[cell] += 1
        by_lang.setdefault(s["lang"], _zero_binary())[cell] += 1
    return {"kind": "binary", "overall": overall, "by_tag": by_tag, "by_lang": by_lang}


def _bump_pii(bucket: dict, expected: set, detected: set) -> None:
    """Accumulate the counts behind the type-level micro-average (see metrics.pii_scores).

    Positive samples (those with expected types) contribute their per-type
    counts to ``expected_total`` / ``intersect_total`` — the numerator and
    denominator of ``type_recall``, which is therefore weighted by how many
    types each sample carries, not by sample. Negative samples contribute to
    the sample-level false-positive counts instead.
    """
    if expected:
        bucket["expected_total"] += len(expected)
        bucket["intersect_total"] += len(expected & detected)
    else:
        bucket["neg_samples"] += 1
        if detected:
            bucket["neg_flagged"] += 1


def _evaluate_pii(adapter, engine: str, samples: list[dict]) -> dict:
    overall, by_tag, by_lang = _zero_pii(), {}, {}
    for s in samples:
        expected = set(s["expected_types"])
        detected = adapter.predict(engine, s)["detected_types"]
        _bump_pii(overall, expected, detected)
        _bump_pii(by_tag.setdefault(s["tag"], _zero_pii()), expected, detected)
        _bump_pii(by_lang.setdefault(s["lang"], _zero_pii()), expected, detected)
    return {"kind": "pii", "overall": overall, "by_tag": by_tag, "by_lang": by_lang}


def evaluate(adapter, engine: str, samples: list[dict]) -> dict:
    """Evaluate one detector+engine over samples; return confusion buckets by tag and lang."""
    if adapter.kind == "pii":
        return _evaluate_pii(adapter, engine, samples)
    return _evaluate_binary(adapter, engine, samples)

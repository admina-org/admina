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
"""Pure scoring functions. No I/O, no dependencies. Zero denominator -> None."""

from __future__ import annotations


def _safe_div(num: float, den: float) -> float | None:
    return num / den if den else None


def binary_scores(tp: int, fp: int, fn: int, tn: int) -> dict:
    """Scores for a binary detector (positive=attack/loop); tp/fp/fn/tn are sample counts."""
    recall = _safe_div(tp, tp + fn)
    precision = _safe_div(tp, tp + fp)
    fpr = _safe_div(fp, fp + tn)
    # F1 = 2*p*r/(p+r) is undefined when p+r == 0 (degenerate p=r=0, not a null case).
    if recall is None or precision is None or (precision + recall) == 0:
        f1 = None
    else:
        f1 = 2 * precision * recall / (precision + recall)
    return {
        "recall": recall,
        "precision": precision,
        "fpr": fpr,
        "f1": f1,
        "counts": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
    }


def pii_scores(
    expected_total: int, intersect_total: int, neg_samples: int, neg_flagged: int
) -> dict:
    """Type-level PII scores.

    ``type_recall`` is a **micro-average over PII types**, deliberately *not*
    the sample-level ``recall`` produced by :func:`binary_scores`. It is the
    total number of expected PII types that were detected, summed across every
    positive sample, divided by the total number of expected types
    (``intersect_total / expected_total``). A sample that expects 3 types and
    has 2 detected contributes 2/3 — not 0 (any-miss) and not 1 (any-hit). It
    is reported under a distinct key precisely so it is never conflated with
    the binary, sample-level ``recall``.

    ``fp`` is sample-level: the count of negative samples (no expected types)
    on which the detector flagged anything, and ``fpr`` is that over all
    negatives. These FP figures are environment-sensitive for the Python
    engine (spaCy NER fires on some non-English negatives); the redteam
    baseline pins the measurement mode so the gate compares like-for-like.
    """
    return {
        "type_recall": _safe_div(intersect_total, expected_total),
        "fpr": _safe_div(neg_flagged, neg_samples),
        "fp": neg_flagged,
        "fp_samples": neg_samples,
        "counts": {
            "expected_total": expected_total,
            "intersect_total": intersect_total,
            "neg_samples": neg_samples,
            "neg_flagged": neg_flagged,
        },
    }

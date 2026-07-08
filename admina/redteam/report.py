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
"""Turn raw evaluation buckets into a scorecard (JSON + Markdown) and a baseline."""

from __future__ import annotations

from . import metrics

RUST_CAVEAT = (
    "Note: the Rust engine does not implement homoglyph/leetspeak/base64/ROT13 evasion "
    "normalization, and its PII coverage is regex-only with fewer patterns (no "
    "IBAN/codice-fiscale/DNI; multilingual NER needs Python+spaCy). Cells show each "
    "engine's MEASURED detection, not equivalent capability. See MODEL_CARD.md for limits."
)


def _score_bucket(kind: str, counts: dict) -> dict:
    if kind == "pii":
        return metrics.pii_scores(**counts)
    return metrics.binary_scores(**counts)


def score_engine(eval_result: dict) -> dict:
    """Apply metrics to the overall bucket and every per-tag / per-lang bucket."""
    kind = eval_result["kind"]
    return {
        "overall": _score_bucket(kind, eval_result["overall"]),
        "by_tag": {t: _score_bucket(kind, c) for t, c in eval_result["by_tag"].items()},
        "by_lang": {lng: _score_bucket(kind, c) for lng, c in eval_result["by_lang"].items()},
    }


def build_scorecard(results: dict, rust_version: str | None, env: dict | None = None) -> dict:
    """Assemble the full scorecard from {detector: {engine: eval_result}}.

    ``env`` is an optional ``{detector: {engine: signature}}`` map of
    measurement-environment signatures (e.g. the PII engine's spaCy-vs-regex
    mode). When present, the signature is attached to that detector+engine
    score as ``"mode"`` so the committed baseline can pin it and the CI gate
    can compare metrics only within the same mode.
    """
    env = env or {}
    detectors_out: dict = {}
    rust_seen = False
    for det, by_engine in results.items():
        detectors_out[det] = {}
        for eng, ev in by_engine.items():
            score = score_engine(ev)
            sig = env.get(det, {}).get(eng)
            if sig is not None:
                score["mode"] = sig
            detectors_out[det][eng] = score
        rust_seen = rust_seen or "rust" in by_engine
    return {
        # v2: the PII detector row reports `type_recall` (not `recall`) and
        # carries a measurement `mode`; consumers branching on the recall key
        # must handle both. Bumped from v1 during PR #29 review.
        "schema_version": 2,
        "engines": {
            "python": {"available": True},
            "rust": {"available": rust_seen, "version": rust_version},
        },
        "detectors": detectors_out,
    }


def _fp_and_samples(score: dict) -> tuple:
    c = score["counts"]
    if "tp" in c:  # binary
        return c["fp"], c["fp"] + c["tn"]
    return c["neg_flagged"], c["neg_samples"]


def recall_item(metrics_like: dict) -> tuple:
    """Return (key, value) for whichever recall metric a score/baseline entry carries.

    Binary detectors expose sample-level ``recall``; the PII detector exposes a
    type-level ``type_recall`` (see metrics.pii_scores). They are never the same
    key, so every consumer (baseline, gate, markdown) compares like-for-like and
    reports the correct name instead of silently conflating the two.
    """
    if "type_recall" in metrics_like:
        return "type_recall", metrics_like["type_recall"]
    if "recall" in metrics_like:
        return "recall", metrics_like["recall"]
    raise KeyError(f"entry carries neither 'recall' nor 'type_recall': {sorted(metrics_like)}")


def make_baseline(scorecard: dict) -> dict:
    """Reduce a scorecard to the committed baseline shape: recall + fp + fp_samples.

    The recall metric is stored under its real key (``recall`` for binary
    detectors, ``type_recall`` for PII). When a detector+engine carries a
    measurement-mode signature (``mode``), it is copied into the baseline so the
    CI gate can refuse to compare metrics across modes.
    """
    base: dict = {}
    for det, by_engine in scorecard["detectors"].items():
        base[det] = {}
        for eng, score in by_engine.items():
            overall = score["overall"]
            fp, fp_samples = _fp_and_samples(overall)
            rkey, rval = recall_item(overall)
            entry = {rkey: rval, "fp": fp, "fp_samples": fp_samples}
            if "mode" in score:
                entry["mode"] = score["mode"]
            base[det][eng] = entry
    return base


def _pct(x: float | None) -> str:
    return "n/a" if x is None else f"{round(x * 100)}%"


def _cell_recall(metric: dict | None) -> str:
    return _pct(recall_item(metric)[1]) if metric else "-"


def to_markdown(scorecard: dict) -> str:
    """Render the dual-engine per-class recall matrix, with the Rust caveat above it."""
    lines = [
        f"> {RUST_CAVEAT}",
        "",
        "| Detector | Class | Python | Rust | Presidio |",
        "|---|---|:---:|:---:|:---:|",
    ]
    for det, by_engine in scorecard["detectors"].items():
        tags = sorted({t for eng in by_engine.values() for t in eng["by_tag"]})
        for tag in tags:
            py = by_engine.get("python", {}).get("by_tag", {}).get(tag)
            rs = by_engine.get("rust", {}).get("by_tag", {}).get(tag)
            pr = by_engine.get("presidio", {}).get("by_tag", {}).get(tag)
            lines.append(
                f"| {det} | {tag} | {_cell_recall(py)} | {_cell_recall(rs)} | {_cell_recall(pr)} |"
            )
    footnotes = []
    if "pii" in scorecard["detectors"]:
        footnotes.append(
            "_PII rows report **type-level recall** (micro-average over PII types, "
            "see `admina/redteam/metrics.py`), not the sample-level recall used for "
            "injection/loop._"
        )
    modes = [
        f"{det}/{eng} measured in `{score['mode']}` mode"
        for det, by_engine in scorecard["detectors"].items()
        for eng, score in by_engine.items()
        if "mode" in score
    ]
    if modes:
        footnotes.append("_Measurement environment: " + "; ".join(modes) + "._")
    if footnotes:
        lines.append("")
        lines.extend(footnotes)
    return "\n".join(lines) + "\n"

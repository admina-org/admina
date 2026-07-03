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
"""admina-redteam — detection efficacy measurement suite."""

from __future__ import annotations

from .corpora import load_corpus
from .detectors import all_detectors, rust_available
from .gate import compare
from .report import build_scorecard, make_baseline, to_markdown
from .runner import evaluate

__all__ = [
    "run_suite",
    "load_corpus",
    "build_scorecard",
    "make_baseline",
    "to_markdown",
    "compare",
]

_CORPUS_FOR = {"injection": "injection", "pii": "pii", "loop": "loop"}


def _rust_version() -> str | None:
    try:
        import admina_core

        return admina_core.version()
    except Exception:  # noqa: BLE001 - version() is best-effort metadata
        return None


def run_suite(engines: list[str] | None = None, corpora: list[str] | None = None) -> dict:
    """Run each selected detector over its corpus on each available engine; return the scorecard.

    engines: restrict to a subset of ["python", "rust"] (default: all available).
    corpora: restrict to a subset of ["injection", "pii", "loop"] (default: all).
    """
    results: dict = {}
    env: dict = {}
    for adapter in all_detectors():
        if corpora is not None and adapter.name not in corpora:
            continue
        available = adapter.engines()
        chosen = [e for e in available if engines is None or e in engines]
        samples = load_corpus(_CORPUS_FOR[adapter.name])
        results[adapter.name] = {e: evaluate(adapter, e, samples) for e in chosen}
        # Capture measurement-environment signatures (e.g. the PII engine's
        # spaCy-vs-regex mode) so the baseline can pin them and the gate can
        # refuse to compare metrics across modes. Detectors without an
        # env_signature() hook (injection, loop) are environment-stable.
        sig_fn = getattr(adapter, "env_signature", None)
        if sig_fn is not None:
            for e in chosen:
                sig = sig_fn(e)
                if sig is not None:
                    env.setdefault(adapter.name, {})[e] = sig
    return build_scorecard(
        results, rust_version=_rust_version() if rust_available() else None, env=env
    )

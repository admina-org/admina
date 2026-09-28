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

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .corpora import load_corpus, load_external_corpora
from .detectors import all_detectors, rust_available
from .gate import compare
from .report import build_scorecard, make_baseline, to_markdown
from .runner import evaluate

if TYPE_CHECKING:
    from admina.core.config import FirewallConfig

__all__ = [
    "BASELINE_PATH",
    "run_suite",
    "load_corpus",
    "load_external_corpora",
    "build_scorecard",
    "make_baseline",
    "to_markdown",
    "compare",
]

#: The baseline of the packaged corpora.
BASELINE_PATH = Path(__file__).parent / "baselines" / "baseline.json"

_CORPUS_FOR = {"injection": "injection", "pii": "pii", "loop": "loop"}


def _rust_version() -> str | None:
    try:
        import admina_core

        return admina_core.version()
    except Exception:  # noqa: BLE001 - version() is best-effort metadata
        return None


def _firewall_config(path: str | Path) -> FirewallConfig:
    """``agent_security.firewall`` of the admina.yaml at *path*.

    Raises:
        FileNotFoundError: *path* is not a file.
        ConfigSchemaError: a value has the wrong type.
        ValueError, yaml.YAMLError: the file is not a YAML mapping.
    """
    from admina.core.config import load_config

    if not Path(path).is_file():
        raise FileNotFoundError(f"admina.yaml {path} is not a file")
    return load_config(path).agent_security.firewall


def _load_baseline(baseline: str | Path | dict) -> dict:
    if isinstance(baseline, dict):
        return baseline
    data = json.loads(Path(baseline).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not all(isinstance(v, dict) for v in data.values()):
        raise ValueError(f"baseline {baseline} is not a mapping of detector to engine entries")
    return data


def _gate(
    card: dict,
    baseline: str | Path | dict,
    corpora: list[str] | None,
    engines: list[str] | None,
) -> dict:
    """:func:`compare` of the run against *baseline*, limited to the corpora
    and engines selected for the run."""
    committed = {
        name: {
            engine: entry
            for engine, entry in entries.items()
            if engines is None or engine in engines
        }
        for name, entries in _load_baseline(baseline).items()
        if corpora is None or name in corpora
    }
    result = compare(committed, make_baseline(card))
    source = None if isinstance(baseline, dict) else str(baseline)
    return {"baseline": source, **result}


def run_suite(
    engines: list[str] | None = None,
    corpora: list[str] | None = None,
    *,
    corpora_dir: str | Path | None = None,
    baseline: str | Path | dict | None = None,
    config: str | Path | None = None,
) -> dict:
    """Run each selected detector over its corpus on each available engine; return the scorecard.

    engines: restrict to a subset of ["python", "rust"] (default: all available).
    corpora: restrict to a subset of the corpora: "injection", "pii", "loop"
        and the external ones (default: all).
    corpora_dir: a directory of external corpora
        (:func:`~admina.redteam.corpora.load_external_corpora`), run after the
        packaged ones under their names, each by the detector of its rows. The
        scorecard's ``external_corpora`` lists them (``dir``, and ``corpora``:
        name to detector).
    baseline: a baseline (a file, or its mapping) that the run is compared
        with (:func:`~admina.redteam.gate.compare`), limited to the selected
        corpora and engines; the scorecard's ``gate`` holds the result
        (``baseline``: the file or None, ``failures``, ``notes``).
    config: an admina.yaml whose ``agent_security.firewall`` settings build
        the injection firewall (see
        :class:`~admina.redteam.detectors.InjectionAdapter`); the scorecard's
        ``config`` holds its ``path`` and the ``python_only_keys`` that keep
        the Rust engine out of the injection corpora.

    Raises:
        ValueError: an unknown corpus in *corpora*; an external corpus that
            cannot be loaded (see ``load_external_corpora``) or is named as a
            packaged one; a *config* whose values have the wrong type or
            whose pattern packs cannot be loaded; a *baseline* that is not a
            mapping.
        OSError: a file cannot be read (FileNotFoundError: *config* is not
            a file).
    """
    firewall_config = _firewall_config(config) if config is not None else None
    detectors = {adapter.name: adapter for adapter in all_detectors(firewall_config)}
    external = load_external_corpora(corpora_dir) if corpora_dir is not None else {}
    clash = sorted(set(external) & set(_CORPUS_FOR))
    if clash:
        raise ValueError(
            f"external corpora {', '.join(clash)} have the name of a packaged corpus: rename them"
        )
    plan: list[tuple[str, Any, list[dict] | None]] = [
        (name, detectors[detector], None) for name, detector in _CORPUS_FOR.items()
    ]
    plan += [(name, detectors[c.detector], c.rows) for name, c in external.items()]
    if corpora is not None:
        unknown = sorted(set(corpora) - {name for name, _, _ in plan})
        if unknown:
            known = ", ".join(name for name, _, _ in plan)
            raise ValueError(f"unknown corpora {', '.join(unknown)} (available: {known})")

    results: dict = {}
    env: dict = {}
    for name, adapter, rows in plan:
        if corpora is not None and name not in corpora:
            continue
        available = adapter.engines()
        chosen = [e for e in available if engines is None or e in engines]
        samples = load_corpus(name) if rows is None else rows
        results[name] = {e: evaluate(adapter, e, samples) for e in chosen}
        # Capture measurement-environment signatures (e.g. the PII engine's
        # spaCy-vs-regex mode) so the baseline can pin them and the gate can
        # refuse to compare metrics across modes. Detectors without an
        # env_signature() hook (injection, loop) are environment-stable.
        sig_fn = getattr(adapter, "env_signature", None)
        if sig_fn is not None:
            for e in chosen:
                sig = sig_fn(e)
                if sig is not None:
                    env.setdefault(name, {})[e] = sig
    card = build_scorecard(
        results, rust_version=_rust_version() if rust_available() else None, env=env
    )
    if external:
        card["external_corpora"] = {
            "dir": str(corpora_dir),
            "corpora": {name: c.detector for name, c in external.items()},
        }
    if config is not None:
        card["config"] = {
            "path": str(config),
            "python_only_keys": detectors["injection"].python_only_keys(),
        }
    if baseline is not None:
        card["gate"] = _gate(card, baseline, corpora, engines)
    return card

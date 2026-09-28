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

"""``admina redteam``: the detection-efficacy scorecard of :mod:`admina.redteam`.

The packaged corpora, and the corpora of ``--corpora-dir``, run on the
selected engines; ``--format`` prints the Markdown scorecard and/or writes
the JSON one to ``--out``. ``--config`` (default ``$ADMINA_CONFIG``) builds
the injection firewall from the ``agent_security.firewall`` settings of an
admina.yaml. With ``--baseline`` or ``--gate`` the run is compared with a
baseline (default: the packaged one) and the result is printed on standard
error.

Exit status: 0; 1 when ``--gate`` finds a regression (a lower recall or a
new false positive, see :func:`admina.redteam.gate.compare`); 2 when the
command cannot run (an option, a corpus, the configuration or the baseline
is not valid).
"""

from __future__ import annotations

import json
from pathlib import Path

import click
import yaml

__all__ = ["redteam"]


class _CannotRun(click.ClickException):
    """The suite cannot run with this input (exit status 2)."""

    exit_code = 2


@click.command()
@click.option(
    "--engine",
    type=click.Choice(["both", "python", "rust"]),
    default="both",
    show_default=True,
    help="Engines to measure (both: every available engine).",
)
@click.option(
    "--corpus",
    default="all",
    show_default=True,
    metavar="NAME",
    help="Corpus to run: injection, pii, loop, the name of an external corpus, or all.",
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["md", "json", "both"]),
    default="both",
    show_default=True,
    help="md: print the Markdown scorecard; json: write the JSON scorecard to --out.",
)
@click.option(
    "--out",
    default="redteam-scorecard.json",
    show_default=True,
    type=click.Path(dir_okay=False),
    help="File of the JSON scorecard.",
)
@click.option(
    "--corpora-dir",
    type=click.Path(file_okay=False),
    default=None,
    help=(
        "Directory of external corpora: <name>.jsonl files in the format of the packaged "
        "corpora, all listed in its SHA256SUMS. They run after the packaged ones."
    ),
)
@click.option(
    "--config",
    type=click.Path(exists=True, dir_okay=False),
    envvar="ADMINA_CONFIG",
    default=None,
    help=(
        "admina.yaml whose agent_security.firewall settings build the injection firewall. "
        "Defaults to $ADMINA_CONFIG; without either, the default settings."
    ),
)
@click.option(
    "--baseline",
    type=click.Path(exists=True, dir_okay=False),
    default=None,
    help="Baseline to compare the run with (default with --gate: the packaged baseline).",
)
@click.option(
    "--gate",
    is_flag=True,
    help="Exit with status 1 when the run regresses against the baseline.",
)
@click.option(
    "--write-baseline",
    is_flag=False,
    flag_value="",
    default=None,
    metavar="[FILE]",
    help="Also write the baseline of this run to FILE (without FILE: baseline.json next to --out).",
)
def redteam(
    engine: str,
    corpus: str,
    fmt: str,
    out: str,
    corpora_dir: str | None,
    config: str | None,
    baseline: str | None,
    gate: bool,
    write_baseline: str | None,
) -> None:
    """Measure the detection efficacy of the firewall, PII and loop detectors."""
    from admina import redteam as suite

    if gate and baseline is None:
        baseline = str(suite.BASELINE_PATH)
    try:
        card = suite.run_suite(
            engines=None if engine == "both" else [engine],
            corpora=None if corpus == "all" else [corpus],
            corpora_dir=corpora_dir,
            baseline=baseline,
            config=config,
        )
    except (ValueError, OSError, yaml.YAMLError) as exc:
        raise _CannotRun(str(exc)) from exc

    if fmt in ("md", "both"):
        click.echo(suite.to_markdown(card))
    if fmt in ("json", "both"):
        Path(out).write_text(json.dumps(card, indent=2), encoding="utf-8")
    if write_baseline is not None:
        target = Path(write_baseline) if write_baseline else Path(out).with_name("baseline.json")
        target.write_text(json.dumps(suite.make_baseline(card), indent=2), encoding="utf-8")

    result = card.get("gate")
    if result is None:
        return
    failures = result["failures"]
    if failures:
        click.echo(f"redteam gate: {len(failures)} regression(s) against {baseline}:", err=True)
        for failure in failures:
            click.echo(f"  - {failure}", err=True)
    else:
        click.echo(f"redteam gate: passed against {baseline}", err=True)
    for note in result["notes"]:
        click.echo(f"  note: {note}", err=True)
    if gate and failures:
        raise SystemExit(1)

#!/usr/bin/env python3
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
"""CLI for the admina-redteam detection-efficacy suite (sibling of benchmark.py)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from admina import redteam  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Admina detection-efficacy scorecard")
    parser.add_argument("--engine", choices=["both", "python", "rust"], default="both")
    parser.add_argument("--corpus", choices=["all", "injection", "pii", "loop"], default="all")
    parser.add_argument("--format", choices=["md", "json", "both"], default="both")
    parser.add_argument("--out", default="redteam-scorecard.json")
    parser.add_argument(
        "--baseline", action="store_true", help="also write the reduced baseline shape"
    )
    args = parser.parse_args()

    engines = None if args.engine == "both" else [args.engine]
    corpora = None if args.corpus == "all" else [args.corpus]
    card = redteam.run_suite(engines=engines, corpora=corpora)

    if args.format in ("md", "both"):
        print(redteam.to_markdown(card))
    if args.format in ("json", "both"):
        Path(args.out).write_text(json.dumps(card, indent=2), encoding="utf-8")
    if args.baseline:
        Path(args.out).with_name("baseline.json").write_text(
            json.dumps(redteam.make_baseline(card), indent=2), encoding="utf-8"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

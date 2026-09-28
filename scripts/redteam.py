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
"""CLI for the admina-redteam detection-efficacy suite: runs ``admina redteam``.

The options are those of ``admina redteam``. ``--baseline`` without a file
(followed by nothing or by another option) writes the baseline of the run,
as ``--write-baseline`` does.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from admina.cli.redteam import redteam  # noqa: E402


def _arguments(argv: list[str]) -> list[str]:
    """*argv* with a ``--baseline`` that has no file as ``--write-baseline``."""
    args = list(argv)
    for index, arg in enumerate(args):
        following = args[index + 1] if index + 1 < len(args) else None
        if arg == "--baseline" and (following is None or following.startswith("-")):
            args[index] = "--write-baseline"
    return args


if __name__ == "__main__":
    redteam.main(args=_arguments(sys.argv[1:]), prog_name="redteam.py")

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

"""The EU AI Act help of the bundled dashboard and the route it documents.

POST /api/compliance/gap-analysis records an assessment; any other method
answers 405. The dashboard's example command must therefore be a POST, and
must target the origin that served the page (the proxy, or the dashboard
container that forwards /api/ to it), never a fixed host and port.
"""

from __future__ import annotations

import re
from pathlib import Path

import admina

_INDEX = Path(admina.__file__).parent / "dashboard" / "static" / "index.html"


def _assessment_command() -> str:
    html = _INDEX.read_text(encoding="utf-8")
    match = re.search(r'<pre[^>]*id="assessment-cmd"[^>]*>(.*?)</pre>', html, re.S)
    assert match, "assessment command not found in the dashboard page"
    return match.group(1)


def test_command_is_a_post_to_gap_analysis():
    cmd = _assessment_command()
    assert cmd.startswith("curl -X POST ")
    assert "/api/compliance/gap-analysis" in cmd


def test_command_targets_the_page_origin():
    cmd = _assessment_command()
    assert "localhost" not in cmd
    assert '<span x-text="apiBase"></span>/api/compliance/gap-analysis' in cmd
    assert "window.location.origin" in _INDEX.read_text(encoding="utf-8")


def test_gap_analysis_accepts_post_only():
    from admina.proxy.main import app

    routes = [r for r in app.routes if getattr(r, "path", "") == "/api/compliance/gap-analysis"]
    assert len(routes) == 1
    assert routes[0].methods == {"POST"}

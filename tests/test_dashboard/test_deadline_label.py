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

"""The EU AI Act countdown of the bundled dashboard.

The date shown next to the countdown and the number of days both come from
the enforcement deadline of /api/dashboard/compliance; the page carries no
fixed date of its own.
"""

from __future__ import annotations

from pathlib import Path

import admina

_INDEX = Path(admina.__file__).parent / "dashboard" / "static" / "index.html"


def test_no_fixed_deadline_text():
    html = _INDEX.read_text(encoding="utf-8")
    assert "August 2, 2026" not in html
    assert "'Deadline: ' + enforcementDeadlineLabel" in html


def test_label_and_countdown_read_the_same_deadline():
    html = _INDEX.read_text(encoding="utf-8")
    assert "get enforcementDeadline()" in html
    label = html.split("get enforcementDeadlineLabel()", 1)[1].split("},", 1)[0]
    days = html.split("get daysUntilDeadline()", 1)[1].split("},", 1)[0]
    assert "this.enforcementDeadline" in label
    assert "this.enforcementDeadline" in days


def test_fallback_is_the_engine_deadline():
    from admina.domains.compliance.eu_ai_act import EU_AI_ACT_ENFORCEMENT_DEADLINE

    html = _INDEX.read_text(encoding="utf-8")
    block = html.split("get enforcementDeadline()", 1)[1].split("},", 1)[0]
    assert f"'{EU_AI_ACT_ENFORCEMENT_DEADLINE}'" in block

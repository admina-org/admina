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

"""End-to-end: scaffold → discover → look up by name → execute.

This pins the third-party plugin loop: if any seam (template, registry
naming, discovery) regresses, this test fails.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from admina.cli.main import _scaffold_plugin
from admina.plugins.registry import PluginRegistry


def test_scaffolded_guard_full_loop(tmp_path):
    plugin_dir = tmp_path / "my-guard"
    created = _scaffold_plugin("my-guard", "governance_guard", plugin_dir)
    assert "pyproject.toml" in created

    reg = PluginRegistry()
    count = reg.discover(
        builtin_path=Path("/nonexistent"),
        user_path=plugin_dir,
        entry_point_group="",
    )
    assert count >= 1

    cls = reg.get("governance_guard", "my-guard")
    assert cls is not None, "scaffolded guard must register under its plugin name"

    guard = cls()
    verdict = asyncio.run(guard.inspect_request({"content": "hello", "params": {}}))
    assert verdict == {"action": "ALLOW", "risk_level": "LOW", "details": ""}

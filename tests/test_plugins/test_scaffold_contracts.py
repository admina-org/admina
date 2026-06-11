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

"""Scaffolded plugins must satisfy the async ABC contracts."""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from admina.cli.main import _SCAFFOLD_META, _scaffold_plugin
from admina.plugins.registry import PluginRegistry

# plugin types whose scaffold legitimately uses `Any` in signatures
_NEEDS_ANY = {"model_adapter", "data_connector", "transport_adapter", "auth_provider"}

# type_key → coroutine methods the ABC requires
ASYNC_METHODS = {
    "model_adapter": ["send"],
    "data_connector": ["ingest", "query"],
    "governance_guard": ["inspect_request", "inspect_response"],
    "compliance_template": [],  # sync ABC
    "transport_adapter": ["parse_request", "format_response"],
    "forensic_store": ["append", "verify_chain"],
    "auth_provider": ["authenticate", "authorize"],
    "pii_engine": ["detect", "redact"],
    "alert_channel": ["send_alert"],
}


@pytest.mark.parametrize("plugin_type", sorted(_SCAFFOLD_META))
def test_scaffolded_plugin_is_instantiable_and_async(plugin_type, tmp_path):
    plugin_name = f"demo-{plugin_type.replace('_', '-')}"
    _scaffold_plugin(plugin_name, plugin_type, tmp_path / plugin_name)

    reg = PluginRegistry()
    reg.discover(
        builtin_path=Path("/nonexistent"),
        user_path=tmp_path / plugin_name,
        entry_point_group="",
    )
    cls = reg.get(plugin_type, plugin_name)
    assert cls is not None, f"{plugin_type} scaffold not registered as {plugin_name!r}"

    instance = cls()  # raises TypeError if any abstract method is unimplemented
    assert instance.name == plugin_name

    for method in ASYNC_METHODS[plugin_type]:
        assert inspect.iscoroutinefunction(getattr(cls, method)), (
            f"{plugin_type}.{method} must be `async def` to match the ABC"
        )

    # `from typing import Any` must be present iff the scaffold uses Any
    plugin_module = plugin_name.replace("-", "_")
    source = (tmp_path / plugin_name / f"{plugin_module}.py").read_text()
    if plugin_type in _NEEDS_ANY:
        assert "from typing import Any" in source, (
            f"{plugin_type} scaffold uses Any but 'from typing import Any' is missing"
        )
    else:
        assert "from typing import Any" not in source, (
            f"unused 'from typing import Any' in {plugin_type} scaffold (ruff F401)"
        )


def test_scaffolded_pyproject_metadata(tmp_path):
    from admina import __version__

    _scaffold_plugin("my-guard", "governance_guard", tmp_path / "my-guard")
    text = (tmp_path / "my-guard" / "pyproject.toml").read_text()

    assert f"admina-framework>={__version__}" in text
    assert "admina>=0.9.0" not in text
    assert 'requires-python = ">=3.11"' in text
    assert '[project.entry-points."admina.plugins"]' in text
    assert 'my-guard = "my_guard"' in text

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

"""Tests for proxy plugin instantiation helpers."""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")


def test_instantiate_plugins_passes_config_block():
    from admina.plugins.base import BaseGovernanceGuard
    from admina.plugins.registry import PluginRegistry
    from admina.proxy.main import instantiate_plugins

    captured = {}

    class CfgGuard(BaseGovernanceGuard):
        name = "cfg-guard"

        def __init__(self, config=None):
            captured["config"] = config

        async def inspect_request(self, request):
            return {"action": "ALLOW", "risk_level": "LOW", "details": ""}

        async def inspect_response(self, response):
            return {"action": "ALLOW", "risk_level": "LOW", "details": ""}

    class PlainGuard(BaseGovernanceGuard):
        name = "plain-guard"

        async def inspect_request(self, request):
            return {"action": "ALLOW", "risk_level": "LOW", "details": ""}

        async def inspect_response(self, response):
            return {"action": "ALLOW", "risk_level": "LOW", "details": ""}

    reg = PluginRegistry()
    reg.register(CfgGuard)
    reg.register(PlainGuard)

    instances = instantiate_plugins(reg, "governance_guard", {"cfg-guard": {"threshold": 0.8}})
    assert len(instances) == 2
    assert captured["config"] == {"threshold": 0.8}


def test_instantiate_plugins_isolates_constructor_failure():
    from admina.plugins.base import BaseGovernanceGuard
    from admina.plugins.registry import PluginRegistry
    from admina.proxy.main import instantiate_plugins

    class BrokenGuard(BaseGovernanceGuard):
        name = "broken-guard"

        def __init__(self, config=None):
            raise ValueError("bad config")

        async def inspect_request(self, request):
            return {"action": "ALLOW", "risk_level": "LOW", "details": ""}

        async def inspect_response(self, response):
            return {"action": "ALLOW", "risk_level": "LOW", "details": ""}

    class OkGuard(BaseGovernanceGuard):
        name = "ok-guard"

        async def inspect_request(self, request):
            return {"action": "ALLOW", "risk_level": "LOW", "details": ""}

        async def inspect_response(self, response):
            return {"action": "ALLOW", "risk_level": "LOW", "details": ""}

    reg = PluginRegistry()
    reg.register(BrokenGuard)
    reg.register(OkGuard)

    instances = instantiate_plugins(reg, "governance_guard", {"broken-guard": {"x": 1}})
    assert len(instances) == 1
    assert instances[0].name == "ok-guard"

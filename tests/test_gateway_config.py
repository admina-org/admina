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

"""Tests for the OpenAI-gateway settings block."""

from __future__ import annotations

from admina.proxy.config import Settings


def test_gateway_settings_defaults():
    s = Settings()
    assert s.ADMINA_GATEWAY_UPSTREAM == "http://localhost:11434/v1"
    assert "Admina" in s.ADMINA_GATEWAY_BLOCK_MESSAGE
    assert s.ADMINA_GATEWAY_MODELS_ALLOWLIST == ""


def test_gateway_upstream_overridable(monkeypatch):
    monkeypatch.setenv("ADMINA_GATEWAY_UPSTREAM", "http://vllm:8000/v1")
    assert Settings().ADMINA_GATEWAY_UPSTREAM == "http://vllm:8000/v1"

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

"""Admina — pytest configuration."""

from pathlib import Path

import pytest

PII_PLUGIN_DIR = Path(__file__).parent / "fixtures" / "pii_plugin"


@pytest.fixture
def example_pii_plugin(monkeypatch):
    """Put the ``example-pii`` distribution of ``fixtures/pii_plugin`` on
    ``sys.path``: its engines join the ``admina.pii_engines`` entry-point
    group. Returns the name of its main engine."""
    monkeypatch.syspath_prepend(str(PII_PLUGIN_DIR))
    return "example-pii"


@pytest.fixture
def no_network(monkeypatch):
    """Refuse DNS lookups and outgoing connections for one test (see
    ``_network_guard``); returns the list of the attempts."""
    from _network_guard import install

    return install(monkeypatch.setattr)

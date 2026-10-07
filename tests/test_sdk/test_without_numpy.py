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

"""The SDK installed without the scientific stack (``pip install admina``).

numpy and scikit-learn come with the ``proxy`` extra, for the Python loop
breaker. Without them, ``GovernedModel.ask()`` governs a prompt (firewall,
PII) as long as loop detection is off, and asking for loop detection says
which extra it needs. Each case runs in a child interpreter that cannot
import numpy or sklearn.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap

_BLOCK = """
import importlib.abc, sys

class _Blocked(importlib.abc.MetaPathFinder):
    def find_spec(self, name, path=None, target=None):
        if name.split(".")[0] in ("numpy", "sklearn"):
            raise ModuleNotFoundError(f"No module named {name!r}", name=name)
        return None

sys.meta_path.insert(0, _Blocked())
"""

_MODEL = """
import asyncio
from admina.plugins.base import BaseModelAdapter
from admina.sdk import GovernedModel

class Echo(BaseModelAdapter):
    async def send(self, prompt, context=None, **kwargs):
        return {"text": "ok", "metadata": {}}

    def supports_model(self, model_name):
        return True

    @property
    def name(self):
        return "echo"
"""


def _run(code: str) -> subprocess.CompletedProcess:
    script = _BLOCK + _MODEL + textwrap.dedent(code)
    env = {"ADMINA_ENGINE": "python", "PATH": "", "PYTHONPATH": ""}
    return subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, env=env, timeout=120
    )


def test_ask_works_without_numpy():
    proc = _run(
        """
        model = GovernedModel("m", adapter=Echo())
        result = asyncio.run(model.ask("hello"))
        print(result.action, result.text)
        """
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.split() == ["ALLOW", "ok"]


def test_loop_detection_without_numpy_names_the_extra():
    proc = _run(
        """
        model = GovernedModel("m", adapter=Echo(), loop_detection=True)
        try:
            asyncio.run(model.ask("hello", session_id="s1"))
        except ImportError as exc:
            print("ImportError:", exc)
        """
    )
    assert proc.returncode == 0, proc.stderr
    assert "ImportError:" in proc.stdout
    assert "admina[proxy]" in proc.stdout

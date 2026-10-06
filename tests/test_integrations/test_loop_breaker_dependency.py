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

"""The LangChain and CrewAI callbacks without scikit-learn: loop detection
(on by default) raises an ImportError that names the extra to install and
``loop_detection=False``; with loop detection off the callbacks work."""

from __future__ import annotations

import sys

import pytest

from admina.integrations.crewai import callbacks as crewai_callbacks
from admina.integrations.crewai.callbacks import AdminaStepCallback
from admina.integrations.langchain import callbacks as langchain_callbacks
from admina.integrations.langchain.callbacks import AdminaCallbackHandler


@pytest.fixture()
def no_sklearn(monkeypatch: pytest.MonkeyPatch) -> None:
    """The Python loop breaker cannot be imported, as without [proxy]."""
    monkeypatch.setenv("ADMINA_ENGINE", "python")
    # None in sys.modules makes the import raise ImportError; submodules
    # already imported are found by their full name, so they get None too.
    for name in [m for m in sys.modules if m == "sklearn" or m.startswith("sklearn.")]:
        monkeypatch.setitem(sys.modules, name, None)
    monkeypatch.setitem(sys.modules, "sklearn", None)
    monkeypatch.delitem(sys.modules, "admina.domains.agent_security.loop_breaker", raising=False)
    # No shared loop breaker yet, in the module each callback calls (another
    # test may have reloaded admina.integrations._engines).
    for module in (langchain_callbacks, crewai_callbacks):
        monkeypatch.setitem(module.get_loop_breaker.__globals__, "_loop_breaker", None)


def _assert_actionable(exc: pytest.ExceptionInfo[ImportError]) -> None:
    message = str(exc.value)
    assert "admina-framework[proxy]" in message
    assert "loop_detection=False" in message
    assert isinstance(exc.value.__cause__, ImportError)


@pytest.mark.usefixtures("no_sklearn")
class TestLoopDetectionWithoutScikitLearn:
    def test_langchain_handler_names_the_extra(self) -> None:
        handler = AdminaCallbackHandler(firewall=False, pii_redaction=False, audit=False)
        with pytest.raises(ImportError) as exc:
            handler.on_llm_start({"name": "m"}, ["hello"])
        _assert_actionable(exc)

    def test_crewai_step_callback_names_the_extra(self) -> None:
        callback = AdminaStepCallback(firewall=False, pii_redaction=False, audit=False)
        with pytest.raises(ImportError) as exc:
            callback("hello")
        _assert_actionable(exc)

    def test_langchain_handler_without_loop_detection(self) -> None:
        handler = AdminaCallbackHandler(
            firewall=False, pii_redaction=False, loop_detection=False, audit=False
        )
        handler.on_llm_start({"name": "m"}, ["hello"])
        assert handler.last_result.action == "ALLOW"

    def test_crewai_step_callback_without_loop_detection(self) -> None:
        callback = AdminaStepCallback(
            firewall=False, pii_redaction=False, loop_detection=False, audit=False
        )
        callback("hello")
        assert callback.last_result.action == "ALLOW"

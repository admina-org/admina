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

"""Third-party PII engines of the ``admina.pii_engines`` entry-point group.

``get_pii_engine`` resolves a name among the built-in engines first, then
among the entry points of the group (here, those of the ``example-pii``
distribution in ``fixtures/pii_plugin``). An asynchronous
:class:`~admina.plugins.base.BasePIIEngine` is wrapped by
:class:`~admina.engines.PIIEngineBridge`, the synchronous ``PIIBridge`` of
the pipeline, which runs it on an event loop of its own from any thread.
"""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from admina.engines import get_pii_engine
from admina.engines.pii_plugins import PII_ENGINES_GROUP, plugin_engine_names

TEXT = "Scrivi a prova.esempio@example.com per la pratica."


@pytest.fixture(autouse=True)
def _no_engine_settings(monkeypatch, tmp_path):
    for name in ("ADMINA_PII_ENGINE", "ADMINA_PII_MASK_STYLE", "ADMINA_CONFIG"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)  # no admina.yaml of the working directory


def _is_plugin_bridge(engine) -> bool:
    # By class name: other tests reload admina.engines, giving it new classes.
    return type(engine).__name__ == "PIIEngineBridge"


def _write_config(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "admina.yaml"
    path.write_text(text, encoding="utf-8")
    return path


# ── Selection ─────────────────────────────────────────────────


def test_group_name():
    assert PII_ENGINES_GROUP == "admina.pii_engines"


def test_plugin_engine_names(example_pii_plugin):
    assert {"example-pii", "every-word", "factory-pii"} <= set(plugin_engine_names())


def test_engine_is_selected_by_name(example_pii_plugin):
    engine = get_pii_engine(example_pii_plugin)
    assert _is_plugin_bridge(engine)
    out = engine.redact(TEXT)
    assert out["redacted_text"] == "Scrivi a [EMAIL] per la pratica."


def test_engine_is_selected_by_the_environment(example_pii_plugin, monkeypatch):
    monkeypatch.setenv("ADMINA_PII_ENGINE", "example-pii")
    engine = get_pii_engine()
    assert _is_plugin_bridge(engine)
    assert engine.name == "example-pii"


def test_engine_is_selected_by_admina_yaml(example_pii_plugin, monkeypatch, tmp_path):
    monkeypatch.setenv("ADMINA_CONFIG", str(_write_config(tmp_path, "pii_engine: example-pii\n")))
    engine = get_pii_engine()
    assert _is_plugin_bridge(engine)
    assert engine.name == "example-pii"


def test_built_in_engines_come_first(example_pii_plugin):
    # The fixture distribution also registers an engine named spacy-regex.
    assert not _is_plugin_bridge(get_pii_engine("spacy-regex"))


def test_unknown_name_lists_every_engine(example_pii_plugin):
    with pytest.raises(ValueError, match="pii_engine") as excinfo:
        get_pii_engine("no-such-engine")
    message = str(excinfo.value)
    for name in ("spacy-regex", "presidio", "example-pii", "every-word"):
        assert name in message


def test_unknown_name_without_plugins_lists_the_built_in_engines():
    with pytest.raises(ValueError, match=r"Available: \['presidio', 'spacy-regex'\]"):
        get_pii_engine("example-pii")


def test_factory_entry_point(example_pii_plugin):
    engine = get_pii_engine("factory-pii")
    assert engine.redact(TEXT)["count"] == 1


def test_plugin_config_reaches_the_engine(example_pii_plugin, monkeypatch, tmp_path):
    config = "pii_engine: configured-pii\nplugin_config:\n  configured-pii:\n    threshold: 0.7\n"
    monkeypatch.setenv("ADMINA_CONFIG", str(_write_config(tmp_path, config)))
    engine = get_pii_engine()
    assert engine.engine.config == {"threshold": 0.7}


def test_entry_point_that_is_not_an_engine(example_pii_plugin):
    with pytest.raises(TypeError, match="not-an-engine"):
        get_pii_engine("not-an-engine")


def test_entry_point_that_cannot_be_imported(example_pii_plugin):
    with pytest.raises(ImportError, match="missing-pii"):
        get_pii_engine("missing-pii")


# ── The adapter ───────────────────────────────────────────────


def test_result_shape(example_pii_plugin):
    out = get_pii_engine("example-pii").redact(TEXT)
    assert set(out) == {"redacted_text", "entities", "categories", "count"}
    assert out["count"] == 1
    assert out["categories"] == ["EMAIL"]
    (entity,) = out["entities"]
    assert entity == {
        "type": "EMAIL",
        "start": 9,
        "end": 34,
        "original_length": 25,
        "method": "example-pii",
    }


def test_empty_text(example_pii_plugin):
    out = get_pii_engine("example-pii").redact("")
    assert out == {"redacted_text": "", "entities": [], "categories": [], "count": 0}


def test_stats(example_pii_plugin):
    engine = get_pii_engine("example-pii")
    engine.redact(TEXT)
    engine.redact(TEXT + " " + TEXT)
    stats = engine.get_stats()
    assert stats["engine"] == "example-pii"
    assert stats["total_redacted"] == 3
    assert stats["redactions_by_type"] == {"EMAIL": 3}
    assert stats["languages"] == ["it"]


def test_special_categories_of_the_engine(example_pii_plugin):
    from admina.domains.data_sovereignty.classification import DataClassifier

    engine = get_pii_engine("example-pii")
    assert engine.special_categories == frozenset({"HEALTH"})
    classifier = DataClassifier(special_categories=engine.special_categories)
    assert classifier.classify(pii_categories=["HEALTH"])["level"] == "restricted"


def test_redact_inside_a_running_event_loop(example_pii_plugin):
    engine = get_pii_engine("example-pii")

    async def call() -> dict:
        return engine.redact(TEXT)

    assert asyncio.run(call())["count"] == 1


def test_redact_from_many_threads(example_pii_plugin):
    engine = get_pii_engine("example-pii")
    texts = [f"mail {i}@example.com" for i in range(40)]
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(engine.redact, texts))
    assert all(r["redacted_text"] == "mail [EMAIL]" for r in results)


def test_redact_in_the_pipeline_worker_threads(example_pii_plugin):
    from admina.domains.governance import redact_chat_params, run_pipeline
    from admina.proxy.pipeline_executor import PipelineExecutor

    engine = get_pii_engine("example-pii")
    messages = [{"role": "user", "content": TEXT}]

    class Loop:
        def check(self, session_id, content):
            return {"is_loop": False, "similarity": 0.0}

    def pipeline():
        return run_pipeline(
            body={"params": {"messages": messages}},
            content_str=TEXT,
            session_id="s",
            agent_id="a",
            request_id="r",
            params={"messages": messages},
            firewall=None,
            pii_redactor=engine,
            loop_breaker=Loop(),
            governance_guards=[],
            injection_enabled=False,
            loop_enabled=False,
            redact_params=redact_chat_params,
        )

    executor = PipelineExecutor(2)
    try:
        result = asyncio.run(executor.run_coroutine(pipeline, timeout=10))
    finally:
        executor.shutdown()
    assert result.redacted_body["params"]["messages"] == [
        {"role": "user", "content": "Scrivi a [EMAIL] per la pratica."}
    ]


def test_placeholders_are_not_masked_again(example_pii_plugin):
    out = get_pii_engine("every-word").redact("Bonifico su [IBAN] e [OMISSIS] oggi")
    assert out["redacted_text"] == "[PERSON] [PERSON] [IBAN] [PERSON] [OMISSIS] [PERSON]"
    assert out["count"] == 4


def test_a_span_outside_the_text_is_an_error(example_pii_plugin):
    with pytest.raises(ValueError, match="bad-span-pii"):
        get_pii_engine("bad-span-pii").redact(TEXT)


# ── The proxy ─────────────────────────────────────────────────


def test_proxy_starts_with_a_plugin_engine(example_pii_plugin, monkeypatch):
    from _gateway_stream import run_lifespan

    monkeypatch.setenv("ADMINA_PII_ENGINE", "example-pii")
    state = run_lifespan(monkeypatch, None)
    assert _is_plugin_bridge(state.pii_redactor)
    assert state.pii_redactor.name == "example-pii"


def test_proxy_does_not_start_with_an_unknown_engine(example_pii_plugin, monkeypatch):
    from _gateway_stream import run_lifespan

    monkeypatch.setenv("ADMINA_PII_ENGINE", "no-such-engine")
    with pytest.raises(ValueError, match="example-pii"):
        run_lifespan(monkeypatch, None)

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

"""GET /metrics must render one valid Prometheus exposition document.

Before this file, nothing in the suite touched `/metrics` at all
(`grep -rln "prometheus_metrics\\|/metrics" tests/` returned nothing). The
coordination-verdict loop and the firewall-detections loop each call the
shared `_metric()` helper once per label set for the *same* metric family,
and `_metric()` used to append a fresh `# HELP`/`# TYPE` pair on every
call. The Prometheus text exposition format allows exactly one `HELP` and
one `TYPE` line per family; a second one is a parse error that fails the
*whole* scrape (the target goes `up=0`), not just the offending family —
so a coordination detector reporting more than one status, or a firewall
that has blocked more than one category, silently took every other Admina
metric off the board.
"""

from __future__ import annotations

import asyncio
from collections import Counter

import httpx
import pytest

pytest.importorskip("fastapi")


class _FakeFirewallWithTwoCategories:
    """Reports hits in two categories, so the firewall loop emits two samples
    of `admina_firewall_detections_total` — the shape needed to exercise its
    latent duplicate-metadata bug (it has never fired in practice because it
    needs two or more detection categories, and an idle proxy has none)."""

    def get_stats(self) -> dict:
        return {
            "detections_by_type": {"prompt_injection": 3, "jailbreak": 1},
            "total_checked": 10,
            "total_blocked": 4,
        }


def _get_metrics_body(monkeypatch) -> str:
    from admina.proxy import main as proxy_main
    from admina.proxy.multi_upstream import MultiUpstreamRouter
    from admina.proxy.state import ProxyState

    state = ProxyState(
        firewall=_FakeFirewallWithTwoCategories(),
        pii_redactor=None,
        loop_breaker=None,
        egress_policy=None,
        coordination=None,
        router=MultiUpstreamRouter(default_upstream="http://fake-upstream"),
        redis=None,
        clickhouse=None,
        forensic_box=None,
        governance_guards=[],
        alert_channels=[],
        auth_providers=[],
    )
    monkeypatch.setattr(proxy_main.app.state, "proxy", state, raising=False)

    async def go() -> httpx.Response:
        transport = httpx.ASGITransport(app=proxy_main.app, raise_app_exceptions=True)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            return await client.get("/metrics")

    resp = asyncio.run(go())
    assert resp.status_code == 200
    return resp.text


class TestMetricsFixtureActuallyExercisesBothLoops:
    """A sanity check on the fixture, not the endpoint.

    `COORDINATION_COUNTERS` has three entries and the coordination loop
    iterates all of them unconditionally (`m.get(_counter, 0)` defaults a
    quiet deployment to zero, it does not skip the sample), so it always
    renders three samples. The firewall loop only renders one sample per
    category *present in the stats*, so the fixture above must supply two
    or the HELP/TYPE assertions below would pass without ever exercising
    the loop the review found broken.
    """

    def test_both_families_render_more_than_one_sample(self, monkeypatch):
        body = _get_metrics_body(monkeypatch)
        coordination_samples = [
            line
            for line in body.splitlines()
            if line.startswith("admina_coordination_verdicts_total{")
        ]
        firewall_samples = [
            line
            for line in body.splitlines()
            if line.startswith("admina_firewall_detections_total{")
        ]
        assert len(coordination_samples) >= 2, body
        assert len(firewall_samples) >= 2, body


class TestMetricsExpositionIsValidPrometheusFormat:
    def test_no_family_has_more_than_one_help_line(self, monkeypatch):
        body = _get_metrics_body(monkeypatch)
        help_names = [
            line.split(" ", 3)[2] for line in body.splitlines() if line.startswith("# HELP ")
        ]
        dupes = {name for name, count in Counter(help_names).items() if count > 1}
        assert dupes == set(), (
            f"duplicate HELP line(s) for {dupes} — invalid Prometheus exposition:\n{body}"
        )

    def test_no_family_has_more_than_one_type_line(self, monkeypatch):
        body = _get_metrics_body(monkeypatch)
        type_names = [
            line.split(" ", 3)[2] for line in body.splitlines() if line.startswith("# TYPE ")
        ]
        dupes = {name for name, count in Counter(type_names).items() if count > 1}
        assert dupes == set(), (
            f"duplicate TYPE line(s) for {dupes} — invalid Prometheus exposition:\n{body}"
        )

    def test_the_coordination_and_firewall_families_are_present(self, monkeypatch):
        """The two assertions above would pass vacuously on a document
        missing these families entirely; pin that they are actually there."""
        body = _get_metrics_body(monkeypatch)
        help_names = {
            line.split(" ", 3)[2] for line in body.splitlines() if line.startswith("# HELP ")
        }
        assert "admina_coordination_verdicts_total" in help_names
        assert "admina_firewall_detections_total" in help_names

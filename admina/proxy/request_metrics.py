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

"""Governed requests per surface, served on ``/metrics``.

- ``admina_requests_total{surface,action}``: counter of the governed
  requests of each surface (``gateway``, ``mcp``, ``integration``) by
  action: ``ALLOW``, ``BLOCK``, ``REDACT`` (allowed, with PII masked in the
  request), ``CIRCUIT_BREAK`` or ``ERROR`` (the request failed in the proxy
  before its governance decision).
- ``admina_request_duration_seconds{surface}``: histogram of the time from
  the arrival of a governed request to the end of its response, the
  upstream's time included.
- ``admina_governance_duration_seconds{surface}``: histogram of the time the
  governance pipeline took to decide.

Every action of each surface given to :class:`RequestMetrics` has a sample
from the start, 0 until a request is counted. Label values come from these
fixed sets only, never from a request.
"""

from __future__ import annotations

import bisect
import threading
from collections.abc import Iterable

__all__ = [
    "ACTIONS",
    "GOVERNANCE_BUCKETS",
    "GOVERNED_SURFACES",
    "REQUEST_BUCKETS",
    "RequestMetrics",
]

#: The surfaces whose requests are governed, in the order they are reported.
GOVERNED_SURFACES = ("gateway", "mcp", "integration")
#: The values of the ``action`` label.
ACTIONS = ("ALLOW", "BLOCK", "REDACT", "CIRCUIT_BREAK", "ERROR")
#: Upper bounds of the buckets of the request duration, in seconds.
REQUEST_BUCKETS = (
    0.005,
    0.01,
    0.025,
    0.05,
    0.1,
    0.25,
    0.5,
    1.0,
    2.5,
    5.0,
    10.0,
    30.0,
    60.0,
    120.0,
    300.0,
)
#: Upper bounds of the buckets of the governance duration, in seconds.
GOVERNANCE_BUCKETS = (
    0.0005,
    0.001,
    0.0025,
    0.005,
    0.01,
    0.025,
    0.05,
    0.1,
    0.25,
    0.5,
    1.0,
    2.5,
    5.0,
)

_REQUESTS = "admina_requests_total"
_REQUEST_DURATION = "admina_request_duration_seconds"
_GOVERNANCE_DURATION = "admina_governance_duration_seconds"


class _Histogram:
    """One labelled series of a Prometheus histogram."""

    def __init__(self, buckets: tuple[float, ...]) -> None:
        self.buckets = buckets
        self.count = 0
        self.sum = 0.0
        # Observations per bucket, not cumulative; the last slot is above every bound.
        self._counts = [0] * (len(buckets) + 1)

    def observe(self, value: float) -> None:
        value = max(value, 0.0)
        self.count += 1
        self.sum += value
        self._counts[bisect.bisect_left(self.buckets, value)] += 1

    def lines(self, name: str, labels: str) -> list[str]:
        lines = []
        cumulative = 0
        for bound, count in zip(self.buckets, self._counts, strict=False):
            cumulative += count
            lines.append(f'{name}_bucket{{{labels},le="{bound:g}"}} {cumulative}')
        lines.append(f'{name}_bucket{{{labels},le="+Inf"}} {self.count}')
        lines.append(f"{name}_sum{{{labels}}} {round(self.sum, 9)!r}")
        lines.append(f"{name}_count{{{labels}}} {self.count}")
        return lines


class RequestMetrics:
    """The counter and the histograms of the governed requests.

    Args:
        surfaces: The enabled surfaces: those of :data:`GOVERNED_SURFACES`
            have samples from the start (the others are ignored). A
            governed surface left out gets its samples with its first
            request.
    """

    def __init__(self, surfaces: Iterable[str] = GOVERNED_SURFACES) -> None:
        self._lock = threading.Lock()
        self._requests: dict[tuple[str, str], int] = {}
        self._request_duration: dict[str, _Histogram] = {}
        self._governance_duration: dict[str, _Histogram] = {}
        with self._lock:
            for surface in surfaces:
                if surface in GOVERNED_SURFACES:
                    self._series(surface)

    def count(self, surface: str, action: str) -> None:
        """Count one request of *surface* with *action*."""
        if action not in ACTIONS:
            raise ValueError(f"unknown action {action!r}; the actions are: {', '.join(ACTIONS)}")
        surface = _surface(surface)
        with self._lock:
            self._series(surface)
            self._requests[(surface, action)] += 1

    def observe_request(self, surface: str, seconds: float) -> None:
        """Record the duration of one request of *surface*."""
        surface = _surface(surface)
        with self._lock:
            self._series(surface)
            self._request_duration[surface].observe(seconds)

    def observe_governance(self, surface: str, seconds: float) -> None:
        """Record the governance time of one request of *surface*."""
        surface = _surface(surface)
        with self._lock:
            self._series(surface)
            self._governance_duration[surface].observe(seconds)

    def exposition(self) -> list[str]:
        """The three families in the Prometheus text format."""
        with self._lock:
            surfaces = [s for s in GOVERNED_SURFACES if s in self._request_duration]
            lines = [
                f"# HELP {_REQUESTS} Governed requests per surface and action",
                f"# TYPE {_REQUESTS} counter",
            ]
            for surface in surfaces:
                for action in ACTIONS:
                    value = self._requests[(surface, action)]
                    lines.append(f'{_REQUESTS}{{surface="{surface}",action="{action}"}} {value}')
            for name, help_text, histograms in (
                (
                    _REQUEST_DURATION,
                    "Time from the arrival of a governed request to the end of its "
                    "response, upstream included",
                    self._request_duration,
                ),
                (
                    _GOVERNANCE_DURATION,
                    "Time the governance pipeline took to decide on a request",
                    self._governance_duration,
                ),
            ):
                lines.append(f"# HELP {name} {help_text}")
                lines.append(f"# TYPE {name} histogram")
                for surface in surfaces:
                    lines.extend(histograms[surface].lines(name, f'surface="{surface}"'))
            return lines

    def _series(self, surface: str) -> None:
        """Create the samples of *surface* (under the lock)."""
        if surface in self._request_duration:
            return
        for action in ACTIONS:
            self._requests[(surface, action)] = 0
        self._request_duration[surface] = _Histogram(REQUEST_BUCKETS)
        self._governance_duration[surface] = _Histogram(GOVERNANCE_BUCKETS)


def _surface(surface: str) -> str:
    if surface not in GOVERNED_SURFACES:
        raise ValueError(
            f"unknown surface {surface!r}; the governed surfaces are: "
            f"{', '.join(GOVERNED_SURFACES)}"
        )
    return surface

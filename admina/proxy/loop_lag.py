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

"""Event loop lag of the proxy: ``admina_event_loop_lag_seconds``.

A background task sleeps :data:`DEFAULT_INTERVAL` seconds at a time and
records by how much each wake-up comes late: the time the event loop spent
on other work (a request handler, a scan) before it could run the task. The
samples form a Prometheus histogram (``_bucket{le=...}``, ``_sum``,
``_count``) served on ``/metrics``; while nothing holds up the loop they
stay within a millisecond or so.
"""

from __future__ import annotations

import asyncio
import bisect
from contextlib import suppress

__all__ = ["DEFAULT_INTERVAL", "LAG_BUCKETS", "EventLoopLagMonitor"]

#: Seconds between two samples.
DEFAULT_INTERVAL = 0.1
#: Upper bounds of the histogram buckets, in seconds.
LAG_BUCKETS = (0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0)


class EventLoopLagMonitor:
    """Samples the lag of the running event loop into a histogram."""

    name = "admina_event_loop_lag_seconds"

    def __init__(
        self, interval: float = DEFAULT_INTERVAL, buckets: tuple[float, ...] = LAG_BUCKETS
    ) -> None:
        self.interval = interval
        self.buckets = tuple(sorted(buckets))
        self.count = 0
        self.sum = 0.0
        # Samples per bucket, not cumulative; the last slot is above every bound.
        self._counts = [0] * (len(self.buckets) + 1)
        self._task: asyncio.Task | None = None

    @property
    def started(self) -> bool:
        return self._task is not None

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    def observe(self, lag: float) -> None:
        """Record one sample, in seconds (negative values count as 0)."""
        lag = max(lag, 0.0)
        self.count += 1
        self.sum += lag
        self._counts[bisect.bisect_left(self.buckets, lag)] += 1

    def start(self) -> None:
        """Start sampling on the running event loop."""
        self._task = asyncio.get_running_loop().create_task(
            self._sample(), name="admina-event-loop-lag"
        )

    async def stop(self) -> None:
        """Stop sampling."""
        if self._task is not None:
            self._task.cancel()
            with suppress(asyncio.CancelledError):
                await self._task

    async def _sample(self) -> None:
        loop = asyncio.get_running_loop()
        while True:
            started = loop.time()
            await asyncio.sleep(self.interval)
            self.observe(loop.time() - started - self.interval)

    def exposition(self) -> list[str]:
        """The histogram in the Prometheus text format."""
        lines = [
            f"# HELP {self.name} Delay of the event loop in running a task due to "
            f"wake up, sampled every {self.interval:g} s",
            f"# TYPE {self.name} histogram",
        ]
        cumulative = 0
        for bound, count in zip(self.buckets, self._counts, strict=False):
            cumulative += count
            lines.append(f'{self.name}_bucket{{le="{bound:g}"}} {cumulative}')
        lines.append(f'{self.name}_bucket{{le="+Inf"}} {self.count}')
        lines.append(f"{self.name}_sum {round(self.sum, 9)!r}")
        lines.append(f"{self.name}_count {self.count}")
        return lines

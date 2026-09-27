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

"""Bounded pool of worker threads for the governance pipeline.

The gateway runs the pipeline (firewall, PII redaction, egress analysis,
governance guards) here, so that scanning a long prompt does not hold up
the event loop that serves every other request and stream.

- At most ``workers`` jobs run at once; further jobs wait for a free thread.
  The threads, each with its event loop, start with the executor, not on
  the first jobs.
- ``timeout`` bounds how long the caller waits for a job, the wait for a
  free thread included: past it the caller gets :class:`PipelineTimeout`
  and a job that has not started is dropped. A job already running cannot
  be stopped; its thread is busy until the job returns.
- :meth:`PipelineExecutor.run_coroutine` runs a coroutine on an event loop
  of the worker thread's own (one per thread, reused), so the async stages
  of the pipeline, such as governance guards, run in the worker too.
"""

from __future__ import annotations

import asyncio
import os
import threading
from collections.abc import Awaitable, Callable
from concurrent.futures import ThreadPoolExecutor
from typing import TypeVar

__all__ = ["PipelineExecutor", "PipelineTimeout", "default_workers"]

T = TypeVar("T")


class PipelineTimeout(Exception):
    """A job did not complete within its time budget."""

    def __init__(self, timeout: float) -> None:
        super().__init__(f"no result within {timeout} s")
        self.timeout = timeout


def default_workers() -> int:
    """Number of CPUs this process may run on."""
    try:
        return max(1, len(os.sched_getaffinity(0)))
    except AttributeError:  # not available on every platform
        return max(1, os.cpu_count() or 1)


class PipelineExecutor:
    """A pool of *workers* threads (``0`` = :func:`default_workers`)."""

    def __init__(self, workers: int = 0) -> None:
        self.workers = workers if workers > 0 else default_workers()
        self._pool = ThreadPoolExecutor(
            max_workers=self.workers, thread_name_prefix="admina-pipeline"
        )
        self._local = threading.local()
        self._loops: list[asyncio.AbstractEventLoop] = []
        self._loops_lock = threading.Lock()
        self._start_threads()

    def _start_threads(self) -> None:
        """Start every thread now: the pool starts one per job otherwise,
        on the path of the first requests."""
        # Each job waits for the others, so each one needs a thread of its own.
        all_started = threading.Barrier(self.workers)

        def start() -> None:
            self._thread_loop()
            all_started.wait(timeout=10)

        for future in [self._pool.submit(start) for _ in range(self.workers)]:
            future.exception()  # wait; a broken barrier only leaves threads to start later

    async def run(self, fn: Callable[[], T], *, timeout: float = 0.0) -> T:
        """The result of ``fn()``, called in a worker thread.

        Args:
            fn: The job.
            timeout: Seconds to wait for the result; ``0`` = no limit.

        Raises:
            PipelineTimeout: No result within *timeout*.
            RuntimeError: The executor has been shut down.
            Exception: Whatever ``fn()`` raised.
        """
        loop = asyncio.get_running_loop()
        future = loop.run_in_executor(self._pool, fn)
        if not timeout:
            return await future
        expired = False

        def expire() -> None:
            nonlocal expired
            expired = future.cancel()  # a queued job is dropped too

        timer = loop.call_later(timeout, expire)
        try:
            return await future
        except asyncio.CancelledError:
            if expired:
                raise PipelineTimeout(timeout) from None
            raise
        finally:
            timer.cancel()

    async def run_coroutine(
        self, factory: Callable[[], Awaitable[T]], *, timeout: float = 0.0
    ) -> T:
        """The result of the coroutine ``factory()``, created and run in a
        worker thread on that thread's event loop (see :meth:`run`)."""

        def job() -> T:
            return self._thread_loop().run_until_complete(factory())

        return await self.run(job, timeout=timeout)

    def shutdown(self) -> None:
        """Stop accepting jobs, drop the queued ones and close the idle
        threads' event loops. Running jobs are not waited for."""
        self._pool.shutdown(wait=False, cancel_futures=True)
        with self._loops_lock:
            loops, self._loops = self._loops, []
        for loop in loops:
            if not loop.is_running():
                loop.close()

    def _thread_loop(self) -> asyncio.AbstractEventLoop:
        loop = getattr(self._local, "loop", None)
        if loop is None or loop.is_closed():
            loop = asyncio.new_event_loop()
            self._local.loop = loop
            with self._loops_lock:
                self._loops.append(loop)
        return loop

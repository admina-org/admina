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

"""Shared sync→async streaming bridge for the built-in adapters.

The provider SDKs (openai, ollama, anthropic) expose *blocking* streaming
iterators. ``aiter_sync`` builds the iterator and pulls each item off the
event loop via ``asyncio.to_thread`` so a slow network read never blocks
other coroutines.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Callable, Iterator
from typing import Any

__all__ = ["aiter_sync"]

_SENTINEL = object()


async def aiter_sync(make_iter: Callable[[], Iterator[Any]]) -> AsyncIterator[Any]:
    """Bridge a blocking iterator factory to an async iterator.

    Args:
        make_iter: No-arg callable that (blockingly) creates and returns the
            provider's streaming iterator.

    Yields:
        Items from the iterator, each fetched in a worker thread.
    """
    iterator = await asyncio.to_thread(make_iter)
    while True:
        item = await asyncio.to_thread(next, iterator, _SENTINEL)
        if item is _SENTINEL:
            return
        yield item

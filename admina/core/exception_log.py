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

"""Where an exception was raised, without its message.

The message of an exception raised while a request or a response is
governed (by a governance guard, a PII engine, or any code that reads their
text) can quote that text. Where the proxy and the governance pipeline
handle such an exception they log and record its class name, and
:func:`log_frames` logs at ``DEBUG`` where it was raised: the file, line,
function and source line of each frame of its traceback, without its
message and without the exceptions chained to it.
"""

from __future__ import annotations

import logging
import traceback

__all__ = ["exception_frames", "log_frames"]


def exception_frames(exc: BaseException) -> str:
    """The frames of the traceback of *exc* (``traceback.format_tb``):
    neither its message nor the exceptions chained to it."""
    return "".join(traceback.format_tb(exc.__traceback__))


def log_frames(logger: logging.Logger, what: str, exc: BaseException) -> None:
    """Log at ``DEBUG`` on *logger* that *exc* was raised during *what*,
    with its class name and :func:`exception_frames`."""
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug("%s: %s raised at\n%s", what, type(exc).__name__, exception_frames(exc))

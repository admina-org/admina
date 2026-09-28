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

"""``admina.core.exception_log``: where an exception was raised, without
its message or the messages of the exceptions chained to it."""

from __future__ import annotations

import logging

from admina.core.exception_log import exception_frames, log_frames

MARKER = "zqmarkerfortheexceptionmessage"
LOGGER = "admina.test.exception_log"


def _read(text: str) -> None:
    raise ValueError(f"cannot read {text}")


def _wrap(text: str) -> None:
    try:
        _read(text)
    except ValueError as exc:
        raise RuntimeError(f"wrapped {text}") from exc


def _raised(func, text: str) -> BaseException:
    try:
        func(text)
    except Exception as exc:  # noqa: BLE001 — the exception under test
        return exc
    raise AssertionError("nothing raised")


def test_the_frames_name_where_the_exception_was_raised_without_its_message():
    frames = exception_frames(_raised(_read, MARKER))
    assert "_raised" in frames and "_read" in frames
    assert MARKER not in frames


def test_the_frames_leave_out_chained_exceptions():
    exc = _raised(_wrap, MARKER)
    assert exc.__cause__ is not None
    frames = exception_frames(exc)
    assert "_wrap" in frames
    assert MARKER not in frames


def test_log_frames_writes_one_debug_line_without_the_message(caplog):
    logger = logging.getLogger(LOGGER)
    exc = _raised(_wrap, MARKER)
    caplog.set_level(logging.INFO, logger=LOGGER)
    log_frames(logger, "Reading the input", exc)
    assert caplog.records == []
    caplog.set_level(logging.DEBUG, logger=LOGGER)
    log_frames(logger, "Reading the input", exc)
    (record,) = caplog.records
    assert record.levelno == logging.DEBUG
    assert record.exc_info is None
    message = record.getMessage()
    assert message.startswith("Reading the input: RuntimeError raised at")
    assert "_wrap" in message
    assert MARKER not in caplog.text

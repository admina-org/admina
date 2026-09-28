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

"""Admina — windowed streaming PII redactor.

Pure text-in/text-out component (no I/O) shared by the SDK streaming path
(:meth:`GovernedModel.stream`) and the OpenAI-compatible gateway. Chunks
accumulate in a recomposition window and are redacted through any
:class:`~admina.engines.PIIBridge`, so an entity split across a delta
boundary (e.g. ``john.doe@`` + ``example.com``) is still caught. Emission
lags by roughly one window on the trailing edge; the caller must size
``window_chars`` above the longest expected entity (see module tests).

With a redactor that masks whole sentences (``masks_sentences``, such as a
:class:`~admina.engines.PIIEngineBridge` in the ``omissis`` mask style with
sentence categories), text is released only up to the start of the sentence
that the window reaches, so no part of a sentence is sent before a term that
masks it arrives; past ``max_hold_chars`` of held text, the window alone
decides again.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from admina.engines import PIIBridge

__all__ = ["StreamRedactor"]


class StreamRedactor:
    """Recompose streamed deltas, redact PII, emit safe-to-send text.

    Args:
        pii_redactor: Any object satisfying the :class:`PIIBridge` protocol
            (only ``redact(text)`` is used).
        window_chars: Number of trailing raw characters held back so an
            entity forming across a delta boundary is not emitted early.
            Must exceed the longest expected entity.
        max_hold_chars: With a redactor that masks whole sentences, the most
            raw characters held back while a sentence is not complete
            (at least ``window_chars``).
    """

    def __init__(
        self, pii_redactor: PIIBridge, window_chars: int = 64, max_hold_chars: int = 4096
    ) -> None:
        if window_chars < 1:
            raise ValueError("window_chars must be >= 1")
        if max_hold_chars < window_chars:
            raise ValueError("max_hold_chars must be >= window_chars")
        self._redactor = pii_redactor
        self._window = window_chars
        self._max_hold = max_hold_chars
        self._sentences = bool(getattr(pii_redactor, "masks_sentences", False))
        self._buf = ""
        self._pii_count = 0

    def feed(self, delta: str) -> list[str]:
        """Accept a raw delta; return 0+ redacted, safe-to-emit deltas."""
        if not delta:
            return []
        self._buf += delta
        if len(self._buf) <= self._window:
            return []
        cut = len(self._buf) - self._window
        if self._sentences and len(self._buf) <= self._max_hold:
            # Release whole sentences only: the one the window reaches may
            # still get a term that masks all of it.
            cut = self._redactor.sentence_start(self._buf, cut)
            if cut <= 0:
                return []
        red = self._redactor.redact(self._buf)
        red_text = red["redacted_text"]
        tail_raw = self._buf[cut:]
        tail_red = self._redactor.redact(tail_raw)
        if not red_text.endswith(tail_red["redacted_text"]):
            # A PII entity straddles the emit boundary — hold everything and
            # wait for more text so the entity is redacted before emission.
            return []
        head = red_text[: len(red_text) - len(tail_red["redacted_text"])]
        # Clean split ⇒ entity counts partition exactly across head/tail.
        self._pii_count += red["count"] - tail_red["count"]
        self._buf = tail_raw
        return [head] if head else []

    def finish(self) -> tuple[str, dict]:
        """Flush the held window; return (final redacted tail, summary)."""
        red = self._redactor.redact(self._buf)
        self._pii_count += red["count"]
        self._buf = ""
        return red["redacted_text"], {"pii_count": self._pii_count}

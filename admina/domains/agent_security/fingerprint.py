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

"""
Admina — Content fingerprints — Agent Security domain

Sketches used to tell whether text one agent sent somewhere later turns up in
another agent's input. Comparison has to survive reformatting, so this is
shingled MinHash rather than a digest of the whole string.

Nothing here stores or can reconstruct the text. A sketch is a bounded set of
64-bit HMAC values over word shingles: the key makes them incomparable across
deployments and defeats a dictionary attack on common phrases.

Limitations: len(sketch(...)) reveals approximate word count for texts under
~516 words (not plaintext, but not zero-knowledge). The word regex is ASCII-only;
text in non-Latin scripts tokenizes to nothing and yields an empty sketch, so
such content is invisible to the detector. Truncation to SKETCH_SIZE degrades
the comparison for texts longer than ~516 words; callers must bound their input.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
from collections.abc import Sequence

__all__ = [
    "SHINGLE_WORDS",
    "SKETCH_SIZE",
    "MIN_SHARED_SHINGLES",
    "load_fingerprint_key",
    "overlap",
    "sketch",
    "matches",
]

# Words per shingle. Shorter shingles match unrelated prose; longer ones stop
# surviving the light reformatting an agent applies when quoting text.
SHINGLE_WORDS = 5

# Minima kept per sketch. For a 2000-character tail (~263 shingles), truncation
# does not degrade comparison. Larger texts would lose accuracy; callers must
# bound their input. Also bounds memory in Redis and comparison cost.
SKETCH_SIZE = 512

# Shared shingles required to match. Szymkiewicz–Simpson overlap alone allows
# false positives on boilerplate phrases; intersection size discriminates.
MIN_SHARED_SHINGLES = 12

_WORD_RX = re.compile(r"[A-Za-z0-9_]+")

# Below this the key is short enough to enumerate, which is the one thing the
# key exists to prevent. Reported, not enforced: refusing it would disable the
# echo phase on a deployment that believes it is configured.
_MIN_KEY_BYTES = 16

logger = logging.getLogger("admina.coordination")


def load_fingerprint_key() -> bytes | None:
    """Read the deployment fingerprint key, or None when it is not configured.

    Follows the ADMINA_FORENSIC_STATE_KEY precedent. When this returns None the
    caller must disable echo confirmation rather than fall back to unkeyed
    hashes, which would be dictionary-attackable and comparable across
    deployments.
    """
    raw = os.environ.get("ADMINA_EGRESS_FINGERPRINT_KEY", "").strip()
    if not raw:
        return None
    if len(raw.encode()) < _MIN_KEY_BYTES:
        logger.warning(
            "ADMINA_EGRESS_FINGERPRINT_KEY is %d bytes; a key shorter than %d does not "
            "defeat a dictionary attack on the shingles it protects",
            len(raw.encode()),
            _MIN_KEY_BYTES,
        )
    return raw.encode()


def sketch(text: str, key: bytes) -> frozenset[int]:
    """Return a bounded set of keyed hashes over the text's word shingles."""
    words = _WORD_RX.findall(text.lower())
    if len(words) < SHINGLE_WORDS:
        return frozenset()
    values = sorted(
        int.from_bytes(
            hmac.new(
                key,
                " ".join(words[i : i + SHINGLE_WORDS]).encode(),
                hashlib.sha256,
            ).digest()[:8],
            "big",
        )
        for i in range(len(words) - SHINGLE_WORDS + 1)
    )
    return frozenset(values[:SKETCH_SIZE])


def overlap(a: frozenset[int], b: frozenset[int]) -> float:
    """Szymkiewicz–Simpson overlap coefficient of two sketches.

    Measures containment: the fraction of the smaller sketch that appears in
    the larger. Empty sketches never match. Used with MIN_SHARED_SHINGLES to
    avoid false positives on boilerplate.
    """
    if not a or not b:
        return 0.0
    return len(a & b) / min(len(a), len(b))


def matches(
    a_fields: Sequence[frozenset[int]],
    b_fields: Sequence[frozenset[int]],
    threshold: float = 0.4,
) -> bool:
    """Whether two payloads indicate containment, not just similarity.

    Each argument is the sketches of one payload's *fields*, one entry per
    field, because a tool call carries several strings and they are not one
    text. Returns True only if both:

    - a single pair of fields, one from each side, shares at least
      MIN_SHARED_SHINGLES hashes — one coherent run of shared text, never a
      union of separate fields, because short constants concatenated reach
      the floor without any one of them being a message;
    - the two payloads overlap by at least *threshold*: how much of the
      smaller of the two the shared text accounts for, measured over
      everything each call carried.

    Both conditions are necessary, and each answers a different way of
    faking an echo. Containment alone fires on boilerplate phrases, which
    the per-field floor discriminates. The floor alone lets one short
    constant field that every agent in a fleet sends — a header, a template,
    a signature — match at 1.0, which containment over the whole payload
    dilutes in proportion to how much real message surrounds it.
    """
    union_a = frozenset().union(*a_fields) if a_fields else frozenset()
    union_b = frozenset().union(*b_fields) if b_fields else frozenset()
    if overlap(union_a, union_b) < threshold:
        return False
    return any(len(a & b) >= MIN_SHARED_SHINGLES for a in a_fields for b in b_fields)

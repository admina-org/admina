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
    "NEAR_DUPLICATE",
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

# Containment at which two payloads stop being "similar" and become copies of
# each other. A tool call that carries its message in several short arguments —
# an issue title and body, an email subject and body — can hold a quoted run
# that no single argument is long enough to carry on its own, so the run clears
# the floor only when the arguments are counted together. Counting them
# together is safe at this ratio and not at 0.4: at 0.9 practically all of the
# smaller payload is the shared text, which is what one agent reposting
# another's call looks like, while a template two calls share beside their own
# content is a fraction of each.
#
# This bounds the *smaller* payload only, because that is the side containment
# is measured over, and a call that is nothing but a shared template is the
# degenerate small side: it scores 1.0 against any call carrying that template,
# however much of its own message that call also carries. The larger side is
# bounded separately, by the caller's own threshold (see matches()).
NEAR_DUPLICATE = 0.9

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
    threshold: float,
) -> bool:
    """Whether two payloads indicate containment, not just similarity.

    Each argument is the sketches of one payload's *fields*, one entry per
    field, because a tool call carries several strings and they are not one
    text. The fields are never concatenated, here or anywhere upstream: a
    shingle spans five words of one field, so no shared shingle is ever an
    artefact of two constants sitting next to each other.

    Returns True only if all of:

    - the two payloads share at least MIN_SHARED_SHINGLES hashes in total;
    - the two payloads overlap by at least *threshold*: how much of the
      smaller of the two the shared text accounts for, measured over
      everything each call carried;
    - and the shared text is either one coherent run — a single pair of
      fields, one from each side, meeting the floor by itself — or so much
      of *each* payload that the two calls are copies of each other rather
      than two calls with something in common: NEAR_DUPLICATE of the
      smaller and *threshold* of the larger.

    Each condition answers a different way of faking an echo. Containment
    alone fires on boilerplate phrases, which the floor discriminates. The
    floor alone lets one constant field that every agent in a fleet sends —
    a header, a template, a signature — match at 1.0, which containment over
    the whole payload dilutes in proportion to how much real message
    surrounds it. And a floor met by adding up several short shares, at
    ordinary containment, is met by any fleet that spreads its template over
    several arguments — which is why adding them up needs the near-duplicate
    ratio.

    That ratio needs the second half to mean what it says. Containment is
    Szymkiewicz–Simpson, so it is measured over the smaller payload and says
    nothing at all about the larger one: a call that carries a shared
    template and nothing else scores 1.0 against a call carrying the same
    template beside eighty words of its own message, which is a fleet
    sharing a canned notification and not one agent reposting another's
    call. Requiring the shared text to be *threshold* of the larger payload
    too is what leaves no room for a message beside a shared template. Two
    calls that really are copies are unaffected, because on those the two
    payloads are the same size.

    None of this can tell a fleet-wide constant from a quotation on its own;
    that needs more than one call to look at, and is EchoStore.confirm()'s
    job.

    *threshold* has no default on purpose: the value that ships lives in
    EchoStore, which is what the proxy constructs, and a default here would
    be a second place for it that no deployment reads.
    """
    union_a = frozenset().union(*a_fields) if a_fields else frozenset()
    union_b = frozenset().union(*b_fields) if b_fields else frozenset()
    shared = union_a & union_b
    if len(shared) < MIN_SHARED_SHINGLES:
        return False
    containment = overlap(union_a, union_b)
    if containment < threshold:
        return False
    if any(len(a & b) >= MIN_SHARED_SHINGLES for a in a_fields for b in b_fields):
        return True
    return containment >= NEAR_DUPLICATE and len(shared) >= threshold * max(
        len(union_a), len(union_b)
    )

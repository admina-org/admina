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

"""E-mail address matching for the EMAIL PII category.

:data:`EMAIL_RX` is the e-mail pattern of the PII redactor
(``pii.REGEX_PII_PATTERNS["EMAIL"]``) and of the spaCy + regex PII engine.
:func:`iter_email_matches` yields the matches of ``EMAIL_RX.finditer(text)``
in time linear in ``len(text)``: it makes one match attempt per run of
local-part characters followed by ``@`` (``finditer`` makes one at every word
boundary inside such a run, and each attempt reads to the end of the run).

Why one attempt per run is enough: the local part of a match is followed by
``@``, which is not a local-part character, so it ends where its run ends,
and the rest of the match (``@``, domain, top-level domain) does not depend
on where the local part starts. A run followed by ``@`` and a domain that
``EMAIL_RX`` accepts therefore holds exactly one match: the one starting at
the first word boundary of the run that is not before the end of the
previous match. Any other run holds none.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

_LOCAL = r"[A-Za-z0-9._%+-]"
_DOMAIN = r"@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"

EMAIL_RX = re.compile(rf"\b{_LOCAL}+{_DOMAIN}")
"""E-mail pattern of the EMAIL PII category.

Its own ``search``, ``finditer`` and ``sub`` take time quadratic in the
length of a run of local-part characters that holds many word boundaries
(``"a." * 8000``, 16,000 characters, takes about 0.15 s). On text of unbounded length, find the
matches with :func:`iter_email_matches`, as Admina does.
"""

# A whole run of local-part characters (the lookbehind refuses a start
# inside a run and the possessive quantifier reads the run once) followed by
# "@" and a domain that EMAIL_RX accepts.
_RUN_BEFORE_DOMAIN_RX = re.compile(rf"(?<!{_LOCAL}){_LOCAL}++(?={_DOMAIN})")
_WORD_BOUNDARY_RX = re.compile(r"\b")


def iter_email_matches(text: str) -> Iterator[re.Match[str]]:
    """Yield the matches of ``EMAIL_RX.finditer(text)``, in the same order.

    Each match has the span and text of the corresponding ``finditer``
    match; it is the result of ``EMAIL_RX.match(text, start)``.
    """
    if "@" not in text:
        return
    end = 0
    for run in _RUN_BEFORE_DOMAIN_RX.finditer(text):
        at = run.end()
        boundary = _WORD_BOUNDARY_RX.search(text, max(run.start(), end), at)
        if boundary is None or boundary.start() >= at:
            continue
        match = EMAIL_RX.match(text, boundary.start())
        if match is not None:
            yield match
            end = match.end()

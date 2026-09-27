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

"""Pattern timing probe — worst-case search time of a regex on long inputs.

The firewall runs every pattern with Python's backtracking ``re`` engine.
A pattern that places two whitespace quantifiers around optional groups
(``\\s+(?:all\\s+)?\\s*``) needs time proportional to the square of a
whitespace run, and nested quantifiers (``(\\s+)+x``) need exponential
time. Check each entry of ``agent_security.firewall.custom_patterns``
before deploying it::

    from admina.domains.agent_security.pattern_timing import probe_pattern

    worst_ms = probe_pattern(r"(?:ignora|dimentica)\\s++(?:le\\s++)?istruzioni")
    assert worst_ms <= 50.0

Generated inputs (:func:`timing_inputs`), for every trigger:

* triggers: the literal words of the pattern source, the whitespace-joined
  phrases among them (``d'ora\\s+in\\s+poi`` gives ``"d'ora in poi"``) and
  :data:`GENERIC_TRIGGERS`; a character class contributes its first member
  when that is a word character (``tutt[oae]`` gives ``"tutto"``);
* the trigger followed by ``size`` characters of each :data:`FILLERS`
  entry (spaces, tabs, commas, newlines, and a mix of the four);
* the trigger repeated, separated by one space, up to ``size`` characters.

The search time of an input is the best of up to three runs.
:func:`measure_pattern` runs the inputs on growing sizes (8 to 256
characters, then four times larger up to a sixteenth of ``size``, then
``size``) and stops as soon as an input exceeds the budget, so a slow
pattern is reported without running it on 64k characters. Between two
sizes it projects the next size from the measured growth; when the
projection for the slowest input, timed again at both sizes, exceeds
twice the budget, the probe stops there and reports the projection.

Passing the probe is evidence, not proof: the inputs are derived from the
pattern source and cannot cover every possible text. Writing one
whitespace quantifier between two literals, with the whitespace inside
each optional group, and possessive quantifiers (``\\s++``, ``\\s*+``,
Python 3.11+) where a quantifier is followed by a literal, keeps a
pattern linear by construction.
"""

from __future__ import annotations

import math
import re
import time
from collections.abc import Iterator
from typing import NamedTuple

DEFAULT_SIZE = 65_536
"""Characters of filler after each trigger (64k)."""

DEFAULT_BUDGET_MS = 50.0
"""Time budget for one search on one input, in milliseconds."""

DEFAULT_FLAGS = re.IGNORECASE | re.DOTALL
"""Flags used to compile string patterns (the firewall's flags)."""

FILLERS: dict[str, str] = {
    "space": " ",
    "tab": "\t",
    "comma": ",",
    "newline": "\n",
    "mixed": " \t,\n",
}
"""Filler runs placed after each trigger, by name."""

GENERIC_TRIGGERS: tuple[str, ...] = ("", "ignore", "show", "exec")
"""Triggers used for every pattern ("" gives plain filler runs)."""

# Growing input sizes: small steps where nested quantifiers blow up, then
# four times larger up to a sixteenth of the requested size, then that size.
_SMALL_SIZES = (8, 12, 16, 20, 24, 32, 48, 64, 96, 128, 192, 256)
_SIZE_STEP = 4
_LAST_STEP = 16
_REPEATS = 3
# A projection above this multiple of the budget stops the probe; times
# below the floor are too close to the timer resolution to project from.
_PROJECTION_MARGIN = 2.0
_PROJECTION_FLOOR_MS = 0.01
# A run this many times over the budget is not repeated.
_NO_REPEAT_FACTOR = 20.0

# Source scanning for trigger words.
_BREAK = "\x00"
_CLASS_RX = re.compile(r"\[(\^?)((?:\\.|[^\]\\])+)\]")
_WHITESPACE_TOKEN_RX = re.compile(r"(?:\\s|\\t|\\n| )(?:[*+?]|\{\d*(?:,\d*)?\})?[+?]?")
_ESCAPE_RX = re.compile(r"\\.")
_BOUNDS_RX = re.compile(r"\{\d*(?:,\d*)?\}")
_NON_WORD_RX = re.compile(r"[^\w'’ ]")
_WORD_RX = re.compile(r"\w+(?:['’]\w+)*")


class PatternTiming(NamedTuple):
    """Result of :func:`measure_pattern`."""

    worst_ms: float
    """Slowest search time found, in milliseconds (or the projection)."""
    worst_input: str
    """Label of the slowest input (see :func:`timing_inputs`)."""
    size: int
    """Input size ``worst_ms`` refers to."""
    projected: bool
    """True when ``worst_ms`` is projected from smaller sizes, not measured."""
    timings: dict[str, float]
    """Search time of every input measured at the last size run."""


def _source(pattern: str | re.Pattern[str]) -> str:
    return pattern.pattern if isinstance(pattern, re.Pattern) else pattern


def _class_member(match: re.Match[str]) -> str:
    negated, members = match.groups()
    first = members[0]
    return first if not negated and re.fullmatch(r"\w", first) else _BREAK


def trigger_words(pattern: str | re.Pattern[str]) -> list[str]:
    """Return the literal words and phrases of a pattern source, in order.

    A phrase is two or more words separated only by whitespace in the
    source (``\\s+``, ``\\s*``, a space, with any quantifier). Words shorter
    than two characters are left out.
    """
    src = _CLASS_RX.sub(_class_member, _source(pattern))
    src = _WHITESPACE_TOKEN_RX.sub(" ", src)
    src = _ESCAPE_RX.sub(_BREAK, src)
    src = _BOUNDS_RX.sub(_BREAK, src)
    src = _NON_WORD_RX.sub(_BREAK, src)

    found: list[str] = []
    for chunk in src.split(_BREAK):
        words = _WORD_RX.findall(chunk)
        if len(words) > 1:
            found.append(" ".join(words))
        found.extend(w for w in words if len(w) > 1)
    return list(dict.fromkeys(found))


def _fill(unit: str, size: int) -> str:
    return (unit * (size // len(unit) + 1))[:size]


def pattern_triggers(pattern: str | re.Pattern[str]) -> list[str]:
    """Return :func:`trigger_words` followed by :data:`GENERIC_TRIGGERS`."""
    return list(dict.fromkeys([*trigger_words(pattern), *GENERIC_TRIGGERS]))


def trigger_inputs(trigger: str, *, size: int = DEFAULT_SIZE) -> Iterator[tuple[str, str]]:
    """Yield ``(label, text)`` long inputs for one trigger.

    The trigger followed by ``size`` characters of each filler (label
    ``"'show' + space run"``), then the trigger repeated with one space up
    to ``size`` characters (label ``"'show' repeated"``; not for ``""``).
    """
    for name, filler in FILLERS.items():
        yield f"{trigger!r} + {name} run", trigger + _fill(filler, size)
    if trigger:
        yield f"{trigger!r} repeated", _fill(trigger + " ", size)


def timing_inputs(
    pattern: str | re.Pattern[str], *, size: int = DEFAULT_SIZE
) -> Iterator[tuple[str, str]]:
    """Yield the :func:`trigger_inputs` of every :func:`pattern_triggers` entry."""
    for trigger in pattern_triggers(pattern):
        yield from trigger_inputs(trigger, size=size)


def search_ms(
    regex: re.Pattern[str],
    text: str,
    *,
    repeats: int = _REPEATS,
    budget_ms: float | None = None,
) -> float:
    """Return the best of ``repeats`` runs of ``regex.search(text)``, in ms.

    With ``budget_ms`` set, stop repeating as soon as a run is within it,
    or more than twenty times over it.
    """
    best = math.inf
    for _ in range(repeats):
        start = time.perf_counter()
        regex.search(text)
        best = min(best, (time.perf_counter() - start) * 1000)
        if budget_ms is not None and not budget_ms < best <= _NO_REPEAT_FACTOR * budget_ms:
            break
    return best


def _sizes(size: int) -> list[int]:
    sizes = [n for n in _SMALL_SIZES if n < size]
    n = sizes[-1] if sizes else size
    while n * _SIZE_STEP <= size // _LAST_STEP:
        n *= _SIZE_STEP
        sizes.append(n)
    sizes.append(size)
    return sizes


def _projection(previous: tuple[int, float], current: tuple[int, float], size: int) -> float:
    """Project the worst time at ``size`` from the growth between two sizes."""
    (n0, t0), (n1, t1) = previous, current
    if t0 < _PROJECTION_FLOOR_MS or t1 <= t0:
        return 0.0
    exponent = math.log(t1 / t0) / math.log(n1 / n0)
    return t1 * (size / n1) ** exponent


def _input(regex: re.Pattern[str], label: str, size: int) -> str:
    return next(text for name, text in timing_inputs(regex, size=size) if name == label)


def _confirmed_projection(
    regex: re.Pattern[str], label: str, previous: int, current: int, size: int
) -> float:
    """Project ``label`` at ``size`` from best-of-three times at two sizes."""
    t0 = search_ms(regex, _input(regex, label, previous))
    t1 = search_ms(regex, _input(regex, label, current))
    return _projection((previous, t0), (current, t1), size)


def measure_pattern(
    regex: str | re.Pattern[str],
    *,
    size: int = DEFAULT_SIZE,
    budget_ms: float = DEFAULT_BUDGET_MS,
    flags: int = DEFAULT_FLAGS,
) -> PatternTiming:
    """Measure the worst search time of ``regex`` on the generated inputs.

    ``regex`` is a compiled pattern or a string compiled with ``flags``.
    Returns the slowest input at ``size`` characters, or the first input
    over ``budget_ms`` (or the projection) on the way there.
    """
    compiled = regex if isinstance(regex, re.Pattern) else re.compile(regex, flags)
    sizes = _sizes(size)
    previous: tuple[int, float] | None = None
    for step, n in enumerate(sizes):
        timings: dict[str, float] = {}
        worst_ms, worst_input = 0.0, ""
        for label, text in timing_inputs(compiled, size=n):
            ms = search_ms(compiled, text, budget_ms=budget_ms)
            timings[label] = ms
            if ms > worst_ms:
                worst_ms, worst_input = ms, label
            if ms > budget_ms:
                return PatternTiming(ms, label, n, False, timings)
        if step + 1 == len(sizes):
            break
        following = sizes[step + 1]
        limit = _PROJECTION_MARGIN * budget_ms
        if previous is not None and _projection(previous, (n, worst_ms), following) > limit:
            projected = _confirmed_projection(compiled, worst_input, previous[0], n, following)
            if projected > limit:
                return PatternTiming(projected, worst_input, following, True, timings)
        previous = (n, worst_ms)
    return PatternTiming(worst_ms, worst_input, size, False, timings)


def probe_pattern(
    regex: str | re.Pattern[str],
    *,
    size: int = DEFAULT_SIZE,
    budget_ms: float = DEFAULT_BUDGET_MS,
    flags: int = DEFAULT_FLAGS,
) -> float:
    """Return the worst search time of ``regex`` on long inputs, in ms.

    A value above ``budget_ms`` means the pattern is too slow on some
    input; :func:`measure_pattern` names that input.
    """
    return measure_pattern(regex, size=size, budget_ms=budget_ms, flags=flags).worst_ms

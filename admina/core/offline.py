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

"""Admina — offline mode (``ADMINA_OFFLINE``).

Without network access Admina runs as it does with it: the PII engines
never download anything (a spaCy model that is not installed is an error,
and Presidio checks e-mail domains against the public suffix list bundled
with tldextract). ``ADMINA_OFFLINE=true`` also turns off what could reach
the network on its own:

- the variables of :data:`OFFLINE_ENVIRONMENT` are set to ``1`` before a PII
  engine is built and when the proxy starts, so libraries that honour them
  (Hugging Face Hub, Transformers, Datasets) load only local files;
- the proxy starts without the OpenTelemetry exporter.
"""

from __future__ import annotations

import logging
import os

logger = logging.getLogger("admina.offline")

OFFLINE_ENVIRONMENT = ("HF_HUB_OFFLINE", "TRANSFORMERS_OFFLINE", "HF_DATASETS_OFFLINE")
"""Variables set to ``1`` in offline mode."""

_TRUE = frozenset({"1", "true", "yes", "on"})
_FALSE = frozenset({"", "0", "false", "no", "off"})


def offline_mode() -> bool:
    """True when ``ADMINA_OFFLINE`` is ``1``, ``true``, ``yes`` or ``on``
    (any case); False when it is unset, empty, ``0``, ``false``, ``no`` or
    ``off``.

    Raises:
        ValueError: any other value.
    """
    value = os.environ.get("ADMINA_OFFLINE", "").strip().lower()
    if value in _TRUE:
        return True
    if value in _FALSE:
        return False
    raise ValueError("ADMINA_OFFLINE must be true or false (1/0, yes/no, on/off)")


def apply_offline_environment() -> bool:
    """In offline mode, set each variable of :data:`OFFLINE_ENVIRONMENT` to
    ``1``; return whether offline mode is on."""
    if not offline_mode():
        return False
    changed = [name for name in OFFLINE_ENVIRONMENT if os.environ.get(name) != "1"]
    for name in changed:
        os.environ[name] = "1"
    if changed:
        logger.info("ADMINA_OFFLINE: %s set to 1", ", ".join(changed))
    return True

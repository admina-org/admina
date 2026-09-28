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

"""Admina — ``ADMINA_*`` environment variables that nothing reads.

At startup the proxy lists the variables whose name starts with
``ADMINA_`` (any case), in its environment and its ``.env`` file, that no
part of Admina reads: not a setting of the proxy
(:class:`admina.proxy.config.Settings`), not in :data:`KNOWN_VARIABLES`
(engines, SDK, builtin plugins, the other containers of the stack), not a
per-route key of the gateway (``ADMINA_GATEWAY_UPSTREAM_<NAME>_API_KEY``
and ``_FILE``), and not under an allowed prefix:

- ``ADMINA_<NAME>_`` for each entry point ``<name>`` (upper case, any
  character other than a letter or a digit read as ``_``) of the groups
  ``admina.plugins``, ``admina.pii_engines`` and ``admina.pattern_packs``:
  a plugin distribution reads its own variables under the name of its
  entry point (:func:`plugin_prefixes`);
- the prefixes listed in ``ADMINA_ENV_ALLOW_PREFIXES``, for other
  components that share the environment.

They are logged as a warning; ``ADMINA_CONFIG_STRICT=true`` makes them an
:class:`UnknownVariablesError` and the proxy does not start. Values are
never logged.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from importlib import metadata

from admina.proxy.config import Settings

__all__ = [
    "KNOWN_VARIABLES",
    "PLUGIN_GROUPS",
    "UnknownVariablesError",
    "known_variables",
    "plugin_prefixes",
    "unknown_variables",
]

PREFIX = "ADMINA_"

#: ADMINA_* variables read outside the proxy settings.
KNOWN_VARIABLES = frozenset(
    {
        # Engines and configuration.
        "ADMINA_CONFIG",
        "ADMINA_ENGINE",
        "ADMINA_OFFLINE",
        "ADMINA_PATTERN_PACK_DIRS",
        "ADMINA_PII_ENGINE",
        "ADMINA_PII_MASK_STYLE",
        "ADMINA_PRESIDIO_NLP_MODELS",
        "ADMINA_SPACY_MODEL",
        # Governance domains.
        "ADMINA_EGRESS_FINGERPRINT_KEY",
        "ADMINA_EGRESS_MODE",
        "ADMINA_FORENSIC_STATE_KEY",
        "ADMINA_FORENSIC_STATE_KEY_FILE",
        "ADMINA_GDPR_ROPA_PATH",
        # SDK.
        "ADMINA_RETRY_BASE_DELAY_S",
        "ADMINA_RETRY_JITTER",
        "ADMINA_RETRY_MAX_ATTEMPTS",
        "ADMINA_RETRY_MAX_DELAY_S",
        # Builtin plugins: alert channel, model adapters, data connector.
        "ADMINA_ALERT_WEBHOOK_EVENTS",
        "ADMINA_ALERT_WEBHOOK_TIMEOUT",
        "ADMINA_ALERT_WEBHOOK_URL",
        "ADMINA_ANTHROPIC_API_KEY",
        "ADMINA_ANTHROPIC_MAX_TOKENS",
        "ADMINA_ANTHROPIC_MODEL",
        "ADMINA_BEDROCK_MAX_TOKENS",
        "ADMINA_BEDROCK_MODEL",
        "ADMINA_BEDROCK_REGION",
        "ADMINA_CHROMA_COLLECTION",
        "ADMINA_CHROMA_HOST",
        "ADMINA_CHROMA_PORT",
        "ADMINA_GEMINI_API_KEY",
        "ADMINA_GEMINI_MODEL",
        "ADMINA_MISTRAL_API_KEY",
        "ADMINA_MISTRAL_MODEL",
        "ADMINA_OLLAMA_HOST",
        "ADMINA_OLLAMA_MODEL",
        "ADMINA_OPENAI_API_KEY",
        "ADMINA_OPENAI_BASE_URL",
        "ADMINA_OPENAI_MODEL",
        "ADMINA_VLLM_API_KEY",
        "ADMINA_VLLM_BASE_URL",
        "ADMINA_VLLM_MODEL",
        # The dashboard container and the integrations.
        "ADMINA_DASHBOARD_PASSWORD",
        "ADMINA_DASHBOARD_USER",
        "ADMINA_PORT",
        "ADMINA_PROXY_URL",
        "ADMINA_TIMEOUT",
    }
)

# ADMINA_GATEWAY_UPSTREAM_<NAME>_API_KEY[_FILE] (admina.proxy.gateway_upstreams).
_ROUTE_KEY = re.compile(r"ADMINA_GATEWAY_UPSTREAM_[A-Z0-9_]+_API_KEY(?:_FILE)?")

#: Entry-point groups whose entry point names give an allowed prefix.
PLUGIN_GROUPS = ("admina.plugins", "admina.pii_engines", "admina.pattern_packs")


class UnknownVariablesError(ValueError):
    """``ADMINA_CONFIG_STRICT=true`` and ADMINA_* variables that nothing
    reads are set; the proxy does not start."""


def known_variables() -> frozenset[str]:
    """The ADMINA_* settings of the proxy (by the name they are read
    under) and :data:`KNOWN_VARIABLES`."""
    names = set(KNOWN_VARIABLES)
    for name, field in Settings.model_fields.items():
        alias = field.validation_alias
        read_as = alias if isinstance(alias, str) else name
        if read_as.upper().startswith(PREFIX):
            names.add(read_as.upper())
    return frozenset(names)


def plugin_prefixes() -> tuple[str, ...]:
    """``ADMINA_<NAME>_`` for each entry point of :data:`PLUGIN_GROUPS`."""
    prefixes = set()
    for group in PLUGIN_GROUPS:
        for entry_point in metadata.entry_points(group=group):
            prefixes.add(PREFIX + re.sub(r"[^A-Z0-9]", "_", entry_point.name.upper()) + "_")
    return tuple(sorted(prefixes))


def unknown_variables(
    environ: Mapping[str, str], *, allow_prefixes: Iterable[str] = ()
) -> list[str]:
    """The ADMINA_* names of *environ* that nothing reads, sorted.

    Names are compared in upper case, as the settings read them. Empty or
    blank entries of *allow_prefixes* are ignored.
    """
    known = known_variables()
    prefixes = tuple(p.strip().upper() for p in allow_prefixes if p.strip())
    return sorted(
        name
        for name in environ
        if name.upper().startswith(PREFIX)
        and name.upper() not in known
        and not _ROUTE_KEY.fullmatch(name.upper())
        and not name.upper().startswith(prefixes)
    )

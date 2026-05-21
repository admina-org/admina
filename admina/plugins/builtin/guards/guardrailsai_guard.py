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

"""Admina — GuardrailsAI governance guard.

Wraps GuardrailsAI validators (toxic language, PII, jailbreak, bias)
as a :class:`BaseGovernanceGuard` in Admina's governance pipeline.

Requires: the ``guardrails-ai`` package installed in your environment.
That package is currently in PyPI quarantine, so Admina does not ship a
``[guardrailsai]`` extra; install it from a local wheel/mirror if you
have one.

Critical constraint: ``inference_mode: local`` by default — no data
leaves the deployment perimeter.
"""

from __future__ import annotations

import logging
from typing import Any

from admina.plugins.base import BaseGovernanceGuard

logger = logging.getLogger("admina.plugins.guards.guardrailsai")

# Validator name → hub import path mapping.
_VALIDATOR_REGISTRY: dict[str, str] = {
    "toxic_language": "guardrails.hub.ToxicLanguage",
    "detect_pii": "guardrails.hub.DetectPII",
    "detect_jailbreak": "guardrails.hub.DetectJailbreak",
    "bias_check": "guardrails.hub.BiasCheck",
}


def _import_guardrails() -> Any:
    """Import guardrails, raising a clear error if not installed."""
    try:
        import guardrails  # type: ignore[import-untyped]

        return guardrails
    except ImportError as exc:
        raise ImportError(
            "The 'guardrails-ai' package is required for GuardrailsAIGuard, but "
            "it is currently in PyPI quarantine (https://pypi.org/simple/guardrails-ai/), "
            "so Admina does not ship it as an optional extra. If you have a local "
            "copy installed (wheel, mirror, or pre-quarantine cache), the plugin "
            "will detect it automatically; otherwise this guard is disabled."
        ) from exc


def _load_validator(name: str, params: dict[str, Any]) -> Any:
    """Dynamically load a GuardrailsAI validator by name.

    Args:
        name: Validator name from ``admina.yaml`` (e.g. ``"toxic_language"``).
        params: Validator-specific parameters (threshold, entities, etc.).

    Returns:
        An instantiated GuardrailsAI validator object.

    Raises:
        ValueError: If the validator name is unknown.
        ImportError: If the hub module cannot be imported.
    """
    import_path = _VALIDATOR_REGISTRY.get(name)
    if import_path is None:
        raise ValueError(
            f"Unknown GuardrailsAI validator: {name!r}. Supported: {sorted(_VALIDATOR_REGISTRY)}"
        )

    module_path, class_name = import_path.rsplit(".", 1)
    import importlib

    module = importlib.import_module(module_path)
    validator_cls = getattr(module, class_name)

    # Admina handles the action — validators report only.
    params.setdefault("on_fail", "noop")
    return validator_cls(**params)


class GuardrailsAIGuard(BaseGovernanceGuard):
    """Governance guard wrapping GuardrailsAI validators.

    Dynamically loads validators from ``admina.yaml`` config and runs
    them against request/response content.  All inference is local by
    default — no data leaves the deployment perimeter.

    Args:
        config: Guard configuration dict from ``admina.yaml``.
            Expected keys:
            - ``validators``: list of ``{"name": str, **params}`` dicts.
            - ``inference_mode``: ``"local"`` (default) or ``"remote"``.

    Raises:
        ImportError: If ``guardrails-ai`` is not installed.
        ValueError: If ``inference_mode`` is ``"remote"`` (blocked for
            data sovereignty).
    """

    name = "guardrailsai"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        config = config or {}
        guardrails = _import_guardrails()
        Guard = guardrails.Guard

        inference_mode = config.get("inference_mode", "local")
        if inference_mode != "local":
            raise ValueError(
                "GuardrailsAIGuard only supports inference_mode='local'. "
                "Remote mode sends data outside the deployment perimeter, "
                "violating data sovereignty requirements."
            )

        validator_configs = config.get("validators", [])
        if not validator_configs:
            logger.warning("GuardrailsAIGuard created with no validators configured.")

        validators = []
        for v_cfg in validator_configs:
            v_name = v_cfg["name"]
            v_params = {k: v for k, v in v_cfg.items() if k != "name"}
            validators.append(_load_validator(v_name, v_params))

        self._guard: Any = Guard().use_many(*validators) if validators else Guard()
        self._validator_count = len(validators)

    async def inspect_request(self, request: dict[str, Any]) -> dict[str, Any]:
        """Validate inbound request content with GuardrailsAI."""
        return self._validate(request)

    async def inspect_response(self, response: dict[str, Any]) -> dict[str, Any]:
        """Validate outbound response content with GuardrailsAI."""
        return self._validate(response)

    def _validate(self, payload: dict[str, Any]) -> dict[str, Any]:
        text = payload.get("content", "")
        if not text:
            return {"action": "ALLOW", "risk_level": "LOW", "guard": "guardrailsai"}

        outcome = self._guard.validate(text)

        if outcome.validation_passed:
            return {
                "action": "ALLOW",
                "risk_level": "LOW",
                "guard": "guardrailsai",
                "metadata": {"validators_run": self._validator_count},
            }

        return {
            "action": "BLOCK",
            "risk_level": "HIGH",
            "guard": "guardrailsai",
            "details": str(outcome.error),
            "metadata": {
                "failed": [v.__class__.__name__ for v in outcome.failed_validations],
            },
        }

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

"""Admina — Webhook alert channel.

POSTs governance alerts as JSON to a configurable URL.
"""

from __future__ import annotations

import json
import logging
import os
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from admina.plugins.base import BaseAlertChannel

logger = logging.getLogger("admina.plugins.alerts.webhook")

_ALLOWED_SCHEMES = frozenset({"http", "https"})


class WebhookAlertChannel(BaseAlertChannel):
    """Alert channel that POSTs JSON to a webhook URL.

    Args:
        url: The webhook endpoint URL.
        timeout: HTTP request timeout in seconds.
        events: Optional list of alert levels to forward
            (e.g. ``["HIGH", "CRITICAL"]``).  ``None`` forwards all.
    """

    channel_name = "webhook"

    def __init__(
        self,
        url: str | None = None,
        timeout: int | None = None,
        events: list[str] | None = None,
    ) -> None:
        # Read defaults from env so the plugin works when registered with
        # no explicit config. ADMINA_ALERT_WEBHOOK_URL empty = disabled
        # (channel still registers but send_alert short-circuits).
        self._url = url if url is not None else os.environ.get("ADMINA_ALERT_WEBHOOK_URL", "")
        self._timeout = (
            timeout
            if timeout is not None
            else int(os.environ.get("ADMINA_ALERT_WEBHOOK_TIMEOUT", "10"))
        )
        if events is None:
            env_events = os.environ.get("ADMINA_ALERT_WEBHOOK_EVENTS", "")
            events = [e.strip() for e in env_events.split(",") if e.strip()] or None
        self._events = set(events) if events else None

    async def send_alert(self, alert: dict) -> bool:
        """POST the alert as JSON to the configured webhook URL.

        Args:
            alert: Alert dict.

        Returns:
            ``True`` if the webhook responded with 2xx.
        """
        if not self._url:
            logger.warning("Webhook URL not configured — alert dropped")
            return False

        if urlparse(self._url).scheme not in _ALLOWED_SCHEMES:
            logger.error(
                "Webhook URL must use http or https — got %r — alert dropped",
                self._url,
            )
            return False

        if self._events and alert.get("level") not in self._events:
            return True  # filtered out, not an error

        try:
            payload = json.dumps(alert, default=str).encode("utf-8")
            req = Request(  # nosec B310 — scheme validated above
                self._url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(req, timeout=self._timeout) as resp:  # nosec B310
                return 200 <= resp.status < 300
        except (OSError, ValueError):
            logger.exception("Webhook delivery failed")
            return False

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

"""Admina — Logging alert channel.

Sends governance alerts to the Python logging system.
Always available, zero dependencies.
"""

from __future__ import annotations

import logging

from admina.plugins.base import BaseAlertChannel

logger = logging.getLogger("admina.alerts")


class LogAlertChannel(BaseAlertChannel):
    """Alert channel that writes to Python logging.

    Args:
        log_level: Logging level for alerts.  Defaults to ``WARNING``.
    """

    channel_name = "log"

    def __init__(self, log_level: int = logging.WARNING) -> None:
        self._log_level = log_level

    async def send_alert(self, alert: dict) -> bool:
        """Log a governance alert.

        Args:
            alert: Alert dict with ``level``, ``domain``, ``summary``, etc.

        Returns:
            Always ``True``.
        """
        level_map = {
            "LOW": logging.INFO,
            "MEDIUM": logging.WARNING,
            "HIGH": logging.ERROR,
            "CRITICAL": logging.CRITICAL,
        }
        log_level = level_map.get(alert.get("level", ""), self._log_level)

        logger.log(
            log_level,
            "[%s] %s — %s",
            alert.get("level", "UNKNOWN"),
            alert.get("domain", "unknown"),
            alert.get("summary", "no summary"),
        )
        return True

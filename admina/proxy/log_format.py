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

"""Log output of the proxy: text (default) or one JSON object per line.

``ADMINA_LOG_FORMAT=json`` writes ``{"timestamp", "level", "logger",
"message"}`` plus ``"exception"`` when the record carries one. Other record
attributes, such as values passed with ``extra=``, are not written.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime

__all__ = ["LOG_FORMATS", "TEXT_FORMAT", "JsonLogFormatter", "configure_logging"]

#: Values of ADMINA_LOG_FORMAT; the first one is the default.
LOG_FORMATS = ("text", "json")
#: Line format of the text output.
TEXT_FORMAT = "%(asctime)s [%(name)s] %(levelname)s: %(message)s"

# Loggers of uvicorn that carry handlers of their own.
_UVICORN_LOGGERS = ("uvicorn", "uvicorn.access")


class JsonLogFormatter(logging.Formatter):
    """Formats a record as one line of JSON with a fixed set of fields."""

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "timestamp": datetime.fromtimestamp(record.created, UTC)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry, ensure_ascii=False, default=str)


def configure_logging(level: str, log_format: str) -> None:
    """Configure the root logger at *level* with the *log_format* output.

    With ``json`` the handlers uvicorn installed on its own loggers switch
    to JSON too, so every line the process writes is JSON.
    """
    log_level = getattr(logging, level)
    if log_format != "json":
        logging.basicConfig(level=log_level, format=TEXT_FORMAT)
        return
    formatter = JsonLogFormatter()
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logging.basicConfig(level=log_level, handlers=[handler])
    for name in _UVICORN_LOGGERS:
        for uvicorn_handler in logging.getLogger(name).handlers:
            uvicorn_handler.setFormatter(formatter)

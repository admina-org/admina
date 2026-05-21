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

"""Admina — Filesystem data connector.

A simple data connector that reads files from the local filesystem.
Useful as a zero-dependency fallback and for development.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from admina.plugins.base import BaseDataConnector

logger = logging.getLogger("admina.plugins.connectors.filesystem")


class FilesystemConnector(BaseDataConnector):
    """Data connector that reads plain-text files from a directory.

    Args:
        base_dir: Root directory for file operations.
    """

    def __init__(self, base_dir: str = ".") -> None:
        self._base_dir = Path(base_dir).resolve()

    # ── BaseDataConnector interface ─────────────────────────────

    async def ingest(self, source: Any, **kwargs: Any) -> dict:
        """Read files from *source* path(s).

        Args:
            source: A file path, directory path, or list of file paths.
            **kwargs: Supports ``glob`` pattern (default ``"*"``) when
                *source* is a directory.

        Returns:
            ``{"doc_count": int, "chunk_count": int}``.
        """
        paths: list[Path] = []
        if isinstance(source, (list, tuple)):
            paths = [Path(p) for p in source]
        else:
            p = Path(source)
            if p.is_dir():
                pattern = kwargs.get("glob", "*")
                paths = list(p.glob(pattern))
            else:
                paths = [p]

        chunk_count = 0
        for fp in paths:
            if fp.is_file():
                chunk_count += 1

        return {"doc_count": len(paths), "chunk_count": chunk_count}

    async def query(self, query: str, **kwargs: Any) -> list[dict]:
        """Search files in the base directory for *query*.

        A naive substring search — production use should prefer a
        vector store connector like ChromaDB.

        Args:
            query: Search string.
            **kwargs: Supports ``glob`` pattern (default ``"**/*"``).

        Returns:
            List of matching files with content excerpts.
        """
        pattern = kwargs.get("glob", "**/*")
        results: list[dict] = []

        for fp in self._base_dir.glob(pattern):
            if not fp.is_file():
                continue
            try:
                text = fp.read_text(errors="replace")
            except OSError:
                continue

            if query.lower() in text.lower():
                results.append(
                    {
                        "text": text[:500],
                        "metadata": {"path": str(fp)},
                        "score": 1.0,
                    }
                )

        return results

    @property
    def name(self) -> str:
        """Connector name."""
        return "filesystem"

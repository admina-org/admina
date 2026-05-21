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
Admina — Loop Breaker Engine — Agent Security domain
Cosine-similarity sliding window detects reasoning loops in real-time.
"""

import hashlib
import logging
import re
from collections import defaultdict

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from admina.core.types import RiskLevel

# Default thresholds — overridden per-instance via constructor kwargs.
_DEFAULT_WINDOW_SIZE = 10
_DEFAULT_SIMILARITY_THRESHOLD = 0.85
_DEFAULT_MAX_CONSECUTIVE = 3

logger = logging.getLogger("admina.loop_breaker")


class LoopBreaker:
    """
    Maintains a sliding window of recent requests per session.
    Uses TF-IDF + cosine similarity to detect repetitive patterns.
    """

    def __init__(
        self,
        window_size: int | None = None,
        similarity_threshold: float | None = None,
        max_consecutive: int | None = None,
        **kwargs,
    ):
        self._window_size = window_size or _DEFAULT_WINDOW_SIZE
        self._threshold = similarity_threshold or _DEFAULT_SIMILARITY_THRESHOLD
        self._max_consecutive = max_consecutive or _DEFAULT_MAX_CONSECUTIVE
        self.windows: dict[str, list[str]] = defaultdict(list)
        self.vectorizer = TfidfVectorizer(
            max_features=500,
            stop_words="english",
            ngram_range=(1, 2),
        )
        self.consecutive_similar: dict[str, int] = defaultdict(int)
        self.total_blocked: int = 0

    def _content_hash(self, text: str) -> str:
        return hashlib.sha256(text.encode()).hexdigest()[:16]

    @staticmethod
    def _variable_tokens(text: str) -> set[str]:
        """Tokens that typically *differ* between iterations of a legitimate
        template (numbers, hex hashes, URLs, UUID-like strings)."""
        toks: set[str] = set()
        toks.update(re.findall(r"\b\d+\b", text))
        toks.update(re.findall(r"\b[a-f0-9]{8,}\b", text, re.IGNORECASE))
        toks.update(re.findall(r"https?://\S+", text))
        toks.update(
            re.findall(
                r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
                text,
                re.IGNORECASE,
            )
        )
        return toks

    def _compute_similarity(self, texts: list[str]) -> float:
        """Average pairwise cosine similarity in the window.

        If the texts are textually similar (>= threshold) but the *variable*
        tokens (numbers, IDs, URLs) differ across messages, the similarity
        is damped by a fixed factor: this is the signature of a legitimate
        action template ("OK, I will proceed with task 1/2/3 ...") rather
        than a real reasoning loop ("I retrieve the file" repeated).
        """
        if len(texts) < 2:
            return 0.0
        try:
            tfidf_matrix = self.vectorizer.fit_transform(texts)
            sim_matrix = cosine_similarity(tfidf_matrix)
            # Get upper triangle (exclude diagonal)
            n = sim_matrix.shape[0]
            upper = sim_matrix[np.triu_indices(n, k=1)]
            raw_sim = float(np.mean(upper)) if len(upper) > 0 else 0.0
        except ValueError as e:
            logger.warning("Similarity computation failed: %s", e)
            return 0.0

        # Damping: if at least two messages have *different* variable-token
        # sets, this looks like a counter/template loop, not a true repeat.
        if raw_sim >= self._threshold:
            var_sets = [self._variable_tokens(t) for t in texts]
            distinct = {frozenset(s) for s in var_sets if s}
            if len(distinct) >= 2:
                # Damp by 30%; "OK proceed task 1/2/3" with sim≈1.0 → ≈0.70,
                # below the default 0.85 threshold so it stops tripping.
                return round(raw_sim * 0.7, 4)
        return raw_sim

    def check(self, session_id: str, content: str) -> dict:
        """
        Check if the current request is part of a reasoning loop.
        Returns: {is_loop: bool, similarity: float, risk_level: str, window_size: int}
        """
        window = self.windows[session_id]
        window.append(content)

        # Keep window at configured size
        if len(window) > self._window_size:
            window.pop(0)

        result = {
            "is_loop": False,
            "similarity": 0.0,
            "risk_level": RiskLevel.LOW,
            "window_size": len(window),
            "consecutive_similar": 0,
        }

        if len(window) < 3:
            return result

        # Check similarity within the sliding window
        similarity = self._compute_similarity(window[-5:])  # last 5 entries
        result["similarity"] = round(similarity, 4)

        if similarity >= self._threshold:
            self.consecutive_similar[session_id] += 1
        else:
            self.consecutive_similar[session_id] = 0

        consecutive = self.consecutive_similar[session_id]
        result["consecutive_similar"] = consecutive

        if consecutive >= self._max_consecutive:
            result["is_loop"] = True
            result["risk_level"] = RiskLevel.HIGH
            self.total_blocked += 1
            logger.warning(
                "Loop detected for session %s: similarity=%.3f, consecutive=%d",
                session_id,
                similarity,
                consecutive,
            )
        elif similarity >= self._threshold:
            result["risk_level"] = RiskLevel.MEDIUM

        return result

    def reset_session(self, session_id: str) -> None:
        """Reset window for a session."""
        self.windows.pop(session_id, None)
        self.consecutive_similar.pop(session_id, None)

    def get_stats(self) -> dict:
        return {
            "active_sessions": len(self.windows),
            "total_blocked": self.total_blocked,
        }

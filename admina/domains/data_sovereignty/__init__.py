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

"""Admina — Data Sovereignty Domain.

PII redaction, data residency, and classification.

PIIRedactor depends on ``spacy`` (the ``[nlp]`` extra) and is loaded
lazily via PEP 562 ``__getattr__`` so importing this package never
fails on a pure-SDK install.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from admina.domains.data_sovereignty.classification import DataClassifier, SensitivityLevel
from admina.domains.data_sovereignty.residency import ResidencyEnforcer

if TYPE_CHECKING:  # pragma: no cover
    from admina.domains.data_sovereignty.pii import PIIRedactor

__all__ = ["PIIRedactor", "ResidencyEnforcer", "DataClassifier", "SensitivityLevel"]


def __getattr__(name: str):
    if name == "PIIRedactor":
        from admina.domains.data_sovereignty.pii import PIIRedactor

        return PIIRedactor
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

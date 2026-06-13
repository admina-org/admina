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

"""Deprecated location — the governance pipeline moved to
:mod:`admina.domains.governance`. This shim re-exports the public surface
so pre-0.10 imports keep working."""

from __future__ import annotations

from admina.domains.governance import (
    GovernanceResult,
    _extract_text_fields,
    redact_response_result,
    run_pipeline,
    safe_serialize,
)

__all__ = [
    "GovernanceResult",
    "_extract_text_fields",
    "redact_response_result",
    "run_pipeline",
    "safe_serialize",
]

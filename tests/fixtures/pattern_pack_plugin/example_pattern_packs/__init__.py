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

"""Pattern pack loaders of a package, for the ``admina.pattern_packs``
entry-point group of the tests."""

from __future__ import annotations

from importlib import resources
from pathlib import Path

_EXAMPLE = {
    "name": "example-pack",
    "version": "1.0.0",
    "description": "Example patterns for the tests.",
    "patterns": [
        {
            "id": "internal_notes",
            "regex": r"\b(?:show|reveal|print)\s++(?:me\s++)?(?:the\s++)?internal\s++"
            r"(?:ticket\s++)?notes\b",
            "category": "example_disclosure",
            "risk_level": "high",
        },
        {
            "id": "admin_role",
            "regex": r"\byou\s++are\s++(?:now\s++)?(?:the\s++)?(?:system\s++)?administrator\b",
            "category": "example_role",
            "risk_level": "medium",
        },
    ],
}


def example_pack() -> dict:
    """The pack as a mapping."""
    return {**_EXAMPLE, "patterns": [dict(p) for p in _EXAMPLE["patterns"]]}


def example_pack_path() -> Path:
    """The path of the pack file in the package."""
    return Path(__file__).with_name("example-pack.yaml")


def example_pack_resource():
    """The pack file as a package resource."""
    return resources.files(__name__) / "example-pack.yaml"


def not_a_pack() -> int:
    return 42


NOT_CALLABLE = {"name": "example-pack"}

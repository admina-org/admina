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

"""Marker exceptions for the governed-SDK retry contract."""

from __future__ import annotations


class RetryableUpstreamError(Exception):
    """Raise from an adapter/connector to mark an upstream failure as transient
    (the RetryPolicy will retry it)."""


class TerminalUpstreamError(Exception):
    """Raise from an adapter/connector to mark an upstream failure as terminal
    (the RetryPolicy will NOT retry it)."""

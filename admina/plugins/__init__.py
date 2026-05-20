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

"""Admina plugin system.

Provides abstract base classes for all 9 plugin interfaces.
Community developers extend these to add new model adapters,
data connectors, governance guards, and more.
"""

from __future__ import annotations

from admina.plugins.base import (
    BaseAlertChannel,
    BaseAuthProvider,
    BaseComplianceTemplate,
    BaseDataConnector,
    BaseForensicStore,
    BaseGovernanceGuard,
    BaseModelAdapter,
    BasePIIEngine,
    BaseTransportAdapter,
)
from admina.plugins.registry import PLUGIN_TYPES, PluginRegistry

__all__ = [
    "BaseModelAdapter",
    "BaseDataConnector",
    "BaseGovernanceGuard",
    "BaseComplianceTemplate",
    "BaseTransportAdapter",
    "BaseForensicStore",
    "BaseAuthProvider",
    "BasePIIEngine",
    "BaseAlertChannel",
    "PluginRegistry",
    "PLUGIN_TYPES",
]

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

"""Tests for domains.data_sovereignty.residency module."""

from admina.domains.data_sovereignty.residency import ResidencyEnforcer


class TestResidencyEnforcer:
    def test_allowed_zone(self):
        enforcer = ResidencyEnforcer(allowed_zones=["local", "eu"])
        result = enforcer.check(source_zone="local")
        assert result["allowed"] is True

    def test_blocked_zone(self):
        enforcer = ResidencyEnforcer(allowed_zones=["local", "eu"])
        result = enforcer.check(source_zone="us-east-1")
        assert result["allowed"] is False

    def test_outbound_transfer_blocked(self):
        enforcer = ResidencyEnforcer(allowed_zones=["local", "eu"], block_outbound=True)
        result = enforcer.check(source_zone="local", target_zone="us-east-1")
        assert result["allowed"] is False
        assert "blocked" in result

    def test_outbound_transfer_allowed_when_disabled(self):
        enforcer = ResidencyEnforcer(allowed_zones=["local", "eu"], block_outbound=False)
        result = enforcer.check(source_zone="local", target_zone="us-east-1")
        assert result["allowed"] is True

    def test_intra_zone_transfer(self):
        enforcer = ResidencyEnforcer(allowed_zones=["local", "eu"])
        result = enforcer.check(source_zone="eu", target_zone="eu")
        assert result["allowed"] is True

    def test_stats(self):
        enforcer = ResidencyEnforcer()
        enforcer.check(source_zone="local")
        enforcer.check(source_zone="us-east-1")
        stats = enforcer.get_stats()
        assert stats["checks_total"] == 2
        assert stats["violations_total"] == 1

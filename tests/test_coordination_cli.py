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

import pytest
from click.testing import CliRunner

from admina.cli.main import app


class _Redis:
    def __init__(self, entries):
        self.h = dict(entries)

    async def hgetall(self, key):
        return dict(self.h)

    async def hdel(self, key, field):
        return 1 if self.h.pop(field, None) is not None else 0

    async def close(self):
        pass


class _FailingRedis:
    """Redis client that always raises."""

    async def hgetall(self, key):
        raise ConnectionError("Redis unreachable")

    async def hdel(self, key, field):
        raise ConnectionError("Redis unreachable")

    async def close(self):
        pass


@pytest.fixture
def fake_redis(monkeypatch):
    holder = {}

    def _factory(url):
        return holder["redis"]

    monkeypatch.setattr("admina.cli.main._quarantine_redis", _factory, raising=True)
    return holder


class TestQuarantineList:
    def test_lists_live_entries(self, fake_redis):
        fake_redis["redis"] = _Redis({"wiki.corp": "99999999999"})
        out = CliRunner().invoke(app, ["egress", "quarantine", "list"]).output
        assert "wiki.corp" in out

    def test_expired_entries_are_not_listed(self, fake_redis):
        fake_redis["redis"] = _Redis({"old.corp": "1"})
        out = CliRunner().invoke(app, ["egress", "quarantine", "list"]).output
        assert "old.corp" not in out

    def test_empty_set_explains_itself(self, fake_redis):
        fake_redis["redis"] = _Redis({})
        out = CliRunner().invoke(app, ["egress", "quarantine", "list"]).output
        assert "No destination" in out


class TestQuarantineLift:
    def test_lifting_reports_success(self, fake_redis):
        fake_redis["redis"] = _Redis({"wiki.corp": "99999999999"})
        r = CliRunner().invoke(app, ["egress", "quarantine", "lift", "wiki.corp"])
        assert r.exit_code == 0
        assert "Lifted" in r.output

    def test_lifting_an_absent_destination_says_so(self, fake_redis):
        fake_redis["redis"] = _Redis({})
        r = CliRunner().invoke(app, ["egress", "quarantine", "lift", "nope.corp"])
        assert r.exit_code == 0
        assert "not quarantined" in r.output.lower()

    def test_the_destination_is_matched_as_the_store_holds_it(self, fake_redis):
        """Destinations are stored lower-cased by the egress analyser; an
        operator typing what a dashboard shows must not be told it was not
        quarantined."""
        fake_redis["redis"] = _Redis({"wiki.corp": "99999999999"})
        r = CliRunner().invoke(app, ["egress", "quarantine", "lift", " WIKI.CORP "])
        assert r.exit_code == 0
        assert "Lifted" in r.output

    def test_lift_with_redis_down_reports_unavailability(self, fake_redis):
        fake_redis["redis"] = _FailingRedis()
        r = CliRunner().invoke(app, ["egress", "quarantine", "lift", "wiki.corp"])
        assert r.exit_code == 1
        assert "Could not reach" in r.output


class TestQuarantineListErrors:
    def test_list_with_redis_down_reports_unavailability(self, fake_redis):
        fake_redis["redis"] = _FailingRedis()
        r = CliRunner().invoke(app, ["egress", "quarantine", "list"])
        assert r.exit_code == 1
        assert "Could not read" in r.output

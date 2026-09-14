"""Minimal fakes for testing — not a test module itself."""


class FakeRedis:
    """Minimal async stand-in: the four operations the counter uses."""

    def __init__(self):
        self.sets: dict[str, set[str]] = {}
        self.ttls: dict[str, int] = {}
        self.fail = False

    async def sadd(self, key, *values):
        if self.fail:
            raise OSError("redis down")
        self.sets.setdefault(key, set()).update(values)
        return len(values)

    async def scard(self, key):
        if self.fail:
            raise OSError("redis down")
        return len(self.sets.get(key, ()))

    async def smembers(self, key):
        if self.fail:
            raise OSError("redis down")
        return set(self.sets.get(key, ()))

    async def expire(self, key, seconds):
        if self.fail:
            raise OSError("redis down")
        self.ttls[key] = seconds
        return True

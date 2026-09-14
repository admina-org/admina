"""Minimal fakes for testing — not a test module itself."""


class FakeRedisError(Exception):
    """Custom error to test broad exception handling."""

    pass


class FakeRedis:
    """Minimal async stand-in: the four operations the counter uses."""

    def __init__(self):
        self.sets: dict[str, set[str]] = {}
        self.ttls: dict[str, int] = {}
        self.fail = False

    async def sadd(self, key, *values):
        if self.fail:
            raise FakeRedisError("redis down")
        self.sets.setdefault(key, set()).update(values)
        return len(values)

    async def scard(self, key):
        if self.fail:
            raise FakeRedisError("redis down")
        return len(self.sets.get(key, ()))

    async def smembers(self, key):
        if self.fail:
            raise FakeRedisError("redis down")
        return set(self.sets.get(key, ()))

    async def expire(self, key, seconds):
        if self.fail:
            raise FakeRedisError("redis down")
        self.ttls[key] = seconds
        return True


class FakeRedisHash(FakeRedis):
    """Adds the hash operations the quarantine store needs."""

    def __init__(self):
        super().__init__()
        self.hashes: dict[str, dict[str, str]] = {}

    async def hset(self, key, field, value):
        if self.fail:
            raise OSError("redis down")
        self.hashes.setdefault(key, {})[field] = str(value)
        return 1

    async def hgetall(self, key):
        if self.fail:
            raise OSError("redis down")
        return dict(self.hashes.get(key, {}))

    async def hdel(self, key, field):
        if self.fail:
            raise OSError("redis down")
        return 1 if self.hashes.get(key, {}).pop(field, None) is not None else 0

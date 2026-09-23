"""Minimal fakes for testing — not a test module itself."""


class FakeRedisError(Exception):
    """Custom error to test broad exception handling."""

    pass


class FakeRedis:
    """Minimal async stand-in: the set operations the detector uses."""

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

    async def sismember(self, key, value):
        if self.fail:
            raise FakeRedisError("redis down")
        return value in self.sets.get(key, ())

    async def sunion(self, keys, *args):
        """Union of several sets. Mirrors redis-py's list-or-varargs call."""
        if self.fail:
            raise FakeRedisError("redis down")
        names = [keys] if isinstance(keys, str | bytes) else list(keys)
        names.extend(args)
        union: set[str] = set()
        for name in names:
            union |= self.sets.get(name, set())
        return union

    async def spop(self, key, count=None):
        """Remove and return one arbitrary member, as redis-py's SPOP does."""
        if self.fail:
            raise FakeRedisError("redis down")
        members = self.sets.get(key)
        if not members:
            return None
        return members.pop()

    async def delete(self, *keys):
        if self.fail:
            raise FakeRedisError("redis down")
        removed = 0
        for key in keys:
            if self.sets.pop(key, None) is not None:
                removed += 1
            self.ttls.pop(key, None)
        return removed

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
            raise FakeRedisError("redis down")
        self.hashes.setdefault(key, {})[field] = str(value)
        return 1

    async def hget(self, key, field):
        if self.fail:
            raise FakeRedisError("redis down")
        return self.hashes.get(key, {}).get(field)

    async def hgetall(self, key):
        if self.fail:
            raise FakeRedisError("redis down")
        return dict(self.hashes.get(key, {}))

    async def hdel(self, key, field):
        if self.fail:
            raise FakeRedisError("redis down")
        return 1 if self.hashes.get(key, {}).pop(field, None) is not None else 0

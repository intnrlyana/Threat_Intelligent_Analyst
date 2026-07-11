"""Thread-safe bounded TTL cache for normalized provider results."""

from __future__ import annotations

from collections import OrderedDict
from copy import deepcopy
from threading import Lock
from time import monotonic

from backend.src.providers.models import ProviderResult


class ProviderCache:
    def __init__(self, ttl_seconds: int = 300, max_entries: int = 256) -> None:
        self.ttl_seconds = ttl_seconds
        self.max_entries = max_entries
        self._items: OrderedDict[tuple[str, ...], tuple[float, ProviderResult]] = OrderedDict()
        self._lock = Lock()
        self.hits = 0
        self.misses = 0

    def get(self, key: tuple[str, ...]) -> ProviderResult | object:
        with self._lock:
            item = self._items.get(key)
            if item is None or monotonic() - item[0] >= self.ttl_seconds:
                self._items.pop(key, None)
                self.misses += 1
                return CACHE_MISS
            self._items.move_to_end(key)
            self.hits += 1
            return deepcopy(item[1])

    def put(self, key: tuple[str, ...], value: ProviderResult) -> None:
        with self._lock:
            self._items[key] = (monotonic(), deepcopy(value))
            self._items.move_to_end(key)
            while len(self._items) > self.max_entries:
                self._items.popitem(last=False)

    def status(self) -> dict[str, int]:
        with self._lock:
            return {"entries": len(self._items), "hits": self.hits, "misses": self.misses, "ttl_seconds": self.ttl_seconds}


CACHE_MISS = object()
_shared_cache: ProviderCache | None = None


def shared_provider_cache(ttl_seconds: int = 300, max_entries: int = 256) -> ProviderCache:
    global _shared_cache
    if _shared_cache is None or _shared_cache.ttl_seconds != ttl_seconds or _shared_cache.max_entries != max_entries:
        _shared_cache = ProviderCache(ttl_seconds, max_entries)
    return _shared_cache

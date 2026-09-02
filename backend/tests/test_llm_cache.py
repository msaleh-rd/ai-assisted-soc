"""Tests for the Redis-backed LLM response cache (Wave 1 / Phase D, Step 3).

No live Redis server is required: REDIS_URL is left unset/unreachable in the
test environment, so the cache transparently falls back to its in-memory TTL
store, which is what these tests exercise.
"""

import time

import pytest

from backend.services.llm_cache import LLMResponseCache


@pytest.fixture
def cache():
    return LLMResponseCache()


class TestLLMResponseCacheInMemoryFallback:
    def test_get_missing_key_returns_none(self, cache):
        assert cache.get("does-not-exist") is None

    def test_set_then_get_roundtrips_value(self, cache):
        cache.set("key1", {"action": "gather_evidence"}, ttl=60)
        assert cache.get("key1") == {"action": "gather_evidence"}

    def test_expired_entry_returns_none_and_is_evicted(self, cache):
        cache.set("key1", {"a": 1}, ttl=0)
        time.sleep(0.01)
        assert cache.get("key1") is None
        # Confirm it was actually evicted from the in-memory store
        assert "key1" not in cache._memory_store

    def test_clear_removes_all_entries(self, cache):
        cache.set("key1", {"a": 1}, ttl=60)
        cache.set("key2", {"b": 2}, ttl=60)
        cache.clear()
        assert cache.get("key1") is None
        assert cache.get("key2") is None

    def test_redis_unavailable_degrades_gracefully(self, cache, monkeypatch):
        monkeypatch.setenv("REDIS_URL", "redis://localhost:1/0")  # unreachable port
        cache.set("key1", {"a": 1}, ttl=60)
        assert cache.get("key1") == {"a": 1}

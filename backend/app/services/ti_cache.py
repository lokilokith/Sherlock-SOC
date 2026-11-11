import threading
import time
from typing import Optional, Tuple

from app.schemas.threat_intelligence import ThreatIntelLookup
from app.core.config import settings

# In‑memory cache: key -> (lookup, timestamp)
_cache: dict[Tuple[str, str, str], Tuple[ThreatIntelLookup, float]] = {}
_lock = threading.Lock()


def _now() -> float:
    return time.time()


def get_cached(provider_name: str, indicator_type: str, normalized_value: str) -> Optional[ThreatIntelLookup]:
    """Return a cached ``ThreatIntelLookup`` if it exists and is still fresh.

    The cache key combines the provider name, indicator type and normalized
    value.  ``settings.ti_cache_ttl_seconds`` controls the TTL.
    """
    key = (provider_name, indicator_type, normalized_value)
    with _lock:
        entry = _cache.get(key)
        if entry is None:
            return None
        lookup, ts = entry
        if _now() - ts > settings.ti_cache_ttl_seconds:
            # Expired – remove it
            del _cache[key]
            return None
        return lookup


def set_cached(provider_name: str, indicator_type: str, normalized_value: str, lookup: ThreatIntelLookup) -> None:
    """Store ``lookup`` in the cache.

    Only cache successful ``available`` lookups; callers should avoid caching
    ``unavailable`` or ``error`` results.
    """
    if lookup.lookup_status != "available":
        return
    key = (provider_name, indicator_type, normalized_value)
    with _lock:
        _cache[key] = (lookup, _now())


def purge_expired() -> None:
    """Remove all entries that have exceeded the TTL.
    """
    cutoff = _now() - settings.ti_cache_ttl_seconds
    with _lock:
        expired_keys = [k for k, (_, ts) in _cache.items() if ts < cutoff]
        for k in expired_keys:
            del _cache[k]

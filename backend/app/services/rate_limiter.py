import collections, threading, time
from typing import Deque

class RateLimiter:
    """Simple in‑process token‑bucket rate limiter.

    * ``max_per_min`` – allowed requests per minute.
    * Shared across all provider instances because it lives at module scope.
    * Thread‑safe via a lock.
    * Does **not** coordinate across multiple processes – documented in the module.
    """
    def __init__(self, max_per_min: int):
        self.max_per_min = max_per_min
        self._timestamps: Deque[float] = collections.deque()
        self._lock = threading.Lock()

    def allow(self) -> bool:
        """Return ``True`` if a request may proceed, otherwise ``False``.

        The method removes timestamps older than 60 seconds, then checks the
        current count. If under the limit, it records the current time and
        permits the request.
        """
        now = time.time()
        cutoff = now - 60.0
        with self._lock:
            while self._timestamps and self._timestamps[0] < cutoff:
                self._timestamps.popleft()
            if len(self._timestamps) < self.max_per_min:
                self._timestamps.append(now)
                return True
            return False


"""Unit tests for in-memory API rate limiting."""

from __future__ import annotations

import unittest

from phishguard.rate_limiter import InMemoryRateLimiter


class TestRateLimiter(unittest.TestCase):
    """Validate sliding-window limiter behavior."""

    def test_limit_blocks_after_threshold(self) -> None:
        limiter = InMemoryRateLimiter(limit=2, window_seconds=60)

        self.assertEqual(limiter.is_allowed("client-a"), (True, 0))
        self.assertEqual(limiter.is_allowed("client-a"), (True, 0))

        allowed, retry_after = limiter.is_allowed("client-a")
        self.assertFalse(allowed)
        self.assertGreaterEqual(retry_after, 1)


if __name__ == "__main__":
    unittest.main()

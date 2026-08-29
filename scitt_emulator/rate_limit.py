# Copyright (c) SCITT Authors
# Licensed under the MIT License.
"""
Rate limiting, as required by Section 5.3 of draft-ietf-scitt-scrapi-11:

    When a client exceeds the configured rate limit, the Transparency Service
    MUST return a 429 response (see Section 2.3.4) including a Retry-After
    header field.

The specific per-client policy is implementation dependent. This is a fixed
window counter keyed per client, which is enough for an emulator to exercise
the 429 path; a production service would want something that degrades more
gracefully at a window boundary.
"""

import threading
import time
from typing import Optional


class RateLimiter:
    """
    A fixed window request counter.

    The first two requests are within the limit, so nothing is returned. The
    third exceeds it and yields the Retry-After to send with the 429. The
    clock is injected here so the returned interval is deterministic.

    >>> clock = iter([0, 0, 0, 0, 61, 61])
    >>> limiter = RateLimiter(requests=2, period=60, now=lambda: next(clock))
    >>> limiter.check("client") is None
    True
    >>> limiter.check("client") is None
    True
    >>> limiter.check("client")
    61

    A different client has its own window.

    >>> limiter.check("other") is None
    True

    Once the window has passed, the client is allowed again.

    >>> limiter.check("client") is None
    True
    """

    def __init__(self, requests: int, period: float, now=time.monotonic):
        self.requests = requests
        self.period = period
        self._now = now
        self._lock = threading.Lock()
        # client -> (window start, requests seen in this window)
        self._windows = {}

    def check(self, client: str) -> Optional[int]:
        """
        Record a request from ``client``.

        Returns None when the request is within the limit, or the number of
        whole seconds after which the client may retry when it is not. The
        return value is the Retry-After that Section 5.3 requires to
        accompany the 429.
        """
        if self.requests <= 0:
            return int(self.period)

        now = self._now()
        with self._lock:
            window_start, count = self._windows.get(client, (now, 0))
            if now - window_start >= self.period:
                window_start, count = now, 0
            count += 1
            self._windows[client] = (window_start, count)

            if count <= self.requests:
                return None
            # Section 5.2: communicate a minimum retry interval. Round up, so
            # a client that waits exactly this long is inside the next window.
            return max(1, int(self.period - (now - window_start)) + 1)


def client_identity(remote_addr: Optional[str], authorization: Optional[str]) -> str:
    """
    The key a rate limit is applied per.

    Section 5.3: the policy "typically varies with whether and how clients are
    authenticated (e.g., per-identity for authenticated clients versus per
    source IP for unauthenticated clients)".

    >>> client_identity("198.51.100.4", None)
    'ip:198.51.100.4'
    >>> client_identity("198.51.100.4", "Bearer token-value")
    'bearer:token-value'
    """
    if authorization:
        scheme, _, credentials = authorization.partition(" ")
        if credentials:
            return f"{scheme.lower()}:{credentials}"
    return f"ip:{remote_addr or 'unknown'}"

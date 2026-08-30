# Copyright (c) SCITT Authors
# Licensed under the MIT License.
"""
Section 5 of draft-ietf-scitt-scrapi-11, Operational Considerations.
"""
import statistics
import time

import cbor2
import httpx
import pytest

from scitt_emulator.client import (
    HTTP_MAX_RETRY_AFTER_WAIT,
    HTTP_MAX_RETRY_DELAY,
    HttpClient,
    retry_delay,
    worth_retrying,
)
from scitt_emulator.errors import CONTENT_TYPE as PROBLEM_DETAILS_CONTENT_TYPE
from scitt_emulator.rate_limit import RateLimiter, client_identity

from tests.test_cli import Service


@pytest.fixture
def rate_limited_service(tmp_path):
    with Service(
        {
            "workspace": tmp_path / "workspace",
            "error_rate": 0,
            "use_lro": False,
            "rate_limit_requests": 3,
            "rate_limit_period": 60,
        }
    ) as service:
        yield service


def test_exceeding_the_rate_limit_returns_429(rate_limited_service):
    """
    Section 5.3: "When a client exceeds the configured rate limit, the
    Transparency Service MUST return a 429 response (see Section 2.3.4)
    including a Retry-After header field."
    """
    url = f"{rate_limited_service.url}/.well-known/scitt-keys"

    for _ in range(3):
        assert httpx.get(url).status_code == 200

    response = httpx.get(url)

    assert response.status_code == 429
    assert response.headers["Retry-After"]
    assert int(response.headers["Retry-After"]) > 0


def test_429_body_is_concise_problem_details(rate_limited_service):
    """
    Section 2.3.4 gives the shape: title "Too Many Requests" and a detail
    naming the limit.
    """
    url = f"{rate_limited_service.url}/.well-known/scitt-keys"
    for _ in range(3):
        httpx.get(url)

    response = httpx.get(url)

    assert (
        response.headers["content-type"].split(";")[0].strip()
        == PROBLEM_DETAILS_CONTENT_TYPE
    )
    problem_details = cbor2.loads(response.content)
    assert problem_details[-1] == "Too Many Requests"
    assert "3 requests per 60 seconds" in problem_details[-2]


def test_rate_limit_is_per_client(rate_limited_service):
    """
    Section 5.3: the policy "typically varies with whether and how clients are
    authenticated (e.g., per-identity for authenticated clients versus per
    source IP for unauthenticated clients)".
    """
    url = f"{rate_limited_service.url}/.well-known/scitt-keys"

    for _ in range(4):
        httpx.get(url, headers={"Authorization": "Bearer first"})

    # The first client is now limited; a different bearer token is not.
    assert httpx.get(url, headers={"Authorization": "Bearer first"}).status_code == 429
    assert httpx.get(url, headers={"Authorization": "Bearer second"}).status_code == 200


def test_client_retries_a_429_and_succeeds(tmp_path):
    """
    Section 5.1: the client honors Retry-After as a minimum interval and
    retries, rather than surfacing a 429 the service asked it to wait out.

    A short window here so the retry lands inside the test.
    """
    with Service(
        {
            "workspace": tmp_path / "workspace",
            "error_rate": 0,
            "use_lro": False,
            "rate_limit_requests": 3,
            "rate_limit_period": 1,
        }
    ) as service:
        url = f"{service.url}/.well-known/scitt-keys"
        client = HttpClient()

        for _ in range(3):
            client.get(url)

        # This request is over the limit. The client waits out Retry-After and
        # retries, so it returns a Receipt rather than raising.
        response = client.get(url)

        assert response.status_code == 200


def test_client_does_not_sleep_through_a_long_retry_after(rate_limited_service):
    """
    Section 5.1 constrains a client that retries; it does not oblige one to
    retry. A service asking for a longer wait than the client will block for
    is reported, so the caller decides whether to come back, rather than the
    client sleeping through it.
    """
    url = f"{rate_limited_service.url}/.well-known/scitt-keys"
    client = HttpClient()

    for _ in range(3):
        client.get(url)

    # The window here is 60 seconds, well over HTTP_MAX_RETRY_AFTER_WAIT.
    started = time.monotonic()
    with pytest.raises(RuntimeError, match="429"):
        client.get(url)
    elapsed = time.monotonic() - started

    assert elapsed < HTTP_MAX_RETRY_AFTER_WAIT


def test_worth_retrying():
    # Not a retriable status.
    assert not worth_retrying(httpx.Response(status_code=404))
    # Retriable, no Retry-After: back off and retry.
    assert worth_retrying(httpx.Response(status_code=503))
    # Retriable, a wait this client will sit through.
    assert worth_retrying(
        httpx.Response(status_code=429, headers={"Retry-After": "5"})
    )
    # Longer than this client will block for.
    assert not worth_retrying(
        httpx.Response(
            status_code=429,
            headers={"Retry-After": str(HTTP_MAX_RETRY_AFTER_WAIT + 1)},
        )
    )


def test_rate_limiting_is_off_by_default(tmp_path):
    with Service(
        {
            "workspace": tmp_path / "workspace",
            "error_rate": 0,
            "use_lro": False,
        }
    ) as service:
        url = f"{service.url}/.well-known/scitt-keys"
        for _ in range(20):
            assert httpx.get(url).status_code == 200


# Section 5.1, Client Retry Behavior


def response_with(headers=None):
    return httpx.Response(status_code=429, headers=headers or {})


def test_retry_delay_honors_retry_after():
    """
    Section 5.1: "Clients that retry a request MUST honor any Retry-After
    header field ... treating it as a minimum interval before retrying."
    """
    assert retry_delay(response_with({"Retry-After": "7"}), 0) == 7
    assert retry_delay(response_with({"Retry-After": "7"}), 5) == 7


def test_retry_delay_backs_off_exponentially_without_retry_after():
    """
    Section 5.1: "In its absence, clients that retry a request MUST apply
    exponential backoff with jitter, cap the total number of retries, and
    avoid synchronizing retries across clients."
    """
    # Full jitter, so each delay is bounded by a doubling backoff.
    for attempt in range(6):
        bound = min(2 ** attempt, HTTP_MAX_RETRY_DELAY)
        for _ in range(20):
            delay = retry_delay(response_with(), attempt)
            assert 0 <= delay <= bound


def test_retry_delay_is_jittered():
    """
    Jitter is what stops clients synchronizing their retries; a fixed delay
    would put every client back on the service at the same instant.
    """
    delays = [retry_delay(response_with(), 4) for _ in range(50)]

    assert len(set(delays)) > 1
    assert statistics.stdev(delays) > 0


def test_retry_delay_is_capped():
    assert retry_delay(response_with(), 100) <= HTTP_MAX_RETRY_DELAY


def test_retry_delay_falls_back_on_an_http_date_retry_after():
    """
    Retry-After may be an HTTP-date, which this client does not parse. It must
    back off rather than retrying immediately.
    """
    delay = retry_delay(
        response_with({"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"}), 3
    )

    assert 0 <= delay <= 8


def test_client_identity_prefers_the_authenticated_identity():
    assert client_identity("198.51.100.4", None) == "ip:198.51.100.4"
    assert client_identity("198.51.100.4", "Bearer abc") == "bearer:abc"
    # Two source addresses presenting one token are one client.
    assert client_identity("198.51.100.4", "Bearer abc") == client_identity(
        "203.0.113.9", "Bearer abc"
    )


def test_rate_limiter_window_resets():
    clock = [0.0]
    limiter = RateLimiter(requests=2, period=10, now=lambda: clock[0])

    assert limiter.check("c") is None
    assert limiter.check("c") is None
    assert limiter.check("c") is not None

    clock[0] = 10.1
    assert limiter.check("c") is None

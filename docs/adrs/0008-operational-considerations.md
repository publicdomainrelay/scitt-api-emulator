# 8. Implement Section 5, Operational Considerations

Date: 2026-08-29

## Status

Accepted

## Context

Section 5 of [draft-ietf-scitt-scrapi-11][scrapi] is new in `-11`; it did not
exist in `-09`. The alignment work in ADRs 0002 to 0005 read Section 2
carefully and did not read Section 5, so a normative requirement was missed.

**Section 5.3, Rate Limiting:**

> As noted in Section 4.3 and Section 4.4.1.1, rate limiting or other
> denial-of-service mitigations are required. [...] When a client exceeds the
> configured rate limit, the Transparency Service **MUST** return a 429
> response (see Section 2.3.4) including a Retry-After header field.

`grep -n 429 scitt_emulator/*.py` returned nothing. Section 2.3.4 was read
during the earlier work and its `429` was taken as optional politeness — it is
introduced there with "MAY, in addition to implementing rate limiting" — but
Section 5.3 is where the obligation actually lands, and Section 2.3.4 is what
it points at for the shape.

**Section 5.1, Client Retry Behavior**, imposes requirements on clients:

> Clients that retry a request MUST honor any Retry-After header field [...]
> treating it as a minimum interval before retrying. In its absence, clients
> that retry a request MUST apply exponential backoff with jitter, cap the
> total number of retries, and avoid synchronizing retries across clients.

The bundled client did none of the three. `_request` retried `503` with a
fixed one second fallback delay — no backoff, no jitter — and `submit_claim`'s
polling loop was `while receipt is None:`, uncapped, with the same fixed
delay. Neither handled `429` at all, which Section 2.3.4 explicitly
contemplates for a client polling too frequently; `raise_for_status` simply
raised.

## Decision

**Implement rate limiting as a fixed window counter**, off by default and
enabled with `--rate-limit-requests` / `--rate-limit-period`. Exceeding it
returns the `429` of Section 2.3.4 — Concise Problem Details, title "Too Many
Requests", detail naming the limit — with `Retry-After` set to the remainder
of the window, which is also the Section 5.2 guidance to communicate a minimum
retry interval.

Off by default because the emulator's purpose is interoperability testing, and
a limit that fires during someone's test run is worse than no limit. What
matters is that the `429` path exists and can be exercised deliberately. A
fixed window is a crude algorithm that lets a client burst across a window
boundary; that is acceptable here for the same reason.

**Key the limit per client**, by bearer token where there is one and by source
address otherwise, following Section 5.3's note that the policy "typically
varies with whether and how clients are authenticated".

**Give the client real backoff.** `retry_delay` honors `Retry-After` as a
minimum when the service sends one it can parse, and otherwise applies a
doubling backoff with full jitter, capped. Full jitter — a uniform draw over
`[0, backoff]` rather than a fixed delay — is what satisfies "avoid
synchronizing retries across clients"; a deterministic backoff puts every
retrying client back on the service at the same instant. The registration
polling loop is capped and reports rather than looping forever, and `429`
joins `503` as retriable.

**Decline to retry a wait this client will not sit through.** Section 5.1
constrains a client that retries; it does not oblige one to retry. Honoring
`Retry-After` as a *minimum* means never sleeping less than asked, not
sleeping arbitrarily long. A `Retry-After` beyond `HTTP_MAX_RETRY_AFTER_WAIT`
is reported to the caller, who decides whether to come back. Without this the
client blocks for the whole window — the first version of this change made the
test suite take 66 seconds, which is the same defect a user would hit.

`Retry-After` may also be an HTTP-date. This client does not parse that form
and backs off instead of retrying immediately, which is the safe reading.

## Consequences

* The emulator can now exercise the `429` path of Section 2.3.4, and a client
  built against it can be tested for the Section 5.1 behaviour.
* Rate limiting is per-process. Running the emulator under a multi-process
  WSGI server gives each worker its own counter, so the effective limit is the
  configured one times the worker count. Acceptable for an emulator; a real
  service needs shared state.
* The client's retry behaviour is now nondeterministic by design. Tests assert
  the bound and the spread rather than exact delays.
* Sections 4.3 and 4.4.1.1, which Section 5.3 cites, cover a wider threat
  model — authentication and DoS mitigation generally. Only the rate limiting
  obligation is implemented here. Authentication remains out of scope for the
  emulator, as it has always been.

[scrapi]: https://datatracker.ietf.org/doc/draft-ietf-scitt-scrapi/11/

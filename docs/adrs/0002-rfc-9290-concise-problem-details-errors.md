# 2. Use RFC 9290 Concise Problem Details for error responses

Date: 2026-08-29

## Status

Accepted

## Context

The emulator returns errors as JSON objects carrying an error URN:

```json
{"type": "urn:ietf:params:scitt:error:entryNotFound", "detail": "Entry 1 not found"}
```

That shape came from an early SCRAPI revision. Section 2 of
[draft-ietf-scitt-scrapi-11][scrapi] now states that when a Transparency
Service cannot process a request it MUST return a 4xx or 5xx status and the
body MUST be a Concise Problem Details object [RFC 9290], served as
`application/concise-problem-details+cbor`, containing:

* `title` (map key `-1`) — a short human-readable identification of the error,
  suitable for a log message;
* `detail` (map key `-2`) — a longer human-readable description.

The `urn:ietf:params:scitt:error:*` namespace no longer appears in the
document. The draft's rationale for CBOR rather than RFC 9457 JSON problem
details is that SCRAPI resources already speak CBOR and COSE, so Concise
Problem Details avoids mixing CBOR and JSON in a single implementation.

The draft also directs clients to treat unrecognized status codes by their
class (`1xx`..`5xx`) and to rely on the problem details object rather than the
status code alone to determine the application-level cause.

## Decision

Emit RFC 9290 Concise Problem Details for every error response.

* Errors are CBOR maps with integer keys `-1` (title) and `-2` (detail), served
  as `application/concise-problem-details+cbor`.
* Titles use the wording from the draft where the draft defines an error for
  the condition ("Malformed request", "Not Found", "Rejected", "Bad Signature
  Algorithm", "Too Many Requests"). Section 2 permits another valid RFC 9290
  object where none of the defined errors describes the condition, so
  conditions specific to this emulator get their own title.
* `title` and `detail` are emitted as unadorned CBOR text strings. RFC 9290
  `oltext` permits either unadorned text or a tag 38 language-tagged string;
  the emulator has no language negotiation, and Section 2 says unadorned text
  is interpreted as `en`, which is what the emulator produces.
* The bundled client decodes the problem details object and reports `title` and
  `detail`, falling back to the response's status class when the body is not a
  valid problem details object — matching the client behaviour the draft
  requires.

The old error URNs are not retained. Unlike a resource path, an error body has
no deprecation story worth the complexity: a client that understood the old
shape cannot act on both, and the URN namespace it referenced no longer exists
in the specification.

## Consequences

* Error bodies are CBOR, not JSON. Anything scraping the emulator's errors with
  a JSON parser breaks and must be updated; `cbor2` is already a dependency.
* Error identification is now by human-readable title rather than by a
  machine-readable URN. This is a loss of precision for programmatic handling,
  and it is what the draft specifies. RFC 9290 does define a `Custom Problem
  Detail` extension mechanism, which a future revision of the draft (or this
  emulator) could use to reintroduce machine-readable error identifiers.
* The `Retry-After` header remains available on error responses, as Section 2
  permits, and is still emitted for `503` and for in-progress polling.

[scrapi]: https://datatracker.ietf.org/doc/draft-ietf-scitt-scrapi/11/

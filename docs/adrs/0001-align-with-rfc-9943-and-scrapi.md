# 1. Align the emulator with RFC 9943 and draft-ietf-scitt-scrapi-11

Date: 2026-08-29

## Status

Accepted

## Context

The SCITT Architecture was published as [RFC 9943][rfc9943] ("An Architecture
for Trustworthy and Transparent Digital Supply Chains") from
`draft-ietf-scitt-architecture-22`. The companion API document,
[SCITT Reference APIs (SCRAPI)][scrapi], is at `draft-ietf-scitt-scrapi-11`
(26 June 2026) and is still a work in progress.

This emulator's HTTP surface tracks an early SCRAPI revision — roughly the
`draft-ietf-scitt-scrapi-01`/`-02` era. Between then and `-11` the document was
substantially reduced in scope and reshaped. The resources that survived were
renamed or given different semantics, and several resources the emulator
implements were removed from the specification entirely.

### Where the emulator is, versus SCRAPI `-11`

| Area | Emulator today | SCRAPI `-11` |
| ---- | -------------- | ------------ |
| Error responses | JSON `{"type": "urn:ietf:params:scitt:error:*", "detail": ...}` | RFC 9290 Concise Problem Details CBOR (`application/concise-problem-details+cbor`), map keys `-1` (title) and `-2` (detail) |
| Key discovery | `GET /.well-known/transparency-configuration` returning JSON with an embedded JWKS | `GET /.well-known/scitt-keys` returning a COSE Key Set as `application/cbor` (Section 2.1) |
| Individual key | none | `GET /.well-known/scitt-keys/{kid_value}` returning a single COSE Key (Section 2.2) |
| Registration | `POST /entries` returning a JSON `{"entryId": ...}` or a JSON operation object | `POST /entries` returning `201` with the Receipt as `application/cose`, or `202` with a `Location` header (Section 2.3) |
| Async polling | `GET /operations/{operationId}` returning a JSON operation object | polling the Receipt resource itself; `200` Receipt / `204` running / `404` not found (Section 2.4) |
| Receipt retrieval | `GET /entries/{entryId}/receipt` returning bespoke CBOR `[protected, contents]` | `GET /entries/{entryId}` returning a COSE Sign1 Receipt (Section 2.4) |
| Receipt format | bespoke CCF countersignature structure | COSE Sign1 with Verifiable Data Structure (`395`) and proofs (`396`) headers, per RFC 9942 and Section 7 of RFC 9943 |
| Statement CWT Claims label | `14` | `15`, per RFC 9597 and Figure 3 of RFC 9943 |

Notably, `-11` no longer defines a nonce endpoint, a registration policy
resource, an issuer/configuration document, or the `urn:ietf:params:scitt:*`
error URN namespace that this emulator emits.

## Decision

Align the emulator with RFC 9943 and SCRAPI `-11`, in a sequence of stacked
changes, each of which leaves the emulator working end to end:

1. **Errors** — adopt RFC 9290 Concise Problem Details. See [ADR 0002](0002-rfc-9290-concise-problem-details-errors.md).
2. **Key discovery** — add `/.well-known/scitt-keys` and
   `/.well-known/scitt-keys/{kid_value}`.
3. **Registration and Receipt resolution** — reshape `POST /entries` and make
   `GET /entries/{entryId}` the Receipt resource with `200`/`204`/`404`.
4. **Receipt and Statement formats** — COSE Sign1 Receipts carrying RFC 9162
   inclusion proofs, and the RFC 9597 CWT Claims label.

Where a legacy resource is still useful to existing users of this emulator, it
is kept and marked deprecated rather than removed outright, so that a single
change does not break every downstream consumer at once. Deprecated resources
are removed once the specification is published as an RFC.

## Consequences

* The emulator becomes a usable interoperability target for implementations
  written against current SCRAPI, which is the stated purpose of this
  repository.
* Clients written against the emulator's older JSON surface need updating. The
  bundled client is updated in step with the server in each change.
* SCRAPI is not yet an RFC. Further revisions will require further alignment
  work; this ADR series records where each decision came from so that the next
  round can tell "we chose this" from "the draft said this".
* The receipt format change (step 4) is the deepest. The existing `CCF` tree
  algorithm produces a structure with no counterpart in the current documents,
  so it is left in place and a specification-conformant algorithm is added
  alongside it rather than replacing it.

[rfc9943]: https://www.rfc-editor.org/rfc/rfc9943.html
[scrapi]: https://datatracker.ietf.org/doc/draft-ietf-scitt-scrapi/11/

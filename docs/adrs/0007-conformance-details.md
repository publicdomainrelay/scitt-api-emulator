# 7. Close the remaining format and identifier conformance gaps

Date: 2026-08-29

## Status

Accepted

## Context

A requirement-by-requirement audit of [ADRs 0002 to 0005](README.md) against
[draft-ietf-scitt-scrapi-11][scrapi] Section 2 and RFC 9943 Sections 6 and 7
found five gaps that the implementation had missed, plus two robustness
defects in the code that reads untrusted input.

**The thumbprint encoding was not the one RFC 9679 requires.**
`cose_key_thumbprint` used `cbor2.dumps(..., canonical=True)` with a comment
claiming it was the deterministic encoding of Section 4.2.1 of RFC 8949. It is
not. cbor2 implements the RFC 7049 canonical ordering, which Section 4.2.3 of
RFC 8949 describes as "length-first" and explicitly distinguishes from Section
4.2.1's bytewise ordering on the encoded key. They differ as soon as two keys
encode to different widths:

    {1, 10, 100, -1, -2, -100}
    cbor2 canonical:   [1, 10, -1, -2, 100, -100]
    RFC 8949 4.2.1:    [1, 10, 100, -1, -2, -100]

Today's thumbprints happen to be correct, because the required members of an
EC2 key are labels `1, -1, -2, -3`, all one byte. The comment was the real
hazard: it asserted a property the code did not have, for anyone adding a key
type or label outside that range.

**Receipts could omit the Subject Claim.** Section 6 of RFC 9943 says the CWT
Claims value "MUST include the Issuer Claim (Claim label 1) and the Subject
Claim (Claim label 2)". `_sign_receipt` set `iss` unconditionally but added
`sub` only if the submitted statement had one, and validation checked only
that label 15 was *present*. A statement with `15: {}` registered fine and
produced a non-conformant Receipt.

**The kid resolution order let the raw form shadow the base64url form.**
`get_scitt_key` tried the raw kid first and returned the first hit. Section 2.2
makes base64url the form that MUST resolve for *every* kid, while the raw kid
is only accepted where it is URI-safe. With two keys whose raw and base64url
forms collide, the raw-kid key won and the other key's mandatory form was
unreachable. Section 2.2 also forbids such a key set outright — "A Transparency
Service MUST NOT use kid values whose raw and base64url forms would make the
same URL identify different keys" — and nothing checked it.

**Signed Statements carried `394: nil` and a label that no longer exists.**
Figure 3 of RFC 9943 types label 394 as `[+ bstr .cbor Receipt]`; `nil` is not
that, and the `* label => any` escape does not rescue a named entry with a
fixed type. Separately, label 393 (`Reg_Info`) appears **nowhere** in RFC 9943
or SCRAPI — the only "393" in either document is a citation of RFC 9393
(CoSWID). It came from an earlier architecture draft.

**The statement URN kept its base64url padding**, where `cose_keys` correctly
strips it.

Two robustness defects in the same area: `decode_problem_details` indexed a
tag 38 value without checking it is the two element array Appendix A of
RFC 9290 defines, so a malformed error body raised `IndexError`/`TypeError`
past the `ValueError` its caller catches — defeating the documented fallback
to status-class semantics — or silently indexed a *string* and reported one
character as the title. And `base64url_decode` ran with `validate=False`, so
characters outside the alphabet were discarded rather than rejected and
`"!!!!"` decoded to `b""`.

## Decision

* Implement the Section 4.2.1 encoding directly as `deterministic_dumps`, and
  delete the false comment. The doctest shows the two orderings differing so
  the distinction is not lost again. The implementation is checked against
  RFC 9679's own example vector, which it reproduces exactly.
* Require `iss` and `sub` in a Signed Statement's CWT Claims at registration,
  and always copy `sub` into the Receipt. A statement that cannot yield a
  conformant Receipt is rejected rather than producing one.
* Try the base64url form first in `get_scitt_key`, and enforce Section 2.2's
  prohibition in `keys_as_cose_key_set` via
  `check_key_identifiers_unambiguous`, so a tree algorithm assigning its own
  kids cannot publish an ambiguous key set. Enforcing at the source is what
  makes accepting both forms safe.
* Omit label 394 when there are no Receipts, drop `Reg_Info` entirely, and
  strip the URN's padding.
* Validate the shape of a tag 38 value, and reject non-alphabet input in
  `base64url_decode`. Guard `jwk_to_cose_key` against a JWK missing its
  coordinates, which previously produced a COSE key with empty coordinates
  and a perfectly well-formed thumbprint.

## Consequences

* Signed Statements change shape again: no `393`, no `394: nil`. Combined with
  [ADR 0005](0005-cose-receipts.md), a statement from before this series is
  not accepted by it. The emulator exists to be an interoperability target for
  the current documents, and it now emits exactly the protected header of
  Figure 5 — `{1, 3, 4, 15}` — with an empty unprotected header.
* Rejecting a statement without `iss`/`sub` is stricter than before. It is
  what Section 6 requires, and a Receipt is the thing that would otherwise be
  non-conformant.
* A padded base64url kid now 404s rather than resolving. Two URLs identifying
  one key is not a violation of a server MUST, but it is not what Section 2.2
  describes.
* `deterministic_dumps` is used for the thumbprint. The Receipt protected
  header still uses `cbor2.dumps(canonical=True)`; its labels are `1, 4, 15,
  395`, and COSE does not require deterministic encoding of a protected header
  — the bytes are signed as they appear, so any encoding verifies. Left as is
  deliberately, rather than changed for the appearance of consistency.

[scrapi]: https://datatracker.ietf.org/doc/draft-ietf-scitt-scrapi/11/

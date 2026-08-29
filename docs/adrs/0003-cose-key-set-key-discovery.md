# 3. Discover Receipt verification keys as a COSE Key Set

Date: 2026-08-29

## Status

Accepted

## Context

The emulator publishes its Receipt verification keys at
`GET /.well-known/transparency-configuration`, as a JSON document with an
embedded JWKS alongside an `issuer`, a `registration_endpoint`, a
`nonce_endpoint`, a `registration_policy` pointing at `/statements/TODO`, and a
`supported_signature_algorithms` list.

That resource came from an early SCRAPI revision. It does not appear in
[draft-ietf-scitt-scrapi-11][scrapi] in any form, and neither do the nonce
endpoint nor the registration policy resource it advertises. What `-11` defines
instead is:

* **Section 2.1, Transparency Service Keys** — `GET /.well-known/scitt-keys`
  (registered per RFC 8615), which MUST respond with a COSE Key Set, as defined
  in Section 7 of RFC 9052, serialized as `application/cbor`.
* **Section 2.2, Individual Transparency Service Key** —
  `GET /.well-known/scitt-keys/{kid_value}`, which MUST respond with a single
  COSE Key as `application/cbor`, or 404 if no matching key is found.

Section 2.2 also constrains how `{kid_value}` is spelled: the resource MUST
accept the base64url encoding of the kid without padding, and MUST *also*
accept the raw kid when it is safe as a URI path segment without
percent-encoding; both forms identify the same key. It RECOMMENDS deriving the
kid as an [RFC 9679][rfc9679] COSE Key Thumbprint, so that independent parties
compute the same kid for a given key without an out-of-band assignment process.

The move from JWK to COSE is not cosmetic. Receipts are COSE, so a verifier
that had to parse a JWKS was obliged to carry a JSON key parser purely for
discovery — the same argument the draft makes for Concise Problem Details in
[ADR 0002](0002-rfc-9290-concise-problem-details-errors.md).

## Decision

Serve both resources from `scitt_emulator/server.py`, backed by a new
`scitt_emulator/cose_keys.py`.

* `keys_as_cose_key_set()` is added to `SCITTServiceEmulator` with a default
  implementation that converts the JWKs the tree algorithms already produce.
  Tree algorithms whose keys are natively COSE should override it rather than
  round-tripping through JWK. Doing it this way means the RKVST tree algorithm,
  whose client library is unpublished and which returns an empty key set, needs
  no change.
* The kid is the RFC 9679 COSE Key Thumbprint over the key's required members,
  encoded with the deterministic encoding of Section 4.2.1 of RFC 8949 and
  hashed with SHA-256. `cbor2`'s canonical encoding is that deterministic
  encoding.
* The kid is raw thumbprint bytes, matching the `bstr` type COSE gives `kid`.
  Raw thumbprint bytes are not safe as a URI path segment, so in practice only
  the base64url form appears in URLs. The server still accepts a raw kid when
  one is URI-safe, so a tree algorithm that assigns text kids works without
  further change.
* `/.well-known/transparency-configuration` is retained, serving the same
  document, with a `Deprecation: true` header and a `Link` header pointing at
  `/.well-known/scitt-keys` as its successor. The SCRAPI key loader tries
  `/.well-known/scitt-keys` first and falls back to it, so this emulator can
  still resolve keys from a Transparency Service that has not been updated.

Key retirement (the `Expires`/`Cache-Control` guidance and the retention
requirements in Section 2.1) is not implemented. The emulator holds a single
service key for the lifetime of a workspace and never rotates it, so there is
no retired key to retain and no cache lifetime worth advertising. This is a
gap, recorded here rather than papered over: an emulator that grew key rotation
would need to serve retired keys from the Section 2.2 resource for as long as
Receipts signed with them may need verifying.

## Consequences

* Verifiers can discover keys with a CBOR parser alone.
* kids are reproducible from the key material, so two implementations of this
  emulator over the same key agree on the kid without coordination.
* Only EC2 keys convert. The emulator's tree algorithms sign with ES256, so
  this covers everything they produce; a non-EC key raises
  `UnsupportedKeyTypeError` rather than emitting a malformed COSE Key.
* Consumers still reading `transparency-configuration` keep working, but are
  reading a resource that no longer exists in the specification. It is removed
  once SCRAPI is published as an RFC.

[scrapi]: https://datatracker.ietf.org/doc/draft-ietf-scitt-scrapi/11/
[rfc9679]: https://www.rfc-editor.org/rfc/rfc9679.html

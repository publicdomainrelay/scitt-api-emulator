# 5. Issue COSE Sign1 Receipts carrying RFC 9162 inclusion proofs

Date: 2026-08-29

## Status

Accepted

## Context

Section 7 of [RFC 9943][rfc9943] specifies what a Receipt is:

> Receipts are based on signed proofs as described in COSE Receipts [RFC 9942][rfc9942],
> which also provides the COSE header parameter semantics for label 394.

Figures 9, 10, and 11 show the shape. A Receipt is a tagged `COSE_Sign1` whose

* protected header carries the algorithm (1), key identifier (4), the
  Verifiable Data Structure (395) — `1` for `RFC9162_SHA256` — and CWT Claims
  (15) naming the Transparency Service as `iss` and the artifact as `sub`;
* unprotected header carries Proofs (396), with inclusion proofs at label `-1`,
  each a `bstr .cbor` holding `[tree size, leaf index, [intermediate hashes]]`;
* payload is detached — RFC 9942 makes it the Verifiable Data Structure root,
  which a verifier reconstructs from the leaf and the proof.

Adding a Receipt to a Signed Statement's unprotected header under label 394
produces a Transparent Statement.

The emulator's `CCF` tree algorithm produces none of that. It builds a
`CounterSignatureV2` structure over the Signed Statement, signs a Merkle root
padded out with 63 `dummy-envelope-N` leaves, and emits a bare CBOR array
`[protected, [signature, node_cert_der, proof, leaf_info]]`. It predates COSE
Receipts and has no counterpart in the current documents. The emulator also had
two format problems in Signed Statements themselves:

* **CWT Claims sat at label 14.** Figure 3 of RFC 9943 requires label 15, which
  [RFC 9597][rfc9597] registered for CWT Claims in the COSE Header Parameters
  registry. Label 14 was a placeholder from before that registration.
* **The CWT Claims value was a nested, separately signed CWT.** RFC 9597
  defines the value of the CWT Claims header parameter as a CWT Claims Set — a
  plain map of claim key to value — and Figure 5 of RFC 9943 shows it that way.
  The emulator ran the claims through `cwt.encode`, producing a second signed
  COSE structure nested inside the protected header of the first.

## Decision

**Add an `RFC9162_SHA256` tree algorithm** in
`scitt_emulator/rfc9162_sha256.py`, and make it the first entry in
`TREE_ALGS`. It maintains an RFC 9162 Merkle tree (`SHA-256(0x00 || leaf)` for
leaves, `SHA-256(0x01 || left || right)` for interior nodes) over the
registered Signed Statements, and issues Receipts in the shape above. Leaf
hashes are persisted in registration order, which is enough to recompute any
root or inclusion proof.

**Leave `CCF` in place, and do not rewrite it.** It remains selectable for
anyone testing against the structure it produces, and the two algorithms do not
interfere. Rewriting it would mean changing what `CCF` means rather than adding
what the specification describes.

**Move CWT Claims to label 15 and make the value a plain CWT Claims Set.**
Reading the issuer no longer means decoding a nested COSE structure — it is a
map lookup. This does not weaken anything: `verify_statement` always read the
issuer from the *unverified* nested CWT in order to decide which keys to try,
and the signature that is actually checked is the outer `COSE_Sign1`, which
protects the claims either way.

**Verify from the public key alone.** The service's public COSE Key is written
into `service_parameters.json` at initialization, so `verify-receipt` works
against the service parameters without the private key. Verification
reconstructs the root from the leaf and the inclusion proof, checks the `kid`
against the thumbprint of the key held, and then checks the `COSE_Sign1`
signature over the RFC 9052 Section 4.4 `Sig_structure` with the reconstructed
root as the detached payload.

## Consequences

* Receipts from the `RFC9162_SHA256` algorithm are COSE, verifiable by any
  RFC 9942 implementation, and their `kid` resolves through the key discovery
  resource added in [ADR 0003](0003-cose-key-set-key-discovery.md). That
  round trip is covered by a test.
* Signed Statements produced by `create-claim` are not interchangeable with
  those produced before this change: the CWT Claims label moved, and the value
  is a different structure. Statements created by the old code will be rejected
  for lacking a label 15 header parameter. This is the format the specification
  describes, and the emulator exists to be an interoperability target for it.
* Receipts are issued once, at registration, proving inclusion in the tree as
  it stood at that moment. Section 2.1 of SCRAPI contemplates a client
  requesting a *fresh* Receipt for the same Signed Statement at the same
  position — signed with a current key, and against a larger tree. The emulator
  does not re-issue; it serves the stored Receipt. Doing so would need the
  Receipt to be generated on read rather than stored, which is a change to the
  storage model rather than to the format, and is left for a later change.
* Consistency proofs (label `-2`) are not issued. Nothing in RFC 9943 or SCRAPI
  requires a Receipt to carry one, and the emulator has no client for them yet.
* The `TBD` header attribute (395) in `create_statement.py` was being written
  into Signed Statements' unprotected header with the literal value `"TBD"`. It
  is now `VDS`, with the meaning RFC 9942 gives it, and it is no longer written
  into Signed Statements — it belongs in a Receipt's protected header. A
  `Proofs` attribute (396) is added alongside it.

[rfc9943]: https://www.rfc-editor.org/rfc/rfc9943.html
[rfc9597]: https://www.rfc-editor.org/rfc/rfc9597.html
[rfc9942]: https://www.rfc-editor.org/rfc/rfc9942.html

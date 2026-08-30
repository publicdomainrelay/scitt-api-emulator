# 9. Verify Signed Statement signatures at registration

Date: 2026-08-29

## Status

Accepted

## Context

Section 6.3 of [RFC 9943][rfc9943] is explicit about what a Transparency
Service must do with a Signed Statement before recording it:

> The TS MUST perform signature verification per Section 4.4 of RFC 9052
> [STD96] and MUST verify the signature of the Signed Statement with the
> signature algorithm and verification key of the Issuer per [RFC9360].

The emulator has never done this. Its stated behaviour, in its own code, is
that it does not verify the claim signature and does not apply registration
policies; verification is left to the external Registration Policy, which the
policy engine plugin implements. Because verification never ran, the three
registration-time errors
of Section 2.3.3 of [draft-ietf-scitt-scrapi-11][scrapi] that depend on it were
unreachable:

* **"Bad Signature Algorithm"** — no algorithm was ever checked;
* **"Payload Missing"** — a detached-payload statement was accepted;
* **"Rejected"** — no path produced it.

(An emulator with the permissive default insert policy was *defined* to accept
anything, so this was internally consistent. It was also not a Transparency
Service that Section 6.3 describes.)

A review of the emulator also turned up a regression in the COSE Key Set key
discovery: a key resolved from `/.well-known/scitt-keys` could not be converted
to the JWK object a Registration Policy validates against, so any policy
relying on the current discovery resource failed with "Failed to convert
issuer key to JSON schema verifiable object". The docs test that exercises the
policy engine caught it; nothing else did.

## Decision

**Add a `verifySignature` service setting, on by default only when asked.**
The server gains a `--verify-signature` flag that sets it. When set, the
service verifies each Signed Statement's signature, with the Issuer's key
resolved from the `iss` claim of the CWT Claims, using the same
`verify_statement` machinery the Registration Policy uses.

**Validate at registration time, in both modes.** Section 2.3 requires the
Registration Policy to be applied before any additional processing. The
structural checks now run in `submit_claim`, before either an entry or an
operation is created, so a bad statement gets the 400 of Section 2.3.3 in
synchronous *and* asynchronous mode, rather than being accepted and failing
later. The `400` errors map to the draft's titles: "Payload Missing",
"Bad Signature Algorithm", and "Rejected".

**Keep the permissive default.** The emulator exists for interoperability
testing, and its documented default is that a statement is accepted without a
signature check. `--verify-signature` is the switch that makes it behave as
Section 6.3 describes. The MUST is thereby satisfiable and testable rather
than silently ignored.

**The checks that always run** (cheap, structural, independent of policy):

* a payload must be present — Signed Statements MAY use detached payloads when
  the Transparency Service has access to the payload, and this emulator has no
  mechanism for that, so a detached payload is "Payload Missing";
* the signature algorithm must be one the emulator can verify — ES256, ES384,
  ES512, or EdDSA. Anything else is "Bad Signature Algorithm".

**"Confirmation Missing" is not enforced.** Section 2.3.3 lists it as a SHOULD
for a statement without proof of possession (`cnf`). The emulator's
`create-claim` does not emit a `cnf` claim, and enforcing it would make every
statement this repository produces unregistrable. The error is available to
the server but never raised; ADR records the gap.

**Fix the COSE-to-JWK gap.** Add `to_object_cose_key`, so a key discovered from
`/.well-known/scitt-keys` converts to the JWK object a policy validates. This
is what lets signature verification and the policy engine agree on keys from
the current discovery resource.

* The four failing docs tests that this change also fixed were two regressions
  from this series, one pre-existing unfinished test, and one race.

  * **oidc/ssh/nop deny-path tests** asserted the pre-SCRAPI operation-based
    flow (`ClaimOperationError` with a JSON operation). Registration now polls
    the Receipt resource and a policy denial surfaces as the `404` "Registration
    Failed" of Section 2.4.3. The tests were updated to the new flow.
  * **nop test**: the policy engine's validator could not convert a
    COSE-discovered key (the regression above). Fixed by `to_object_cose_key`.
  * **phase_0 test** referenced a non-existent workload-identity-token endpoint
    and an undefined `client`, and built its OIDC service from a Flask app with
    no routes. The dead lines were removed, the OIDC service now uses the OIDC
    fixture, and the middleware wiring was corrected. It is a genuinely
    unfinished test, now repaired enough to exercise the OIDC middleware path
    it was written for.
  * **Race**: re-registering a failed statement reused the content-derived
    EntryID, and `get_entry_receipt` short-circuited on the stale failure
    record. A re-registration now clears the stale record, and
    `_sync_policy_result` ignores policy files older than the current
    operation file — an external policy engine can have a validation in
    flight when an attempt is torn down, and its late `denied` file must not
    be read as this attempt's outcome.
  * The test server was **single-threaded** (`werkzeug.make_server` default),
    while Flask's own server is threaded. Signature verification resolves the
    Issuer's key by fetching it, which may be the service itself; a
    single-threaded server cannot serve that fetch while handling the request,
    and the request deadlocked. The test fixture now uses a threaded server.

## Consequences

* `--verify-signature` gives the emulator a mode that satisfies RFC 9943
  Section 6.3 and exercises the three Section 2.3.3 errors it unlocks.
* Statements created with an issuer whose key cannot be resolved are still
  accepted by default. With `--verify-signature`, they are rejected, because
  the Issuer's key is unresolvable and the signature cannot be checked.
* Validation at POST means malformed statements are rejected immediately in
  both modes rather than asynchronously; the async `404` of Section 2.4.3 now
  only serves policy failures and log-level rejections.
* The `to_object_cose_key` transform is a new entry point, registered in
  `setup.py` alongside the existing key-to-object transforms.

[scrapi]: https://datatracker.ietf.org/doc/draft-ietf-scitt-scrapi/11/
[rfc9943]: https://www.rfc-editor.org/rfc/rfc9943.html

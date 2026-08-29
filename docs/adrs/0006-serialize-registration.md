# 6. Serialize registration, and make it idempotent on the EntryID

Date: 2026-08-29

## Status

Accepted

## Context

Review of [ADR 0004](0004-registration-and-receipt-resolution.md) and
[ADR 0005](0005-cose-receipts.md) as implemented found that registration
mutates state shared across requests without any synchronization, while the
server is threaded. Four defects followed, all reproduced.

**The Merkle tree race.** `_append_leaf` appended a leaf, then re-read the
whole log to derive the index, and `_create_receipt` then read the log a
*third* time to build the proof. A registration arriving between those reads
shifted the tree underneath. The leaf index, the inclusion proof, and the root
came from three different snapshots, so the Receipt was signed over a proof
that reconstructs a different root. Measured over HTTP with 16 concurrent
registrations: **7 of 16 Receipts returned with `201` did not verify**.

This never produced a false proof. The verifier recomputes the root from the
claim's own leaf hash, so a mismatched index simply fails, and a Receipt that
*does* verify really does prove inclusion at the stated index. The damage is
that clients are handed permanently worthless Receipts, silently, with a
success status.

**Concurrent polls of one running registration.** The `polled` flag was a
read-modify-write on a JSON file with no lock, and `_finish_operation`
unlinked files unconditionally. Two polls could both finish the same
operation: one raised `FileNotFoundError` on the second unlink, surfacing as
an HTML `500`, and one entry got **two leaves** because `_create_entry` ran
twice.

**A malformed Signed Statement in asynchronous mode was a permanent `500`.**
Registration validates structure when the leaf is created, which in
asynchronous mode is during a poll, long after the `202`. `ClaimInvalidError`
escaped `resolve_receipt`, which caught only the three registration outcomes.
No failure record was written and the operation was never torn down, so every
subsequent poll raised again, forever.

**Re-registration was not idempotent.** The EntryID is derived from the Signed
Statement, so re-POSTing the same bytes returns the same `Location` — as
Section 2.3.1 of SCRAPI requires — but `_create_receipt` appended another leaf
and overwrote the stored Receipt each time. One EntryID mapped to N leaves,
the resource silently changed which leaf it proved, and any client could grow
the log without bound by replaying one statement.

Separately, Section 2 of SCRAPI says the body of *any* 4xx or 5xx response
MUST be a Concise Problem Details object. Only the resource handlers went
through `make_error`; Flask's own responses for unrouted paths, rejected
methods, and unhandled exceptions were HTML. An EntryID longer than a
filesystem name produced an HTML `500` from an `OSError`.

## Decision

**Serialize the state transitions of registration** behind a
`registration_lock()` on `SCITTServiceEmulator`: appending to the log,
deciding an operation's outcome, and writing a Receipt. It is a
`threading.Lock` for the threaded server, plus an `flock` on a file in the
workspace so the guarantee holds for anyone running the emulator under a
multi-process WSGI server.

**Derive the index, the proof, and the root from one snapshot.**
`_append_leaf` now returns the leaves *including* the new one, rather than an
index the caller re-reads the log to use. The type change is the point: it
makes the single-snapshot property structural rather than something a future
edit has to remember.

**Make `_create_entry` idempotent on the EntryID** — if a Receipt already
exists for it, return it rather than appending another leaf.

**Record an invalid statement as a failed registration.** `get_entry_receipt`
catches `ClaimInvalidError`, writes the failure record, and raises
`RegistrationFailedError`, so the poll becomes the `404` of Section 2.4.3 with
detail and stays that way.

**Convert every error response.** Flask `errorhandler`s for `HTTPException`
and `Exception` return Concise Problem Details, and EntryIDs are validated
against the alphabet the emulator issues before reaching storage, producing
the `400` "Invalid locator" that Section 2.3.3 defines.

**Reject a service key this algorithm cannot sign with.** `RFC9162_SHA256`
signs with ES256, which RFC 9053 ties to P-256, and the P1363 signature
encoding assumes 32-byte coordinates. A key on another curve raised
`OverflowError`; it now raises a typed `UnsupportedServiceKeyError`.

Also: `is_unavailable` used `random.random() <= error_rate`, so
`--error-rate 0` still failed with probability 2⁻⁵³. It is now `<`.

## Consequences

* Registrations are serialized. For an emulator whose purpose is
  interoperability testing this is the right trade: correctness under
  concurrency matters, registration throughput does not. A production
  Transparency Service would want a real append-only log with batched
  signing rather than a global lock.
* `tests/test_concurrency.py` covers all four defects. The previous test suite
  had no concurrency coverage at all, which is why none of this was caught —
  every one of these bugs passed a green suite.
* Idempotent registration is a visible behaviour change: re-registering the
  same Signed Statement now returns the identical Receipt rather than a new
  one proving a later position.
* The `flock` is advisory and POSIX-only. The emulator already assumes a Linux
  environment.

[scrapi]: https://datatracker.ietf.org/doc/draft-ietf-scitt-scrapi/11/
[rfc9053]: https://www.rfc-editor.org/rfc/rfc9053.html
[rfc9162]: https://www.rfc-editor.org/rfc/rfc9162.html

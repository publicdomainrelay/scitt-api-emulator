# 4. Poll the Receipt resource instead of an operation

Date: 2026-08-29

## Status

Accepted

## Context

The emulator's registration flow was built around a long-running operation
resource:

* `POST /entries` returned either `201` with a JSON `{"entryId": ...}` or `202`
  with a JSON operation object and a `Location` naming
  `/operations/{operationId}`.
* `GET /operations/{operationId}` returned a JSON operation object with a
  `status` of `running`, `succeeded`, or `failed`, which the client polled.
* `GET /entries/{entryId}` returned the registered Signed Statement.
* `GET /entries/{entryId}/receipt` returned the Receipt.

[draft-ietf-scitt-scrapi-11][scrapi] has none of that. Operations are gone as a
concept, and there is no resource for reading back a Signed Statement. What
Sections 2.3 and 2.4 define is:

* `POST /entries` returns `201` with the Receipt as `application/cose` when one
  can be produced in reasonable time, or `202` with an empty body when it
  cannot. **Both** carry a `Location` header naming the Receipt resource.
* `GET /entries/{entryId}` *is* the Receipt resource. It returns `200` with the
  Receipt, `204` while registration is still running, or `404` when no Receipt
  exists — including when registration has failed, in which case the problem
  details object MAY be enriched with the reason.

Section 2.3.1 adds a constraint the old design cannot meet:

> Transparency Services that support both synchronous and asynchronous
> registration MUST return the same Location URL for the same registered Signed
> Statement regardless of which registration mode was used.

The emulator assigned an operation a UUID and, separately, gave the eventual
entry a sequential integer ID from a `last_entry_id.txt` counter. The two
modes therefore produced different URLs for the same Signed Statement, and even
within one mode the ID depended on how many statements had been registered
before.

## Decision

**Derive the EntryID from the Signed Statement**: `base64url(sha256(statement))`,
without padding, so it is safe as a URI path segment. This satisfies Section
2.3.1 with no shared state between the two registration paths — both modes
compute the same ID from the same bytes — and it removes the sequential
counter, which was a source of ordering dependence between otherwise unrelated
registrations. The tree algorithm takes the EntryID as opaque data, so nothing
needed a sequential index.

Re-registering the same Signed Statement now resolves to the same EntryID,
which is a behaviour change but a defensible one: the Receipt resource is
specified as being *for* a registered Signed Statement.

**Make `GET /entries/{entryId}` the Receipt resource**, returning `200`/`204`/
`404`, with `Retry-After` and `Cache-Control: no-store` on the `204` as Section
2.4.2 recommends.

**Retain the reason a registration failed.** The old `_finish_operation`
deleted the operation record on failure, so a subsequent poll could not say
why. Section 2.4.3 permits the `404` to carry that detail, so the failure
reason is now written to a `{entryId}.failed.json` record when the operation is
torn down, and surfaced as the `detail` of a "Registration Failed" problem
details object.

**Keep the 204 reachable.** The emulator has always pretended a registration
takes time by finishing an operation only after the client has checked it once.
That pretence moves to the Receipt resource: the first poll of a running
registration returns `204`, and finality is evaluated from the next poll
onward. Without it, the permissive default insert policy would make every
asynchronous registration return `200` on the first poll, and no client would
ever exercise the `204` path.

**Move Signed Statement retrieval to `GET /entries/{entryId}/statement`**, and
mark it as an emulator extension. SCRAPI defines no such resource, but the
bundled client and the interoperability tests need to read back what was
registered, and `/entries/{entryId}` is now the Receipt.

**Remove** `/operations/{operationId}` and `/entries/{entryId}/receipt`.

## Consequences

* The client no longer parses a JSON operation object. It reads the `Location`
  header — which is where SCRAPI puts the EntryID — and polls until `200`.
* Registering the same Signed Statement twice is idempotent in the sense that
  it resolves to the same EntryID and the same Receipt resource.
* The operations directory is keyed by EntryID rather than a UUID. The external
  policy engine documented in `docs/registration_policies.md` watches
  `workspace/storage/operations/*.cose` and writes
  `{stem}.policy.{insert,denied,failed}` beside each, keyed off the filename
  stem whatever it is, so it is unaffected.
* Receipts are served as `application/cose`, which is what Section 2.4 says
  they are. The bytes are COSE Sign1 Receipts carrying RFC 9162 inclusion
  proofs; that is the subject of the next change in this series.

[scrapi]: https://datatracker.ietf.org/doc/draft-ietf-scitt-scrapi/11/

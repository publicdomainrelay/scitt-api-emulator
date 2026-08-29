# Architecture Decision Records

This directory records the decisions taken while aligning this emulator with
the IETF SCITT working group output.

Records are numbered sequentially and never deleted. A record that is
superseded stays in place with its status updated and a pointer to the record
that replaces it.

| ADR | Title | Status |
| --- | ----- | ------ |
| [0001](0001-align-with-rfc-9943-and-scrapi.md) | Align the emulator with RFC 9943 and draft-ietf-scitt-scrapi-11 | Accepted |
| [0002](0002-rfc-9290-concise-problem-details-errors.md) | Use RFC 9290 Concise Problem Details for error responses | Accepted |
| [0003](0003-cose-key-set-key-discovery.md) | Discover Receipt verification keys as a COSE Key Set | Accepted |
| [0004](0004-registration-and-receipt-resolution.md) | Poll the Receipt resource instead of an operation | Accepted |
| [0005](0005-cose-receipts.md) | Issue COSE Sign1 Receipts carrying RFC 9162 inclusion proofs | Accepted |
| [0006](0006-serialize-registration.md) | Serialize registration, and make it idempotent on the EntryID | Accepted |
| [0007](0007-conformance-details.md) | Close the remaining format and identifier conformance gaps | Accepted |
| [0008](0008-operational-considerations.md) | Implement Section 5, Operational Considerations | Accepted |

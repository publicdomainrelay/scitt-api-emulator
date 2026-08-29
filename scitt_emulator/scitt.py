# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

from typing import Optional
from abc import ABC, abstractmethod
from contextlib import contextmanager
from pathlib import Path
from hashlib import sha256
import fcntl
import threading
import time
import json
import uuid

import cbor2
from pycose.messages import Sign1Message
import pycose.headers

from scitt_emulator.cose_keys import (
    COSE_KEY_KID,
    base64url_encode,
    check_key_identifiers_unambiguous,
    jwk_to_cose_key,
)
from scitt_emulator.create_statement import CWTClaims

# temporary receipt header labels, see draft-birkholz-scitt-receipts
COSE_Headers_Service_Id = "service_id"
COSE_Headers_Tree_Alg = "tree_alg"
COSE_Headers_Issued_At = "issued_at"

# permissive insert policy
MOST_PERMISSIVE_INSERT_POLICY = "*"
DEFAULT_INSERT_POLICY = MOST_PERMISSIVE_INSERT_POLICY


class ClaimInvalidError(Exception):
    pass


class PayloadMissingError(ClaimInvalidError):
    """Section 2.3.3 of draft-ietf-scitt-scrapi-11: "Payload Missing"."""


class UnsupportedAlgorithmError(ClaimInvalidError):
    """Section 2.3.3: "Bad Signature Algorithm"."""


class SignatureVerificationError(ClaimInvalidError):
    """Section 2.3.3: "Rejected". The Signed Statement is not accepted."""


# COSE algorithm identifiers the emulator can verify, Section 2.3.3 "Bad
# Signature Algorithm". ES256 (-7), ES384 (-35), ES512 (-36), EdDSA (-8).
SUPPORTED_SIGNATURE_ALGORITHMS = {-7, -35, -36, -8}


class EntryNotFoundError(Exception):
    pass


class OperationNotFoundError(Exception):
    pass


class RegistrationRunningError(Exception):
    """
    Registration of the Signed Statement is still in progress, so no Receipt
    is available yet. Section 2.4.2 of draft-ietf-scitt-scrapi-11 maps this to
    a 204 No Content response.
    """


class RegistrationFailedError(Exception):
    """
    Registration of the Signed Statement failed, so no Receipt will ever be
    produced. Section 2.4.3 of draft-ietf-scitt-scrapi-11 maps this to a 404,
    optionally enriched with detail explaining why registration did not
    complete.
    """


class PolicyResultDecodeError(Exception):
    pass


def entry_id_for_claim(claim: bytes) -> str:
    """
    Derive the EntryID for a Signed Statement.

    Section 2.3.1 of draft-ietf-scitt-scrapi-11 requires that a Transparency
    Service supporting both synchronous and asynchronous registration return
    the same Location URL for the same registered Signed Statement regardless
    of which registration mode was used. Deriving the EntryID from the Signed
    Statement itself satisfies that without any shared state between the two
    paths.

    The result is base64url without padding so that it is safe as a URI path
    segment.

    >>> entry_id_for_claim(b"a signed statement")
    '6jZWRUsucVNMY4twAoE8SPd5w2aISvpeapJ-0SQEmik'
    >>> entry_id_for_claim(b"a signed statement") == entry_id_for_claim(b"a signed statement")
    True
    """
    return base64url_encode(sha256(claim).digest())


def _failure_detail(operation: dict, entry_id: str) -> str:
    error = operation.get("error")
    if isinstance(error, dict):
        detail = error.get("detail")
        if detail:
            return str(detail)
    if error:
        return str(error)
    return f"Signed Statement with entry ID {entry_id} could not be persisted to the log"


class SCITTServiceEmulator(ABC):
    def __init__(
        self, service_parameters_path: Path, storage_path: Optional[Path] = None
    ):
        self.storage_path = storage_path
        self.service_parameters_path = service_parameters_path

        # Registration mutates state that is shared across requests: the
        # operation records here, and the Merkle tree in tree algorithms that
        # keep one. The server is threaded, so those transitions are
        # serialized. The lock file makes this hold across processes too, for
        # anyone running the emulator under a multi-process WSGI server.
        self._registration_lock = threading.Lock()

        if storage_path is not None:
            self.operations_path = storage_path / "operations"
            self.operations_path.mkdir(exist_ok=True)
            self._registration_lock_path = storage_path / ".registration.lock"

        if self.service_parameters_path.exists():
            with open(self.service_parameters_path) as f:
                self.service_parameters = json.load(f)

    @contextmanager
    def registration_lock(self):
        """
        Serialize the state transitions of registration: appending to the log,
        deciding an operation's outcome, and writing a Receipt.
        """
        with self._registration_lock:
            with open(self._registration_lock_path, "a+") as lock_file:
                fcntl.flock(lock_file, fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(lock_file, fcntl.LOCK_UN)

    @abstractmethod
    def initialize_service(self):
        raise NotImplementedError

    @abstractmethod
    def keys_as_jwks(self):
        raise NotImplementedError

    def keys_as_cose_key_set(self) -> list:
        """
        The Transparency Service's Receipt verification keys as a COSE Key Set,
        for the resource defined in Section 2.1 of
        draft-ietf-scitt-scrapi-11.

        Tree algorithms currently expose their keys as JWKs; convert those by
        default. A tree algorithm whose keys are natively COSE should override
        this rather than round-tripping through JWK.
        """
        cose_keys = [
            jwk_to_cose_key(jwk_key_as_dict)
            for jwk_key_as_dict in self.keys_as_jwks().values()
        ]
        # Section 2.2 of draft-ietf-scitt-scrapi-11 forbids a key set whose
        # kids would make one URL identify different keys. Checking here means
        # a tree algorithm assigning its own kids cannot publish such a set.
        check_key_identifiers_unambiguous(cose_keys)
        return cose_keys

    def key_by_kid(self, kid: bytes):
        """
        Resolve a single COSE Key by its kid, for the sub-resource defined in
        Section 2.2 of draft-ietf-scitt-scrapi-11. Returns None if no key
        matches.
        """
        for cose_key in self.keys_as_cose_key_set():
            if cose_key.get(COSE_KEY_KID) == kid:
                return cose_key
        return None

    @abstractmethod
    def create_receipt_contents(self, countersign_tbi: bytes, entry_id: str):
        raise NotImplementedError

    @abstractmethod
    def verify_receipt_contents(receipt_contents: list, countersign_tbi: bytes):
        raise NotImplementedError

    def get_operation(self, operation_id: str) -> dict:
        """
        Deprecated. Operations are not a SCRAPI concept; Section 2.4 of
        draft-ietf-scitt-scrapi-11 has clients poll the Receipt resource
        instead. Retained so existing consumers of the emulator keep working.
        """
        operation_path = self.operations_path / f"{operation_id}.json"
        try:
            with open(operation_path, "r") as f:
                operation = json.load(f)
        except FileNotFoundError:
            raise OperationNotFoundError(f"Operation {operation_id} not found")
        
        if operation["status"] == "running":
            # Pretend that the service finishes the operation after
            # the client having checked the operation status once.
            operation = self._finish_operation(operation)
        return operation

    def get_entry(self, entry_id: str) -> dict:
        try:
            self.get_claim(entry_id)
        except EntryNotFoundError:
            raise
        # More metadata to follow in the future.
        return { "entryId": entry_id }

    def get_claim(self, entry_id: str) -> bytes:
        claim_path = self.storage_path / f"{entry_id}.cose"
        try:
            with open(claim_path, "rb") as f:
                claim = f.read()
        except FileNotFoundError:
            raise EntryNotFoundError(f"Entry {entry_id} not found")
        return claim

    def submit_claim(self, claim: bytes, long_running=True) -> dict:
        """
        Register a Signed Statement, per Section 2.3 of
        draft-ietf-scitt-scrapi-11.

        Returns a dict with the EntryID and a status of either "succeeded",
        meaning a Receipt is available now, or "running", meaning the client
        polls the Receipt resource. The EntryID is the same either way for the
        same Signed Statement, as Section 2.3.1 requires.
        """
        insert_policy = self.service_parameters.get("insertPolicy", DEFAULT_INSERT_POLICY)
        entry_id = entry_id_for_claim(claim)

        # Section 2.3 of draft-ietf-scitt-scrapi-11: "The Registration Policy
        # for the Transparency Service MUST be applied before any additional
        # processing." Validating the Signed Statement here, before either an
        # entry or an operation is created, is what lets a bad statement get
        # the 400 of Section 2.3.3 in both registration modes rather than
        # surfacing only later.
        self._validate_submission(claim)

        if long_running:
            return self._create_operation(claim, entry_id)
        elif insert_policy != MOST_PERMISSIVE_INSERT_POLICY:
            raise NotImplementedError(
                f"non-* insertPolicy only works with long_running=True: {insert_policy!r}"
            )
        else:
            with self.registration_lock():
                entry = self._create_entry(claim, entry_id)
            return {**entry, "status": "succeeded"}

    def _create_entry(self, claim: bytes, entry_id: str) -> dict:
        """
        Register a Signed Statement under its EntryID. Callers hold the
        registration lock.

        Registration is idempotent on the EntryID. The EntryID is derived from
        the Signed Statement, so re-registering the same bytes names the same
        Receipt resource; appending a second leaf for it would mean the
        resource silently changed which leaf it proves, and would let any
        client grow the log without bound by replaying one statement.
        """
        receipt_path = self.storage_path / f"{entry_id}.receipt.cbor"
        if receipt_path.exists():
            print(f"Entry {entry_id} is already registered")
            return {"entryId": entry_id}

        # A prior attempt may have failed (a policy denial, for instance) and
        # left a failure record behind. This registration is a fresh attempt
        # at the same EntryID, so the stale record must not block it.
        self.operations_path.joinpath(f"{entry_id}.failed.json").unlink(missing_ok=True)

        self._create_receipt(claim, entry_id)

        claim_path = self.storage_path / f"{entry_id}.cose"
        claim_path.write_bytes(claim)

        print(f"A COSE signed Claim was written to:  {claim_path}")

        return {"entryId": entry_id}

    def _validate_submission(self, claim: bytes):
        """
        Validate a Signed Statement before it is registered.

        Section 2.3.3 of draft-ietf-scitt-scrapi-11 defines the "Payload
        Missing", "Bad Signature Algorithm", and "Rejected" errors. The
        structural checks here always run; signature verification runs when
        the service is configured to require it (see RFC 9943 Section 6.3).
        """
        try:
            msg = Sign1Message.decode(claim, tag=True)
        except Exception as error:
            raise ClaimInvalidError("Claim is not a valid COSE_Sign1 message") from error
        if not isinstance(msg, Sign1Message):
            raise ClaimInvalidError("Claim is not a COSE_Sign1 message")

        # Section 2.3: Signed Statements MAY use detached payloads when the
        # Transparency Service has access to the payload. This emulator has no
        # mechanism for that, so the payload must be present.
        if msg.payload is None:
            raise PayloadMissingError("Signed Statement payload must be present")

        # pycose gives back an Algorithm object; its identifier is the COSE
        # registered integer.
        algorithm = msg.phdr.get(pycose.headers.Algorithm)
        algorithm_id = getattr(algorithm, "identifier", algorithm)
        if algorithm_id not in SUPPORTED_SIGNATURE_ALGORITHMS:
            raise UnsupportedAlgorithmError(
                f"Signed Statement contained a non-supported algorithm: {algorithm!r}"
            )

        if self.service_parameters.get("verifySignature"):
            self._verify_signed_statement(msg)

    def _verify_signed_statement(self, msg: Sign1Message):
        """
        Verify the Signed Statement's signature with the Issuer's key, as
        RFC 9943 Section 6.3 requires: "The TS MUST perform signature
        verification per Section 4.4 of RFC 9052 and MUST verify the signature
        of the Signed Statement with the signature algorithm and verification
        key of the Issuer per [RFC9360]."

        The Issuer's key is resolved from the iss claim of the CWT Claims, the
        same way the Registration Policy resolves it.
        """
        from scitt_emulator.verify_statement import verify_statement

        try:
            verification_key = verify_statement(msg)
        except Exception as error:
            raise SignatureVerificationError(
                f"Could not verify the Signed Statement signature: {error}"
            ) from error
        if verification_key is None:
            raise SignatureVerificationError(
                "Signed Statement signature could not be verified with the "
                "Issuer's key"
            )

    def _create_operation(self, claim: bytes, entry_id: str) -> dict:
        operation_path = self.operations_path / f"{entry_id}.json"
        claim_path = self.operations_path / f"{entry_id}.cose"

        # A prior attempt at this EntryID may have failed and left a failure
        # record behind; this is a fresh attempt, so clear it.
        self.operations_path.joinpath(f"{entry_id}.failed.json").unlink(missing_ok=True)

        operation = {
            "operationId": entry_id,
            "entryId": entry_id,
            "status": "running",
        }

        with open(operation_path, "w") as f:
            json.dump(operation, f)

        with open(claim_path, "wb") as f:
            f.write(claim)

        print(f"Operation {entry_id} created")
        print(f"A COSE signed Claim was written to:  {claim_path}")

        return operation

    def get_entry_receipt(self, entry_id: str) -> bytes:
        """
        Resolve the Receipt for an EntryID, per Section 2.4 of
        draft-ietf-scitt-scrapi-11.

        Raises RegistrationRunningError while registration is in progress
        (204), and RegistrationFailedError or EntryNotFoundError when no
        Receipt exists (404).
        """
        receipt_path = self.storage_path / f"{entry_id}.receipt.cbor"
        if receipt_path.exists():
            return receipt_path.read_bytes()

        failure_path = self.operations_path / f"{entry_id}.failed.json"
        if failure_path.exists():
            failure = json.loads(failure_path.read_text())
            raise RegistrationFailedError(
                failure.get("detail", f"Registration of entry {entry_id} failed")
            )

        operation_path = self.operations_path / f"{entry_id}.json"
        if not operation_path.exists():
            raise EntryNotFoundError(
                f"Receipt with entry ID {entry_id} not known to this "
                f"Transparency Service"
            )

        with self.registration_lock():
            # Re-check under the lock: another request may have finished this
            # registration between the checks above and here.
            if receipt_path.exists():
                return receipt_path.read_bytes()
            if failure_path.exists():
                failure = json.loads(failure_path.read_text())
                raise RegistrationFailedError(
                    failure.get("detail", f"Registration of entry {entry_id} failed")
                )
            if not operation_path.exists():
                raise EntryNotFoundError(
                    f"Receipt with entry ID {entry_id} not known to this "
                    f"Transparency Service"
                )

            operation = json.loads(operation_path.read_text())

            if not operation.get("polled"):
                # Pretend that the service takes some time to reach finality,
                # so that clients exercise the 204 path of Section 2.4.2
                # rather than always seeing a Receipt on the first poll.
                operation["polled"] = True
                operation_path.write_text(json.dumps(operation))
                raise RegistrationRunningError(entry_id)

            try:
                operation = self._finish_operation(operation)
            except ClaimInvalidError as error:
                # The Signed Statement cannot be registered at all. In
                # synchronous mode this is the 400 of Section 2.3.3, but the
                # request that would have carried it is long gone, so record
                # the failure and report it as the 404 of Section 2.4.3.
                self._record_failure(entry_id, str(error))
                raise RegistrationFailedError(str(error)) from error

            if operation["status"] == "succeeded":
                return receipt_path.read_bytes()
            if operation["status"] == "running":
                raise RegistrationRunningError(entry_id)
            raise RegistrationFailedError(
                _failure_detail(operation, entry_id)
            )

    def _record_failure(self, entry_id: str, detail: str):
        """
        Record why a registration failed, and tear down its operation.

        Section 2.4.3 of draft-ietf-scitt-scrapi-11 permits the 404 for a
        failed registration to carry detail explaining why it did not
        complete, so the reason has to outlive the operation.
        """
        failure_path = self.operations_path / f"{entry_id}.failed.json"
        failure_path.write_text(json.dumps({"detail": detail}))
        for path in (
            self.operations_path / f"{entry_id}.json",
            self.operations_path / f"{entry_id}.cose",
        ):
            path.unlink(missing_ok=True)

    def _sync_policy_result(self, operation: dict):
        operation_id = operation["entryId"]
        policy_insert_path = self.operations_path / f"{operation_id}.policy.insert"
        policy_denied_path = self.operations_path / f"{operation_id}.policy.denied"
        policy_failed_path = self.operations_path / f"{operation_id}.policy.failed"
        insert_policy = self.service_parameters.get("insertPolicy", DEFAULT_INSERT_POLICY)

        # The EntryID is derived from the Signed Statement, so a later attempt
        # at the same entry reuses it. A policy file written for a previous
        # attempt can still be on disk (an external policy engine may have had
        # a validation in flight when the attempt was consumed and torn down).
        # The current operation file is newer than any such leftover, so only
        # policy files at least as new as it belong to this attempt.
        operation_path = self.operations_path / f"{operation_id}.json"
        operation_mtime_ns = (
            operation_path.stat().st_mtime_ns if operation_path.exists() else 0
        )
        for policy_path in (
            policy_insert_path,
            policy_failed_path,
            policy_denied_path,
        ):
            if policy_path.exists() and policy_path.stat().st_mtime_ns < operation_mtime_ns:
                policy_path.unlink(missing_ok=True)

        policy_result = {"status": operation["status"]}

        if insert_policy == MOST_PERMISSIVE_INSERT_POLICY:
            policy_result["status"] = "succeeded"
        if policy_insert_path.exists():
            policy_result["status"] = "succeeded"
            policy_insert_path.unlink()
        if policy_failed_path.exists():
            policy_result["status"] = "failed"
            if policy_failed_path.stat().st_size != 0:
                try:
                    policy_result_error = json.loads(policy_failed_path.read_text())
                except Exception as error:
                    raise PolicyResultDecodeError(operation_id) from error
                policy_result["error"] = policy_result_error
            policy_failed_path.unlink()
        if policy_denied_path.exists():
            policy_result["status"] = "denied"
            if policy_denied_path.stat().st_size != 0:
                try:
                    policy_result_error = json.loads(policy_denied_path.read_text())
                except Exception as error:
                    raise PolicyResultDecodeError(operation_id) from error
                policy_result["error"] = policy_result_error
            policy_denied_path.unlink()

        return policy_result

    def _finish_operation(self, operation: dict):
        entry_id = operation["entryId"]
        operation_path = self.operations_path / f"{entry_id}.json"
        claim_src_path = self.operations_path / f"{entry_id}.cose"

        policy_result = self._sync_policy_result(operation)
        if policy_result["status"] == "running":
            return operation
        if policy_result["status"] != "succeeded":
            operation["status"] = "failed"
            if "error" in policy_result:
                operation["error"] = policy_result["error"]
            # Record why registration failed. Section 2.4.3 of
            # draft-ietf-scitt-scrapi-11 permits the 404 for a failed
            # registration to be enriched with detail explaining why it did
            # not complete, so the reason has to outlive the operation.
            self._record_failure(
                entry_id, _failure_detail(operation, entry_id)
            )
            return operation

        claim = claim_src_path.read_bytes()
        entry = self._create_entry(claim, entry_id)
        claim_src_path.unlink(missing_ok=True)

        operation["status"] = "succeeded"
        operation["entryId"] = entry["entryId"]

        with open(operation_path, "w") as f:
            json.dump(operation, f)

        return operation

    def _create_receipt(self, claim: bytes, entry_id: str):
        # Validate claim
        # Note: This emulator does not verify the claim signature and does not apply
        # registration policies.
        try:
            msg = Sign1Message.decode(claim, tag=True)
        except:
            raise ClaimInvalidError("Claim is not a valid COSE message")
        if not isinstance(msg, Sign1Message):
            raise ClaimInvalidError("Claim is not a COSE_Sign1 message")
        if pycose.headers.Algorithm not in msg.phdr:
            raise ClaimInvalidError("Claim does not have an algorithm header parameter")
        if pycose.headers.ContentType not in msg.phdr:
            raise ClaimInvalidError(
                "Claim does not have a content type header parameter"
            )
        if CWTClaims not in msg.phdr:
            raise ClaimInvalidError("Claim does not have a CWTClaims header parameter")

        # Extract fields of COSE_Sign1 for countersigning
        outer = cbor2.loads(claim)
        [phdr, uhdr, payload, sig] = outer.value

        # Create countersigner protected header
        sign_protected = cbor2.dumps(
            {
                COSE_Headers_Service_Id: self.service_parameters["serviceId"],
                COSE_Headers_Tree_Alg: self.service_parameters["treeAlgorithm"],
                COSE_Headers_Issued_At: int(time.time()),
            }
        )

        # Compute countersign to-be-included
        countersign_tbi = create_countersign_to_be_included(
            phdr, sign_protected, payload, sig
        )

        # Tree algorithm receipt contents
        receipt_contents = self.create_receipt_contents(countersign_tbi, entry_id)

        # Create receipt
        receipt = cbor2.dumps([sign_protected, receipt_contents])

        # Store receipt
        receipt_path = self.storage_path / f"{entry_id}.receipt.cbor"
        with open(receipt_path, "wb") as f:
            f.write(receipt)
        print(f"Receipt written to {receipt_path}")

    def get_receipt(self, entry_id: str):
        receipt_path = self.storage_path / f"{entry_id}.receipt.cbor"
        try:
            with open(receipt_path, "rb") as f:
                receipt = f.read()
        except FileNotFoundError:
            raise EntryNotFoundError(f"Entry {entry_id} not found")
        return receipt

    def verify_receipt(self, cose_path: Path, receipt_path: Path):
        with open(cose_path, "rb") as f:
            envelope = f.read()

        outer = cbor2.loads(envelope)
        assert outer.tag == Sign1Message.cbor_tag
        [phdr, uhdr, payload, sig] = outer.value

        with open(receipt_path, "rb") as f:
            receipt = cbor2.loads(f.read())

        [sign_protected, receipt_contents] = receipt

        countersign_tbi = create_countersign_to_be_included(
            phdr, sign_protected, payload, sig
        )

        sign_protected_decoded = cbor2.loads(sign_protected)
        tree_alg = sign_protected_decoded[COSE_Headers_Tree_Alg]
        assert tree_alg == self.tree_alg

        self.verify_receipt_contents(receipt_contents, countersign_tbi)


def create_countersign_to_be_included(
    body_protected, sign_protected, payload, signature
):
    context = "CounterSignatureV2"
    countersign_structure = [
        context,
        body_protected,
        sign_protected,
        b"",  # no external AAD
        payload,
        [signature],
    ]
    to_be_signed = cbor2.dumps(countersign_structure)
    return to_be_signed

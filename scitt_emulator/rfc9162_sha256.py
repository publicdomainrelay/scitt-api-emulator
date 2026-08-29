# Copyright (c) SCITT Authors
# Licensed under the MIT License.
"""
A Transparency Service whose Receipts are COSE Sign1 messages carrying RFC 9162
inclusion proofs, as described in Section 7 of RFC 9943 and specified by
COSE Receipts (RFC 9942).

The Verifiable Data Structure is RFC9162_SHA256, value 1 in the "COSE
Verifiable Data Structure Algorithms" registry. Its Merkle tree hashing is
Section 2.1.1 of RFC 9162:

    leaf hash     = SHA-256(0x00 || leaf data)
    interior hash = SHA-256(0x01 || left || right)
"""

from typing import List, Optional, Tuple
from pathlib import Path
from hashlib import sha256
import json

import cbor2
import jwcrypto.jwk
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_pem_private_key,
)

from scitt_emulator.cose_keys import (
    COSE_KEY_EC2_X,
    COSE_KEY_EC2_Y,
    COSE_KEY_KID,
    base64url_decode,
    base64url_encode,
    cose_key_thumbprint,
    jwk_to_cose_key,
)
from scitt_emulator.scitt import ClaimInvalidError, SCITTServiceEmulator

# COSE header parameters, per RFC 9943 Figures 9 and 10.
COSE_HEADER_ALG = 1
COSE_HEADER_KID = 4
COSE_HEADER_CWT_CLAIMS = 15
COSE_HEADER_VDS = 395
COSE_HEADER_PROOFS = 396

# RFC 9942 "COSE Verifiable Data Structure Algorithms": RFC9162_SHA256 is 1.
VDS_RFC9162_SHA256 = 1

# RFC 9942 proof types, per RFC 9943 Section 7.
PROOF_TYPE_INCLUSION = -1
PROOF_TYPE_CONSISTENCY = -2

# CWT Claim keys, RFC 8392.
CWT_CLAIM_ISS = 1
CWT_CLAIM_SUB = 2

# COSE algorithm identifier for ECDSA with SHA-256.
COSE_ALG_ES256 = -7

COSE_SIGN1_TAG = 18

# RFC 9162 Section 2.1.1 domain separation prefixes.
LEAF_PREFIX = b"\x00"
INTERIOR_PREFIX = b"\x01"


class ReceiptInvalidError(Exception):
    pass


def leaf_hash(leaf_data: bytes) -> bytes:
    """
    RFC 9162 Section 2.1.1: MTH({d(0)}) = SHA-256(0x00 || d(0)).

    >>> leaf_hash(b"").hex()[:16]
    '6e340b9cffb37a98'
    """
    return sha256(LEAF_PREFIX + leaf_data).digest()


def interior_hash(left: bytes, right: bytes) -> bytes:
    """
    RFC 9162 Section 2.1.1: MTH(D[n]) = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n])).
    """
    return sha256(INTERIOR_PREFIX + left + right).digest()


def _split_point(n: int) -> int:
    """
    RFC 9162 Section 2.1.1: k is the largest power of two smaller than n.

    >>> [_split_point(n) for n in (2, 3, 5, 8, 9)]
    [1, 2, 4, 4, 8]
    """
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def merkle_tree_hash(leaves: List[bytes]) -> bytes:
    """
    RFC 9162 Section 2.1.1: the Merkle Tree Hash of a list of leaf hashes.

    The hash of an empty list is the hash of the empty string.

    >>> merkle_tree_hash([]) == sha256(b"").digest()
    True
    >>> merkle_tree_hash([leaf_hash(b"a")]) == leaf_hash(b"a")
    True
    """
    if not leaves:
        return sha256(b"").digest()
    if len(leaves) == 1:
        return leaves[0]
    k = _split_point(len(leaves))
    return interior_hash(merkle_tree_hash(leaves[:k]), merkle_tree_hash(leaves[k:]))


def inclusion_proof_path(leaves: List[bytes], index: int) -> List[bytes]:
    """
    RFC 9162 Section 2.1.3: the audit path for the leaf at ``index``, in the
    tree over ``leaves``.

    >>> leaves = [leaf_hash(bytes([i])) for i in range(4)]
    >>> path = inclusion_proof_path(leaves, 2)
    >>> len(path)
    2
    """
    if not 0 <= index < len(leaves):
        raise IndexError(f"Leaf index {index} outside tree of size {len(leaves)}")
    if len(leaves) == 1:
        return []
    k = _split_point(len(leaves))
    if index < k:
        return inclusion_proof_path(leaves[:k], index) + [merkle_tree_hash(leaves[k:])]
    return inclusion_proof_path(leaves[k:], index - k) + [merkle_tree_hash(leaves[:k])]


def root_from_inclusion_proof(
    tree_size: int, leaf_index: int, leaf: bytes, path: List[bytes]
) -> bytes:
    """
    RFC 9162 Section 2.1.3.2: reconstruct the Merkle tree root from a leaf hash
    and its inclusion proof, so a verifier need not hold the whole tree.

    >>> leaves = [leaf_hash(bytes([i])) for i in range(5)]
    >>> path = inclusion_proof_path(leaves, 3)
    >>> root_from_inclusion_proof(5, 3, leaves[3], path) == merkle_tree_hash(leaves)
    True
    """
    if not 0 <= leaf_index < tree_size:
        raise ReceiptInvalidError(
            f"Leaf index {leaf_index} outside tree of size {tree_size}"
        )

    # Walk down from the root recording, at each level, which half the leaf
    # falls in. The audit path runs leaf to root, so these are consumed in
    # reverse.
    descend_right = []
    index, size = leaf_index, tree_size
    while size > 1:
        k = _split_point(size)
        if index < k:
            descend_right.append(False)
            size = k
        else:
            descend_right.append(True)
            index, size = index - k, size - k

    if len(descend_right) != len(path):
        raise ReceiptInvalidError(
            f"Inclusion proof has {len(path)} intermediate hashes, expected "
            f"{len(descend_right)} for leaf {leaf_index} of {tree_size}"
        )

    current = leaf
    for is_right, sibling in zip(reversed(descend_right), path):
        current = (
            interior_hash(sibling, current)
            if is_right
            else interior_hash(current, sibling)
        )
    return current


def encode_inclusion_proof(tree_size: int, leaf_index: int, path: List[bytes]) -> bytes:
    """
    Figure 11 of RFC 9943: an RFC9162_SHA256 inclusion proof is
    ``[tree size, leaf index, [intermediate hashes]]``, carried as a
    ``bstr .cbor``.
    """
    return cbor2.dumps([tree_size, leaf_index, list(path)])


def decode_inclusion_proof(encoded: bytes) -> Tuple[int, int, List[bytes]]:
    proof = cbor2.loads(encoded)
    if (
        not isinstance(proof, list)
        or len(proof) != 3
        or not isinstance(proof[0], int)
        or not isinstance(proof[1], int)
        or not isinstance(proof[2], list)
        or not all(isinstance(node, bytes) for node in proof[2])
    ):
        raise ReceiptInvalidError(
            "Inclusion proof is not [tree size, leaf index, [intermediate hashes]]"
        )
    return proof[0], proof[1], proof[2]


def sig_structure(protected: bytes, payload: bytes) -> bytes:
    """
    Section 4.4 of RFC 9052: the Sig_structure for a COSE_Sign1, over which the
    signature is computed. The Receipt's payload is detached, so it is supplied
    here rather than carried in the message.
    """
    return cbor2.dumps(["Signature1", protected, b"", payload])


class RFC9162SHA256SCITTServiceEmulator(SCITTServiceEmulator):
    """
    A Transparency Service backed by an RFC 9162 Merkle tree, issuing COSE
    Sign1 Receipts.
    """

    tree_alg = "RFC9162_SHA256"

    def __init__(
        self, service_parameters_path: Path, storage_path: Optional[Path] = None
    ):
        super().__init__(service_parameters_path, storage_path)
        if storage_path is not None:
            self._service_private_key_path = (
                self.storage_path / "service_private_key.pem"
            )
            self._leaves_path = self.storage_path / "tree_leaves.txt"

    def initialize_service(self):
        if self.service_parameters_path.exists():
            return

        service_private_key = ec.generate_private_key(ec.SECP256R1())
        self._service_private_key_path.write_bytes(
            service_private_key.private_bytes(
                Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
            )
        )
        print(f"Service private key written to {self._service_private_key_path}")

        self.service_parameters = {
            "serviceId": "emulator",
            "treeAlgorithm": self.tree_alg,
            "signatureAlgorithm": "ES256",
            # The iss of the CWT Claims in Receipts this service issues.
            "issuer": "transparency.example",
            # The public COSE Key, so that a Receipt can be verified from the
            # service parameters alone, without the private key. This is the
            # same key served from /.well-known/scitt-keys.
            "serviceCoseKey": base64url_encode(
                cbor2.dumps(self._cose_key_from_private_key(), canonical=True)
            ),
        }
        with open(self.service_parameters_path, "w") as f:
            json.dump(self.service_parameters, f)
        print(f"Service parameters written to {self.service_parameters_path}")

    def _private_key(self):
        return load_pem_private_key(self._service_private_key_path.read_bytes(), None)

    def keys_as_jwks(self):
        key = jwcrypto.jwk.JWK()
        key.import_from_pem(self._service_private_key_path.read_bytes())
        return {
            key.thumbprint(): {
                **key.export_public(as_dict=True),
                "use": "sig",
                "kid": key.thumbprint(),
            }
        }

    def _cose_key_from_private_key(self) -> dict:
        (jwk,) = self.keys_as_jwks().values()
        return jwk_to_cose_key(jwk)

    def _cose_key(self) -> dict:
        """
        The public COSE Key this service signs Receipts with.

        Taken from the service parameters when present, so that a verifier
        holding only the service parameters can check a Receipt without the
        private key.
        """
        encoded = self.service_parameters.get("serviceCoseKey")
        if encoded is not None:
            return cbor2.loads(base64url_decode(encoded))
        return self._cose_key_from_private_key()

    def _public_key(self):
        cose_key = self._cose_key()
        return ec.EllipticCurvePublicNumbers(
            int.from_bytes(cose_key[COSE_KEY_EC2_X], "big"),
            int.from_bytes(cose_key[COSE_KEY_EC2_Y], "big"),
            ec.SECP256R1(),
        ).public_key()

    def _kid(self) -> bytes:
        return self._cose_key()[COSE_KEY_KID]

    # Tree state. Leaf hashes are kept in registration order, one hex digest
    # per line, which is enough to recompute any root or inclusion proof.

    def _leaves(self) -> List[bytes]:
        if not self._leaves_path.exists():
            return []
        return [
            bytes.fromhex(line)
            for line in self._leaves_path.read_text().split()
            if line
        ]

    def _append_leaf(self, leaf: bytes) -> int:
        with open(self._leaves_path, "a") as f:
            f.write(leaf.hex() + "\n")
        return len(self._leaves()) - 1

    def _create_receipt(self, claim: bytes, entry_id: str):
        # The Registration Policy is applied before this point; here the
        # Signed Statement is checked for the structure Figure 3 of RFC 9943
        # requires before it becomes a leaf.
        self._validate_signed_statement(claim)

        # The leaf commits to the Signed Statement as registered.
        leaf = leaf_hash(claim)
        leaf_index = self._append_leaf(leaf)
        leaves = self._leaves()

        receipt = self._sign_receipt(claim, leaves, leaf_index)

        receipt_path = self.storage_path / f"{entry_id}.receipt.cbor"
        receipt_path.write_bytes(receipt)
        print(f"Receipt written to {receipt_path}")

    def _validate_signed_statement(self, claim: bytes):
        try:
            outer = cbor2.loads(claim)
        except Exception as error:
            raise ClaimInvalidError("Claim is not a valid CBOR document") from error
        if not isinstance(outer, cbor2.CBORTag) or outer.tag != COSE_SIGN1_TAG:
            raise ClaimInvalidError("Claim is not a tagged COSE_Sign1 message")
        if not isinstance(outer.value, list) or len(outer.value) != 4:
            raise ClaimInvalidError("COSE_Sign1 does not have four elements")
        try:
            phdr = cbor2.loads(outer.value[0])
        except Exception as error:
            raise ClaimInvalidError("Protected header is not valid CBOR") from error
        if not isinstance(phdr, dict):
            raise ClaimInvalidError("Protected header is not a CBOR map")
        # Figure 3 of RFC 9943: CWT_Claims is the one mandatory label.
        if COSE_HEADER_CWT_CLAIMS not in phdr:
            raise ClaimInvalidError(
                "Claim does not have a CWT Claims (15) header parameter"
            )
        if COSE_HEADER_ALG not in phdr:
            raise ClaimInvalidError("Claim does not have an algorithm header parameter")

    def _subject_of(self, claim: bytes) -> Optional[str]:
        """
        The sub of the Signed Statement's CWT Claims, which the Receipt repeats
        so that a Receipt says what it is about (Figure 10 of RFC 9943).

        Per RFC 9597 the CWT Claims header parameter holds a CWT Claims Set, a
        plain map, so no signature verification is involved in reading it; the
        Signed Statement's own signature is checked by the Registration Policy.
        """
        phdr = cbor2.loads(cbor2.loads(claim).value[0])
        cwt_claims = phdr.get(COSE_HEADER_CWT_CLAIMS)
        if not isinstance(cwt_claims, dict):
            return None
        subject = cwt_claims.get(CWT_CLAIM_SUB)
        return subject if isinstance(subject, str) else None

    def _sign_receipt(self, claim: bytes, leaves: List[bytes], leaf_index: int) -> bytes:
        tree_size = len(leaves)
        root = merkle_tree_hash(leaves)
        path = inclusion_proof_path(leaves, leaf_index)

        cwt_claims = {
            CWT_CLAIM_ISS: self.service_parameters.get("issuer", "transparency.example"),
        }
        subject = self._subject_of(claim)
        if subject is not None:
            cwt_claims[CWT_CLAIM_SUB] = subject

        # Figure 10 of RFC 9943: the Receipt's protected header.
        protected = cbor2.dumps(
            {
                COSE_HEADER_ALG: COSE_ALG_ES256,
                COSE_HEADER_KID: self._kid(),
                COSE_HEADER_VDS: VDS_RFC9162_SHA256,
                COSE_HEADER_CWT_CLAIMS: cwt_claims,
            },
            canonical=True,
        )

        # RFC 9942: the payload of a Receipt is the Verifiable Data Structure
        # root, and is detached. A verifier recomputes it from the proof.
        signature = self._private_key().sign(
            sig_structure(protected, root), ec.ECDSA(hashes.SHA256())
        )

        # Figure 9 of RFC 9943: the inclusion proof goes in the unprotected
        # header, under Proofs (396) at label -1.
        unprotected = {
            COSE_HEADER_PROOFS: {
                PROOF_TYPE_INCLUSION: [
                    encode_inclusion_proof(tree_size, leaf_index, path)
                ],
            },
        }

        return cbor2.dumps(
            cbor2.CBORTag(
                COSE_SIGN1_TAG,
                [protected, unprotected, None, _der_to_p1363(signature)],
            )
        )

    # The base class's countersignature-based receipt machinery does not apply.

    def create_receipt_contents(self, countersign_tbi: bytes, entry_id: str):
        raise NotImplementedError(
            "RFC9162_SHA256 Receipts are COSE Sign1 messages, not countersignatures"
        )

    def verify_receipt_contents(self, receipt_contents: list, countersign_tbi: bytes):
        raise NotImplementedError(
            "RFC9162_SHA256 Receipts are COSE Sign1 messages, not countersignatures"
        )

    def verify_receipt(self, cose_path: Path, receipt_path: Path):
        """
        Verify a Receipt against the Signed Statement it is about.

        Section 7.1 of RFC 9943: a Relying Party applies the verification
        process of Section 4.4 of RFC 9052 when checking the signature of a
        Receipt. The Receipt's payload is the Verifiable Data Structure root,
        recomputed here from the leaf and the inclusion proof.
        """
        claim = Path(cose_path).read_bytes()
        receipt = Path(receipt_path).read_bytes()

        outer = cbor2.loads(receipt)
        if not isinstance(outer, cbor2.CBORTag) or outer.tag != COSE_SIGN1_TAG:
            raise ReceiptInvalidError("Receipt is not a tagged COSE_Sign1 message")
        protected_bytes, unprotected, payload, signature = outer.value

        if payload is not None:
            raise ReceiptInvalidError("Receipt payload must be detached")

        protected = cbor2.loads(protected_bytes)
        vds = protected.get(COSE_HEADER_VDS)
        if vds != VDS_RFC9162_SHA256:
            raise ReceiptInvalidError(
                f"Receipt is for verifiable data structure {vds!r}, expected "
                f"{VDS_RFC9162_SHA256} (RFC9162_SHA256)"
            )

        proofs = unprotected.get(COSE_HEADER_PROOFS)
        if not isinstance(proofs, dict):
            raise ReceiptInvalidError("Receipt has no proofs in its unprotected header")
        inclusion_proofs = proofs.get(PROOF_TYPE_INCLUSION)
        if not inclusion_proofs:
            raise ReceiptInvalidError("Receipt has no inclusion proof")

        tree_size, leaf_index, path = decode_inclusion_proof(inclusion_proofs[0])
        root = root_from_inclusion_proof(
            tree_size, leaf_index, leaf_hash(claim), path
        )

        # The kid in the Receipt selects the verification key. Checking it
        # against the thumbprint of the key we hold is what makes the kid
        # meaningful; see Section 2.2 of draft-ietf-scitt-scrapi-11.
        cose_key = self._cose_key()
        kid = protected.get(COSE_HEADER_KID)
        if kid is not None and kid != cose_key_thumbprint(cose_key):
            raise ReceiptInvalidError(
                "Receipt kid does not match this Transparency Service's key"
            )

        try:
            self._public_key().verify(
                _p1363_to_der(signature),
                sig_structure(protected_bytes, root),
                ec.ECDSA(hashes.SHA256()),
            )
        except Exception as error:
            raise ReceiptInvalidError("Receipt signature is not valid") from error

        print(f"Verified inclusion of leaf {leaf_index} in tree of size {tree_size}")
        print(f"Root: {root.hex()}")


def _der_to_p1363(signature: bytes) -> bytes:
    """
    Section 8.1 of RFC 9053: COSE ECDSA signatures are the fixed-width
    concatenation of r and s, not the DER sequence ``cryptography`` produces.
    """
    r, s = utils.decode_dss_signature(signature)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _p1363_to_der(signature: bytes) -> bytes:
    if len(signature) != 64:
        raise ReceiptInvalidError(
            f"ES256 signature must be 64 bytes, got {len(signature)}"
        )
    return utils.encode_dss_signature(
        int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
    )

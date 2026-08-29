# Copyright (c) SCITT Authors
# Licensed under the MIT License.
import base64
import pathlib
import hashlib
import argparse
from typing import Union, Optional, List

import cwt
import pycose
import pycose.headers
import pycose.messages
import pycose.keys.ec2
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.serialization import load_pem_private_key

# TODO jwcrypto is LGPLv3, is there another option with a permissive licence?
import jwcrypto.jwk

from scitt_emulator.did_helpers import DID_JWK_METHOD


@pycose.headers.CoseHeaderAttribute.register_attribute()
class CWTClaims(pycose.headers.CoseHeaderAttribute):
    # RFC 9597 registers label 15 for CWT Claims in the COSE Header Parameters
    # registry. Figure 3 of RFC 9943 requires it in the protected header of
    # Signed Statements and Receipts.
    identifier = 15
    fullname = "CWT_CLAIMS"


@pycose.headers.CoseHeaderAttribute.register_attribute()
class Receipts(pycose.headers.CoseHeaderAttribute):
    identifier = 394
    fullname = "RECEIPTS"


@pycose.headers.CoseHeaderAttribute.register_attribute()
class VDS(pycose.headers.CoseHeaderAttribute):
    # Verifiable Data Structure, RFC 9942. Figure 10 of RFC 9943 shows it in
    # the protected header of a Receipt, identifying the algorithm whose
    # proofs the Receipt carries.
    identifier = 395
    fullname = "VERIFIABLE_DATA_STRUCTURE"


@pycose.headers.CoseHeaderAttribute.register_attribute()
class Proofs(pycose.headers.CoseHeaderAttribute):
    # Verifiable Data structure Proofs, RFC 9942. Figure 9 of RFC 9943 shows
    # it in the unprotected header of a Receipt, with inclusion proofs at -1
    # and consistency proofs at -2.
    identifier = 396
    fullname = "PROOFS"


def create_claim(
    claim_path: pathlib.Path,
    issuer: Union[str, None],
    subject: str,
    content_type: str,
    payload: bytes,
    private_key_pem_path: Optional[str] = None,
    receipts: Optional[List[bytes]] = None,
):
    # https://ietf-wg-scitt.github.io/draft-ietf-scitt-architecture/draft-ietf-scitt-architecture.html#name-signed-statement-envelope

    # Create COSE_Sign1 structure
    # Create an ad-hoc key
    # oct: size(int)
    # RSA: public_exponent(int), size(int)
    # EC: crv(str) (one of P-256, P-384, P-521, secp256k1)
    # OKP: crv(str) (one of Ed25519, Ed448, X25519, X448)
    key = jwcrypto.jwk.JWK()
    if private_key_pem_path and private_key_pem_path.exists():
        key.import_from_pem(private_key_pem_path.read_bytes())
    else:
        key = key.generate(kty="EC", crv="P-384")
    # https://python-cwt.readthedocs.io/en/stable/algorithms.html
    alg = key.key_curve.replace("P-", "ES")
    kid = key.thumbprint()
    key_as_pem_bytes = key.export_to_pem(private_key=True, password=None)
    # cwt_cose_key = cwt.COSEKey.generate_symmetric_key(alg=alg, kid=kid)
    cwt_cose_key = cwt.COSEKey.from_pem(key_as_pem_bytes, kid=kid)
    # cwt_cose_key_to_cose_key = cwt.algs.ec2.EC2Key.to_cose_key(cwt_cose_key)
    cwt_cose_key_to_cose_key = cwt_cose_key.to_dict()
    sign1_message_key = pycose.keys.ec2.EC2Key.from_dict(cwt_cose_key_to_cose_key)

    # If issuer was not given used did:jwk of public key
    if issuer is None:
        issuer = DID_JWK_METHOD + base64.urlsafe_b64encode(key.export_public().encode()).decode()

    # CWT_Claims (label: 15, RFC 9597): A CWT representing
    # the Issuer (iss) making the statement, and the Subject (sub) to
    # correlate a collection of statements about an Artifact. Additional
    # [CWT_CLAIMS] MAY be used, while iss and sub MUST be provided
    # CWT_Claims = {
    cwt_claims = {
        # iss (CWT_Claim Key 1): The Identifier of the signer, as a string
        # Example: did:web:example.com
        #   1 => tstr; iss, the issuer making statements,
        1: issuer,
        # sub (CWT_Claim Key 2): The Subject to which the Statement refers,
        # chosen by the Issuer
        # Example: github.com/opensbom-generator/spdx-sbom-generator/releases/tag/v0.0.13
        #   2 => tstr; sub, the subject of the statements,
        2: subject,
        #   * tstr => any
    }
    # }

    # Protected_Header = {
    protected = {
        # algorithm (label: 1): Asymmetric signature algorithm used by the
        # Issuer of a Signed Statement, as an integer.
        # Example: -35 is the registered algorithm identifier for ECDSA with
        # SHA-384, see COSE Algorithms Registry [IANA.cose].
        #   1   => int             ; algorithm identifier,
        # https://www.iana.org/assignments/cose/cose.xhtml#algorithms
        # pycose.headers.Algorithm: "ES256",
        pycose.headers.Algorithm: getattr(cwt.enums.COSEAlgs, alg),
        # Key ID (label: 4): Key ID, as a bytestring
        #   4   => bstr            ; Key ID,
        pycose.headers.KID: kid.encode("ascii"),
        #   15  => CWT_Claims      ; CBOR Web Token Claims,
        # RFC 9597: the value of the CWT Claims header parameter is a CWT
        # Claims Set, a plain map of claim key to value. Figure 5 of RFC 9943
        # shows it that way; it is not a nested, separately signed CWT. The
        # outer COSE_Sign1 signature protects it.
        CWTClaims: cwt_claims,
        #   3   => tstr            ; payload type
        pycose.headers.ContentType: content_type,
    }
    # }

    # Unprotected_Header = {
    unprotected = {}
    #   ? 394 => [+ bstr .cbor Receipt]
    # Figure 7 of RFC 9943: a Signed Statement with Receipts in its
    # unprotected header is a Transparent Statement. Figure 3 types label 394
    # as [+ bstr .cbor Receipt], so it is omitted rather than set to nil when
    # there are no Receipts.
    if receipts:
        unprotected[Receipts] = receipts
    # }

    # https://github.com/TimothyClaeys/pycose/blob/e527e79b611f6cc6673bbb694056a7468c2eef75/pycose/messages/cosemessage.py#L84-L91
    msg = pycose.messages.Sign1Message(
        phdr=protected,
        uhdr=unprotected,
        payload=payload,
    )

    # Sign
    msg.key = sign1_message_key
    # https://github.com/TimothyClaeys/pycose/blob/e527e79b611f6cc6673bbb694056a7468c2eef75/pycose/messages/cosemessage.py#L143
    claim = msg.encode(tag=True)
    claim_path.write_bytes(claim)

    # Write out private key in PEM format if argument given and not exists
    if private_key_pem_path and not private_key_pem_path.exists():
        private_key_pem_path.write_bytes(key_as_pem_bytes)

    # https://github.com/TimothyClaeys/pycose/blob/e527e79b611f6cc6673bbb694056a7468c2eef75/pycose/messages/sign1message.py#L66C9-L79
    msg.signature = b""
    # https://github.com/TimothyClaeys/pycose/blob/e527e79b611f6cc6673bbb694056a7468c2eef75/pycose/messages/cosemessage.py#L143
    claim = msg.encode(tag=True, sign=False)

    # https://www.ietf.org/archive/id/draft-ietf-scitt-architecture-10.html#appendix-B.2-5
    # signed statement and statement are identical AFAIK
    message_type = "signed-statement"

    hash_name = "sha256"
    hash_instance = hashlib.new(hash_name)
    hash_instance.update(claim)

    base_encoding = "base64url"
    # Section 2 of RFC 7515 base64url omits all trailing "=".
    base64url_encoded_bytes_digest = (
        base64.urlsafe_b64encode(hash_instance.digest()).decode().rstrip("=")
    )

    return f"urn:ietf:params:scitt:{message_type}:{hash_name}:{base_encoding}:{base64url_encoded_bytes_digest}"


def cli(fn):
    p = fn("create-claim", description="Create a fake SCITT claim")
    p.add_argument("--out", required=True, type=pathlib.Path)
    p.add_argument("--issuer", required=False, type=str, default=None)
    p.add_argument("--subject", required=True, type=str)
    p.add_argument("--content-type", required=True, type=str)
    p.add_argument("--payload", required=True, type=str)
    p.add_argument("--private-key-pem", required=False, type=pathlib.Path)
    p.set_defaults(
        func=lambda args: create_claim(
            args.out,
            args.issuer,
            args.subject,
            args.content_type,
            args.payload.encode("utf-8"),
            private_key_pem_path=args.private_key_pem,
        )
    )

    return p


def main(argv=None):
    parser = cli(argparse.ArgumentParser)
    args = parser.parse_args(argv)
    urn = args.func(args)
    print(urn)


if __name__ == "__main__":
    main()

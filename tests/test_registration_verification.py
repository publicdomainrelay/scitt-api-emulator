# Copyright (c) SCITT Authors
# Licensed under the MIT License.
"""
Signed Statement signature verification at registration, as RFC 9943 Section
6.3 requires, and the errors of Section 2.3.3 of draft-ietf-scitt-scrapi-11.
"""
import os
import pathlib

import cbor2
import httpx
import pytest

from scitt_emulator import create_statement
from scitt_emulator.did_helpers import url_to_did_web

from tests.test_cli import Service

# Resolve did:web to plain http so the issuer names this test service. Set at
# import time, before any did:web resolution.
os.environ["DID_WEB_ASSUME_SCHEME"] = "http"

# COSE_Sign1 CBOR tag, RFC 9052 Section 4.2.
COSE_SIGN1_TAG = 18
# COSE algorithm header label, RFC 9052 Section 3.
COSE_HEADER_ALG = 1
# HS256 is symmetric; the emulator signs with asymmetric algorithms, so it
# decodes as a known COSE algorithm and is rejected as unsupported.
UNSUPPORTED_ALG = 5


def make_service(tmp_path, verify_signature=False, use_lro=False):
    return Service(
        {
            "tree_alg": "RFC9162_SHA256",
            "workspace": tmp_path / "workspace",
            "error_rate": 0,
            "use_lro": use_lro,
            "verify_signature": verify_signature,
        }
    )


def statement_signed_with(claim_path, issuer, private_key_pem):
    create_statement.create_claim(
        claim_path,
        issuer,
        "vendor.product.example",
        "application/json",
        b'{"foo": "bar"}',
        private_key_pem_path=pathlib.Path(private_key_pem),
    )


def submit(service, claim: bytes):
    return httpx.post(
        f"{service.url}/entries",
        content=claim,
        headers={"Content-Type": "application/cose", "Accept": "application/cose"},
    )


@pytest.mark.parametrize("use_lro", [False, True])
def test_bad_signature_algorithm(tmp_path, use_lro):
    """
    Section 2.3.3: "Bad Signature Algorithm" when the Signed Statement
    contained a non-supported algorithm.
    """
    protected = cbor2.dumps({COSE_HEADER_ALG: UNSUPPORTED_ALG})
    claim = cbor2.dumps(
        cbor2.CBORTag(COSE_SIGN1_TAG, [protected, {}, b"payload", b"signature"])
    )

    with make_service(tmp_path, use_lro=use_lro) as service:
        response = submit(service, claim)

    assert response.status_code == 400
    assert cbor2.loads(response.content)[-1] == "Bad Signature Algorithm"


@pytest.mark.parametrize("use_lro", [False, True])
def test_payload_missing(tmp_path, use_lro):
    """
    Section 2.3.3: "Payload Missing". Signed Statements MAY use detached
    payloads when the Transparency Service has access to the payload; this
    emulator has no mechanism for that, so the payload must be present.
    """
    claim = cbor2.dumps(cbor2.CBORTag(COSE_SIGN1_TAG, [cbor2.dumps({1: -7}), {}, None, b"s"]))

    with make_service(tmp_path, use_lro=use_lro) as service:
        response = submit(service, claim)

    assert response.status_code == 400
    assert cbor2.loads(response.content)[-1] == "Payload Missing"


def test_verify_signature_accepts_a_statement_signed_with_the_service_key(tmp_path):
    """
    RFC 9943 Section 6.3: the Transparency Service verifies the Signed
    Statement's signature with the Issuer's key, resolved from the iss claim.
    A statement whose issuer is the service itself, signed with the service's
    own key, verifies.
    """
    with make_service(tmp_path, verify_signature=True) as service:
        claim_path = tmp_path / "claim.cose"
        issuer = url_to_did_web(service.url)
        service_key = (
            tmp_path / "workspace" / "storage" / "service_private_key.pem"
        )
        statement_signed_with(claim_path, issuer, service_key)

        response = submit(service, claim_path.read_bytes())

    assert response.status_code == 201, response.content


def test_verify_signature_rejects_a_statement_signed_with_the_wrong_key(tmp_path):
    """
    A statement whose issuer names this service but whose signature does not
    verify against the service's key is rejected.
    """
    with make_service(tmp_path, verify_signature=True) as service:
        claim_path = tmp_path / "claim.cose"
        issuer = url_to_did_web(service.url)
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        wrong_key = tmp_path / "wrong-key.pem"
        wrong_key.write_bytes(
            ec.generate_private_key(ec.SECP256R1()).private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        statement_signed_with(claim_path, issuer, wrong_key)

        response = submit(service, claim_path.read_bytes())

    assert response.status_code == 400
    problem_details = cbor2.loads(response.content)
    assert problem_details[-1] == "Rejected"
    assert "signature could not be verified" in problem_details[-2]


def test_verification_is_off_by_default(tmp_path):
    """
    The emulator's default is permissive, for interoperability testing: a
    statement whose issuer's key cannot be resolved is still registered.
    """
    claim_path = tmp_path / "claim.cose"
    create_statement.create_claim(
        claim_path,
        "did:web:example.org",
        "subject",
        "application/json",
        b'{"foo": "bar"}',
    )

    with make_service(tmp_path) as service:
        response = submit(service, claim_path.read_bytes())

    assert response.status_code == 201, response.content

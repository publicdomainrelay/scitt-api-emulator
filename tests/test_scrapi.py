# Copyright (c) SCITT Authors
# Licensed under the MIT License.
"""
Conformance tests for the HTTP resources defined by
draft-ietf-scitt-scrapi-11.
"""
import pathlib
import tempfile

import cbor2
import httpx
import pytest

from scitt_emulator import create_statement, server
from scitt_emulator.client import describe_error_response
from scitt_emulator.cose_keys import (
    COSE_KEY_EC2_CRV,
    COSE_KEY_EC2_X,
    COSE_KEY_EC2_Y,
    COSE_KEY_KID,
    COSE_KEY_KTY,
    COSE_KEY_CRV_P256,
    COSE_KEY_TYPE_EC2,
    base64url_encode,
    cose_key_thumbprint,
    kid_url_segments,
)
from scitt_emulator.errors import CONTENT_TYPE as PROBLEM_DETAILS_CONTENT_TYPE

from .test_cli import Service


def make_service(tmp_path, use_lro=False):
    return Service(
        {
            "tree_alg": "CCF",
            "workspace": tmp_path / "workspace",
            "error_rate": 0,
            "use_lro": use_lro,
        }
    )


@pytest.fixture
def service(tmp_path):
    with make_service(tmp_path) as service:
        yield service


@pytest.fixture(params=[False, True], ids=["sync", "async"])
def service_either_mode(request, tmp_path):
    with make_service(tmp_path, use_lro=request.param) as service:
        yield service


def signed_statement():
    """A Signed Statement the emulator will accept for registration."""
    private_key_pem_path = tempfile.mktemp(suffix=".pem")
    claim_path = tempfile.mktemp(suffix=".cose")
    create_statement.create_claim(
        pathlib.Path(claim_path),
        "did:web:example.org",
        "subject",
        "application/json",
        b'{"foo": "bar"}',
    )
    return pathlib.Path(claim_path).read_bytes()


def register(service, claim):
    return httpx.post(
        f"{service.url}/entries",
        content=claim,
        headers={"Content-Type": "application/cose", "Accept": "application/cose"},
    )


def test_error_is_concise_problem_details(service):
    """
    Section 2: on a request the Transparency Service cannot process, the body
    MUST be an RFC 9290 Concise Problem Details object.
    """
    response = httpx.get(f"{service.url}/entries/does-not-exist")

    assert response.status_code == 404
    assert (
        response.headers["content-type"].split(";")[0].strip()
        == PROBLEM_DETAILS_CONTENT_TYPE
    )

    problem_details = cbor2.loads(response.content)
    # RFC 9290 Section 2: title is -1 and detail is -2.
    assert isinstance(problem_details, dict)
    assert isinstance(problem_details[-1], str)
    assert isinstance(problem_details[-2], str)
    assert problem_details[-1] == "Not Found"
    assert "does-not-exist" in problem_details[-2]


def test_error_no_longer_uses_scitt_error_urns(service):
    """
    The urn:ietf:params:scitt:error:* namespace was removed from SCRAPI; no
    error response should still carry it.
    """
    response = httpx.get(f"{service.url}/entries/does-not-exist")

    assert b"urn:ietf:params:scitt:error" not in response.content


def test_malformed_registration_request(service):
    """
    Section 2: the "malformed" error type indicates the Transparency Service
    could not parse the client's request.
    """
    response = httpx.post(
        f"{service.url}/entries",
        content=b"not a COSE message",
        headers={"Content-Type": "application/cose"},
    )

    assert response.status_code == 400
    problem_details = cbor2.loads(response.content)
    assert problem_details[-1] == "Malformed request"


def test_client_describes_problem_details(service):
    """
    Section 2: clients MUST rely on the Concise Problem Details object rather
    than the status code alone to determine the cause of an error.
    """
    response = httpx.get(f"{service.url}/entries/does-not-exist")

    described = describe_error_response(response)

    assert "404" in described
    assert "Not Found" in described


def test_client_falls_back_to_status_class():
    """
    Section 2: clients MUST be prepared to handle any HTTP status code by
    falling back to the generic class semantics of the response.
    """
    # A status code with no SCRAPI-defined meaning and no problem details body.
    response = httpx.Response(status_code=418, content=b"")

    assert describe_error_response(response) == "HTTP 418 (Client Error)"


def test_client_falls_back_when_problem_details_undecodable():
    """
    A body that claims to be Concise Problem Details but is not must not
    prevent the client from reporting the error.
    """
    response = httpx.Response(
        status_code=500,
        content=b"\xff\xff not cbor",
        headers={"Content-Type": PROBLEM_DETAILS_CONTENT_TYPE},
    )

    assert describe_error_response(response) == "HTTP 500 (Server Error)"


def test_transparency_service_keys_is_cose_key_set(service):
    """
    Section 2.1: the Transparency Service MUST respond with a COSE Key Set, as
    defined in Section 7 of RFC 9052, serialized as application/cbor.
    """
    response = httpx.get(
        f"{service.url}/.well-known/scitt-keys",
        headers={"Accept": "application/cbor"},
    )

    assert response.status_code == 200
    assert response.headers["content-type"].split(";")[0].strip() == "application/cbor"

    cose_key_set = cbor2.loads(response.content)
    # Section 7 of RFC 9052: a COSE Key Set is an array of COSE Keys.
    assert isinstance(cose_key_set, list)
    assert cose_key_set

    for cose_key in cose_key_set:
        assert isinstance(cose_key, dict)
        # kty, crv, x, y, kid for the ES256 keys the emulator signs with.
        assert cose_key[COSE_KEY_KTY] == COSE_KEY_TYPE_EC2
        assert cose_key[COSE_KEY_EC2_CRV] == COSE_KEY_CRV_P256
        assert isinstance(cose_key[COSE_KEY_EC2_X], bytes)
        assert isinstance(cose_key[COSE_KEY_EC2_Y], bytes)
        assert isinstance(cose_key[COSE_KEY_KID], bytes)


def test_kid_is_rfc_9679_cose_key_thumbprint(service):
    """
    Section 2.2 RECOMMENDS the RFC 9679 COSE Key Thumbprint as the mechanism
    to assign a kid, so that independent parties compute the same kid.
    """
    cose_key_set = cbor2.loads(
        httpx.get(f"{service.url}/.well-known/scitt-keys").content
    )

    for cose_key in cose_key_set:
        assert cose_key[COSE_KEY_KID] == cose_key_thumbprint(cose_key)


def test_individual_key_by_base64url_kid(service):
    """
    Section 2.2: for every kid value used by the service, this resource MUST
    accept the base64url encoding of the kid value, without padding.
    """
    cose_key_set = cbor2.loads(
        httpx.get(f"{service.url}/.well-known/scitt-keys").content
    )
    cose_key = cose_key_set[0]
    kid_value = base64url_encode(cose_key[COSE_KEY_KID])
    assert "=" not in kid_value

    response = httpx.get(
        f"{service.url}/.well-known/scitt-keys/{kid_value}",
        headers={"Accept": "application/cbor"},
    )

    assert response.status_code == 200
    assert response.headers["content-type"].split(";")[0].strip() == "application/cbor"
    # A single COSE Key, not a key set.
    resolved = cbor2.loads(response.content)
    assert isinstance(resolved, dict)
    assert resolved == cose_key


def test_individual_key_not_found(service):
    """
    Section 2.2: a 404 status if no matching key is found, with a Concise
    Problem Details body.
    """
    kid_value = base64url_encode(b"no such key")

    response = httpx.get(f"{service.url}/.well-known/scitt-keys/{kid_value}")

    assert response.status_code == 404
    assert (
        response.headers["content-type"].split(";")[0].strip()
        == PROBLEM_DETAILS_CONTENT_TYPE
    )
    problem_details = cbor2.loads(response.content)
    assert problem_details[-1] == "No such key"


def test_transparency_configuration_is_deprecated(service):
    """
    The transparency configuration resource is from an early SCRAPI revision
    and no longer appears in the document. It is retained for existing
    consumers, and marked deprecated pointing at its replacement.
    """
    response = httpx.get(f"{service.url}/.well-known/transparency-configuration")

    assert response.status_code == 200
    assert response.headers["Deprecation"] == "true"
    assert "/.well-known/scitt-keys" in response.headers["Link"]


def test_kid_url_segments_for_uri_safe_kid():
    """
    Section 2.2: if a kid value is safe for use as a URI path segment without
    percent-encoding, this resource MUST also accept the kid value itself.
    """
    assert kid_url_segments(b"kid1") == ["a2lkMQ", "kid1"]
    # Raw thumbprint bytes are not URI-safe, so only base64url is offered.
    assert kid_url_segments(bytes(range(32))) == [base64url_encode(bytes(range(32)))]


def test_registration_location_is_the_receipt_resource(service_either_mode):
    """
    Section 2.3.1 and Section 2.3.2: the response MUST contain a Location
    header field whose value is the URL of the (eventual) Receipt resource.
    """
    service = service_either_mode
    response = register(service, signed_statement())

    assert response.status_code in (201, 202)
    location = response.headers["Location"]
    assert location.startswith(f"{service.url}/entries/")


def test_registration_modes_agree_on_location(tmp_path):
    """
    Section 2.3.1: Transparency Services that support both synchronous and
    asynchronous registration MUST return the same Location URL for the same
    registered Signed Statement regardless of which registration mode was
    used.
    """
    claim = signed_statement()

    with make_service(tmp_path / "sync", use_lro=False) as service:
        sync_location = register(service, claim).headers["Location"]
        sync_entry_id = sync_location.rsplit("/", 1)[-1]

    with make_service(tmp_path / "async", use_lro=True) as service:
        async_location = register(service, claim).headers["Location"]
        async_entry_id = async_location.rsplit("/", 1)[-1]

    assert sync_entry_id == async_entry_id


def test_synchronous_registration_returns_the_receipt(service):
    """
    Section 2.3.1, Status 201: if the Transparency Service is able to produce
    a Receipt within a reasonable time, it MAY return it directly, as
    application/cose.
    """
    response = register(service, signed_statement())

    assert response.status_code == 201
    assert response.headers["content-type"].split(";")[0].strip() == "application/cose"
    assert response.content
    # The same bytes are served from the Receipt resource named by Location.
    resolved = httpx.get(response.headers["Location"])
    assert resolved.status_code == 200
    assert resolved.content == response.content


def test_asynchronous_registration_returns_202_then_the_receipt(tmp_path):
    """
    Section 2.3.2 and the sequence in Section 2.4.3: 202 with a Location, then
    the client polls that resource until it returns 200 with the Receipt.
    """
    with make_service(tmp_path, use_lro=True) as service:
        response = register(service, signed_statement())

        assert response.status_code == 202
        assert response.headers["Retry-After"]
        assert response.content == b""
        location = response.headers["Location"]

        # Section 2.4.2, Status 204: registration is running.
        running = httpx.get(location, headers={"Accept": "application/cose"})
        assert running.status_code == 204
        assert running.headers["Cache-Control"] == "no-store"
        assert running.headers["Retry-After"]

        # Section 2.4.1, Status 200: the Receipt is available.
        done = httpx.get(location, headers={"Accept": "application/cose"})
        assert done.status_code == 200
        assert (
            done.headers["content-type"].split(";")[0].strip() == "application/cose"
        )
        assert done.headers["Location"] == location
        assert done.content


def test_receipt_resource_serves_repeated_reads(service):
    """
    Section 2.4: the Receipt resource may be used at any later time to obtain
    a fresh Receipt for a previously registered Signed Statement.
    """
    location = register(service, signed_statement()).headers["Location"]

    for _ in range(3):
        response = httpx.get(location, headers={"Accept": "application/cose"})
        assert response.status_code == 200
        assert response.content


def test_receipt_resource_not_found(service):
    """
    Section 2.4.3: if there is no Receipt found for the specified EntryID the
    Transparency Service MUST respond with a 4xx-class status code and a
    Concise Problem Details object.
    """
    response = httpx.get(f"{service.url}/entries/no-such-entry")

    assert response.status_code == 404
    problem_details = cbor2.loads(response.content)
    assert problem_details[-1] == "Not Found"
    assert "no-such-entry" in problem_details[-2]


def test_deprecated_receipt_subresource(service):
    """
    The /entries/{entryId}/receipt sub-resource is from an early SCRAPI
    revision; Section 2.4 makes the entry resource itself the Receipt
    resource. It is retained and marked deprecated.
    """
    location = register(service, signed_statement()).headers["Location"]
    entry_id = location.rsplit("/", 1)[-1]

    response = httpx.get(f"{service.url}/entries/{entry_id}/receipt")

    assert response.status_code == 200
    assert response.headers["Deprecation"] == "true"
    assert response.headers["Link"] == f'<{location}>; rel="successor-version"'
    assert response.content == httpx.get(location).content


def test_every_error_response_is_concise_problem_details(service):
    """
    Section 2: if the Transparency Service cannot process a client's request
    it MUST return a 4xx or 5xx status code and the body MUST be a Concise
    Problem Details object.

    Flask generates HTML for unrouted paths, rejected methods and the like, so
    those responses have to be converted too, not just the ones the resource
    handlers produce.
    """
    responses = [
        httpx.get(f"{service.url}/entries/" + "x" * 300),
        httpx.get(f"{service.url}/no-such-resource"),
        httpx.request("DELETE", f"{service.url}/entries"),
        httpx.get(f"{service.url}/entries/"),
    ]

    for response in responses:
        assert 400 <= response.status_code < 600, response.status_code
        assert (
            response.headers["content-type"].split(";")[0].strip()
            == PROBLEM_DETAILS_CONTENT_TYPE
        ), response.headers.get("content-type")
        problem_details = cbor2.loads(response.content)
        assert isinstance(problem_details[-1], str)
        assert isinstance(problem_details[-2], str)


def test_invalid_locator(service):
    """
    Section 2.3.3 defines the "Invalid locator" error for an operation locator
    that is not in a valid form.
    """
    response = httpx.get(f"{service.url}/entries/" + "x" * 300)

    assert response.status_code == 400
    problem_details = cbor2.loads(response.content)
    assert problem_details[-1] == "Invalid locator"
    assert problem_details[-2] == "Operation locator is not in a valid form"


def test_malformed_statement_in_asynchronous_mode_reaches_a_terminal_404(tmp_path):
    """
    A Signed Statement that cannot be registered at all is the 400 of Section
    2.3.3 in synchronous mode. In asynchronous mode the request that would
    have carried it is long gone, so it must become the 404 of Section 2.4.3
    with detail, and must stay that way rather than failing on every poll.
    """
    with make_service(tmp_path, use_lro=True) as service:
        response = httpx.post(
            f"{service.url}/entries",
            content=b"not a COSE message",
            headers={"Content-Type": "application/cose"},
        )
        assert response.status_code == 202
        location = response.headers["Location"]

        assert httpx.get(location).status_code == 204
        for _ in range(3):
            failed = httpx.get(location)
            assert failed.status_code == 404
            assert (
                failed.headers["content-type"].split(";")[0].strip()
                == PROBLEM_DETAILS_CONTENT_TYPE
            )
            assert cbor2.loads(failed.content)[-1] == "Registration Failed"

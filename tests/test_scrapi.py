# Copyright (c) SCITT Authors
# Licensed under the MIT License.
"""
Conformance tests for the HTTP resources defined by
draft-ietf-scitt-scrapi-11.
"""
import cbor2
import httpx
import pytest

from scitt_emulator import server
from scitt_emulator.client import describe_error_response
from scitt_emulator.errors import CONTENT_TYPE as PROBLEM_DETAILS_CONTENT_TYPE

from .test_cli import Service


@pytest.fixture
def service(tmp_path):
    with Service(
        {
            "tree_alg": "CCF",
            "workspace": tmp_path / "workspace",
            "error_rate": 0,
            "use_lro": False,
        }
    ) as service:
        yield service


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

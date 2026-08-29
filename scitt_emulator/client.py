# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from typing import Optional
from pathlib import Path
import json
import random
import time

import httpx

from scitt_emulator import create_statement
from scitt_emulator.errors import CONTENT_TYPE as PROBLEM_DETAILS_CONTENT_TYPE, decode_problem_details
from scitt_emulator.tree_algs import TREE_ALGS

DEFAULT_URL = "http://127.0.0.1:8000"
CONNECT_RETRIES = 3
HTTP_RETRIES = 3

# Section 5.1 of draft-ietf-scitt-scrapi-11: "Clients that retry a request
# MUST honor any Retry-After header field ... treating it as a minimum
# interval before retrying. In its absence, clients that retry a request MUST
# apply exponential backoff with jitter, cap the total number of retries, and
# avoid synchronizing retries across clients."
HTTP_DEFAULT_RETRY_DELAY = 1
# Upper bound on the backoff, regardless of attempts.
HTTP_MAX_RETRY_DELAY = 32
# Section 5.1 constrains clients that retry; it does not oblige a client to
# retry at all. When the service asks for a longer wait than this, retrying
# would just block the caller, so the error is reported and the caller decides
# whether to come back. Honoring Retry-After as a minimum means never sleeping
# less than it asks, not sleeping arbitrarily long.
HTTP_MAX_RETRY_AFTER_WAIT = 30
# The cap on polling a registration to completion. Registration latency is
# unbounded in principle, so this is a client policy, not a protocol limit.
REGISTRATION_POLL_ATTEMPTS = 20


# Section 2 of draft-ietf-scitt-scrapi-11: clients MUST be prepared to handle
# any HTTP status code by falling back to the generic class semantics of the
# response, and MUST rely on the RFC 9290 Concise Problem Details object (when
# present) rather than the status code alone.
HTTP_STATUS_CLASS_SEMANTICS = {
    1: "Informational",
    2: "Successful",
    3: "Redirection",
    4: "Client Error",
    5: "Server Error",
}


class ClaimOperationError(Exception):
    def __init__(self, operation):
        self.operation = operation

    def __str__(self):
        error_type = self.operation.get("error", {}).get(
            "type", "error.type not present",
        )
        error_detail = self.operation.get("error", {}).get(
            "detail", "error.detail not present",
        )
        return f"Operation error {error_type}: {error_detail}"


def describe_error_response(response: httpx.Response) -> str:
    """
    Describe an error response, preferring the Concise Problem Details object
    over the status code, and falling back to the status code's class when the
    body is absent or not a valid problem details object.
    """
    status_class = HTTP_STATUS_CLASS_SEMANTICS.get(
        response.status_code // 100, "Unknown"
    )
    described = f"HTTP {response.status_code} ({status_class})"
    content_type = response.headers.get("content-type", "")
    if content_type.split(";")[0].strip() == PROBLEM_DETAILS_CONTENT_TYPE:
        try:
            problem_details = decode_problem_details(response.content)
        except ValueError:
            pass
        else:
            title = problem_details.get("title", "")
            detail = problem_details.get("detail", "")
            return f"{described}: {title}: {detail}".rstrip(": ")
    return described


def raise_for_status(response: httpx.Response):
    if response.is_success:
        return
    raise RuntimeError(describe_error_response(response))


def raise_for_operation_status(operation: dict):
    if operation["status"] != "failed":
        return
    raise ClaimOperationError(operation)



def retry_after_seconds(response: httpx.Response) -> Optional[float]:
    """
    The Retry-After interval the service asked for, if it sent one this client
    can parse.

    Retry-After may also be an HTTP-date, which this client does not parse;
    None is returned so the caller backs off rather than retrying at once.
    """
    retry_after = response.headers.get("retry-after")
    if retry_after is None:
        return None
    try:
        return max(0.0, float(int(retry_after)))
    except ValueError:
        return None


def retry_delay(response: httpx.Response, attempt: int) -> float:
    """
    How long to wait before retrying, per Section 5.1.

    Retry-After is honored as a minimum interval when the service sends one.
    Otherwise the delay doubles per attempt, and full jitter is applied so
    that clients retrying against the same service do not synchronize.
    """
    retry_after = retry_after_seconds(response)
    if retry_after is not None:
        return retry_after
    backoff = min(HTTP_DEFAULT_RETRY_DELAY * (2 ** attempt), HTTP_MAX_RETRY_DELAY)
    return random.uniform(0, backoff)


def worth_retrying(response: httpx.Response) -> bool:
    """
    Whether to retry at all.

    Section 5.1 constrains a client that retries; it does not require one to.
    A service asking for a longer wait than this client is willing to block
    for is better reported than slept through.
    """
    if response.status_code not in HttpClient.RETRIABLE_STATUS_CODES:
        return False
    retry_after = retry_after_seconds(response)
    return retry_after is None or retry_after <= HTTP_MAX_RETRY_AFTER_WAIT



class HttpClient:
    def __init__(self, bearer_token: Optional[str] = None, cacert: Optional[Path] = None):
        headers = {}
        if bearer_token is not None:
            headers["Authorization"] = f"Bearer {bearer_token}"
        verify = True if cacert is None else str(cacert)
        transport = httpx.HTTPTransport(retries=CONNECT_RETRIES, verify=verify)
        self.client = httpx.Client(transport=transport, headers=headers)

    # Section 2 of draft-ietf-scitt-scrapi-11 has clients fall back to the
    # generic class semantics of a status code. 503 is retried because
    # Section 15.6.4 of RFC 9110 makes it transient; 429 is retried because
    # Section 5.3 defines it as the service asking the client to slow down.
    RETRIABLE_STATUS_CODES = (429, 503)

    def _request(self, *args, **kwargs):
        response = self.client.request(*args, **kwargs)
        for attempt in range(HTTP_RETRIES):
            if not worth_retrying(response):
                break
            time.sleep(retry_delay(response, attempt))
            response = self.client.request(*args, **kwargs)
        raise_for_status(response)
        return response

    def get(self, *args, **kwargs):
        return self._request("GET", *args, **kwargs)

    def post(self, *args, **kwargs):
        return self._request("POST", *args, **kwargs)


def submit_claim(
    url: str,
    claim_path: Path,
    receipt_path: Path,
    entry_id_path: Optional[Path],
    client: HttpClient,
):
    """
    Register a Signed Statement and retrieve its Receipt, following Section 2.3
    and Section 2.4 of draft-ietf-scitt-scrapi-11.
    """
    with open(claim_path, "rb") as f:
        claim = f.read()

    response = client.post(
        f"{url}/entries",
        content=claim,
        headers={
            "Content-Type": "application/cose",
            "Accept": "application/cose",
        },
    )

    # Section 2.3.1 and Section 2.3.2: the response MUST contain a Location
    # header field whose value is the URL of the (eventual) Receipt resource.
    receipt_url = response.headers.get("location")
    if not receipt_url:
        raise RuntimeError(
            f"Registration response with status {response.status_code} has no "
            f"Location header naming the Receipt resource"
        )
    entry_id = receipt_url.rstrip("/").rsplit("/", 1)[-1]

    if response.status_code == 201:
        # Section 2.3.1: the Receipt is returned directly.
        receipt = response.content
    elif response.status_code == 202:
        # Section 2.4: poll the Receipt resource. 204 means registration is
        # still running; 200 means the Receipt is available. Anything else is
        # raised by the client's status handling.
        # Section 5.1 requires a cap on the total number of retries, so
        # polling does not continue indefinitely against a service that never
        # reaches finality.
        receipt = None
        for attempt in range(REGISTRATION_POLL_ATTEMPTS):
            time.sleep(retry_delay(response, attempt))
            response = client.get(receipt_url, headers={"Accept": "application/cose"})
            if response.status_code == 200:
                receipt = response.content
                break
        if receipt is None:
            raise RuntimeError(
                f"Registration did not complete after "
                f"{REGISTRATION_POLL_ATTEMPTS} polls of {receipt_url!r}"
            )
    else:
        raise RuntimeError(f"Unexpected status code: {response.status_code}")

    print("Claim Registered:")
    print(f"  Entry ID: {entry_id}")
    print(f"  Receipt:  {receipt_url}")

    # Save receipt to file
    with open(receipt_path, "wb") as f:
        f.write(receipt)

    print(f"  Receipt:  ./{receipt_path}")

    # Save entry ID to file
    if entry_id_path:
        with open(entry_id_path, "w") as f:
            f.write(str(entry_id))

        print(f"Entry ID written to {entry_id_path}")


def retrieve_claim(url: str, entry_id: Path, claim_path: Path, client: HttpClient):
    # SCRAPI defines no resource for reading back a registered Signed
    # Statement; this is an emulator extension.
    response = client.get(f"{url}/entries/{entry_id}/statement")
    claim = response.content

    with open(claim_path, "wb") as f:
        f.write(claim)

    print(f"A COSE signed Claim was written to: {claim_path}")


def retrieve_receipt(url: str, entry_id: Path, receipt_path: Path, client: HttpClient):
    # Section 2.4 of draft-ietf-scitt-scrapi-11: the entry resource is the
    # Receipt resource, and may be used at any time to obtain a fresh Receipt.
    response = client.get(
        f"{url}/entries/{entry_id}", headers={"Accept": "application/cose"}
    )
    receipt = response.content

    with open(receipt_path, "wb") as f:
        f.write(receipt)

    print(f"Receipt written to {receipt_path}")


def verify_receipt(cose_path: Path, receipt_path: Path, service_parameters_path: Path):
    with open(service_parameters_path) as f:
        service_parameters = json.load(f)

    clazz = TREE_ALGS[service_parameters["treeAlgorithm"]]
    service = clazz(service_parameters_path=service_parameters_path)
    service.verify_receipt(cose_path, receipt_path)
    print("Receipt verified")


def cli(fn):
    parser = fn(description="Execute client commands")
    sub = parser.add_subparsers(dest="cmd", help="Command to execute", required=True)

    create_statement.cli(sub.add_parser)

    p = sub.add_parser(
        "submit-claim", description="Submit a SCITT claim and retrieve the receipt"
    )
    p.add_argument("--claim", required=True, type=Path)
    p.add_argument(
        "--out", required=True, type=Path, help="Path to write the receipt to"
    )
    p.add_argument(
        "--out-entry-id",
        required=False,
        type=Path,
        help="Path to write the entry id to",
    )
    p.add_argument("--url", required=False, default=DEFAULT_URL)
    p.add_argument("--token", help="Bearer token to authenticate with")
    p.add_argument("--cacert", type=Path, help="CA certificate to verify host against")
    p.set_defaults(
        func=lambda args: submit_claim(
            args.url, args.claim, args.out, args.out_entry_id,
            HttpClient(args.token, args.cacert)
        )
    )

    p = sub.add_parser("retrieve-claim", description="Retrieve a SCITT claim")
    p.add_argument("--entry-id", required=True, type=str)
    p.add_argument("--out", required=True, type=Path, help="Path to write the claim to")
    p.add_argument("--url", required=False, default=DEFAULT_URL)
    p.add_argument("--token", help="Bearer token to authenticate with")
    p.add_argument("--cacert", type=Path, help="CA certificate to verify host against")
    p.set_defaults(
        func=lambda args: retrieve_claim(
            args.url, args.entry_id, args.out,
            HttpClient(args.token, args.cacert)
        )
    )

    p = sub.add_parser("retrieve-receipt", description="Retrieve a SCITT receipt")
    p.add_argument("--entry-id", required=True, type=str)
    p.add_argument(
        "--out", required=True, type=Path, help="Path to write the receipt to"
    )
    p.add_argument("--url", required=False, default=DEFAULT_URL)
    p.add_argument("--token", help="Bearer token to authenticate with")
    p.add_argument("--cacert", type=Path, help="CA certificate to verify host against")
    p.set_defaults(
        func=lambda args: retrieve_receipt(
            args.url, args.entry_id, args.out,
            HttpClient(args.token, args.cacert)
        )
    )

    p = sub.add_parser("verify-receipt", description="Verify a SCITT receipt")
    p.add_argument("--claim", required=True, type=Path)
    p.add_argument("--receipt", required=True, type=Path)
    p.add_argument("--service-parameters", required=True, type=Path)
    p.set_defaults(
        func=lambda args: verify_receipt(
            args.claim, args.receipt, args.service_parameters
        )
    )

    return parser

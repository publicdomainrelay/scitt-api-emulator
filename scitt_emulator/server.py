# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import os
import json
import re
from pathlib import Path
from io import BytesIO
import random

import jwt.api_jwt
import jwcrypto.jwt
import pycose.headers
from pycose.messages import Sign1Message
from flask import Flask, request, send_file, make_response, jsonify
from werkzeug.exceptions import HTTPException

from scitt_emulator.cose_keys import CONTENT_TYPE as COSE_KEY_CONTENT_TYPE
from scitt_emulator.cose_keys import (
    COSE_KEY_KID,
    base64url_decode,
    encode_cose_key,
    encode_cose_key_set,
)
from scitt_emulator.errors import CONTENT_TYPE as PROBLEM_DETAILS_CONTENT_TYPE, encode_problem_details
from scitt_emulator.tree_algs import TREE_ALGS
from scitt_emulator.verify_statement import verify_statement
from scitt_emulator.plugin_helpers import entrypoint_style_load
from scitt_emulator.rate_limit import RateLimiter, client_identity
from scitt_emulator.scitt import (
    EntryNotFoundError,
    ClaimInvalidError,
    OperationNotFoundError,
    RegistrationFailedError,
    RegistrationRunningError,
    PayloadMissingError,
    SignatureVerificationError,
    UnsupportedAlgorithmError,
)

# Section 2.3 of draft-ietf-scitt-scrapi-11: Signed Statements and Receipts are
# COSE, exchanged as application/cose.
COSE_CONTENT_TYPE = "application/cose"


def make_error(title: str, detail: str, status_code: int, headers: dict = None):
    """
    Build an error response as an RFC 9290 Concise Problem Details object, as
    required by Section 2 of draft-ietf-scitt-scrapi-11.
    """
    response = make_response(
        encode_problem_details(title, detail), status_code, headers or {}
    )
    response.headers["Content-Type"] = PROBLEM_DETAILS_CONTENT_TYPE
    return response


def make_unavailable_error():
    return make_error(
        "Service Unavailable",
        "The Transparency Service is unavailable, try again later",
        503,
        {"Retry-After": "1"},
    )


# EntryID path segments are unpadded base64url, Section 2.4 of draft-ietf-scitt-scrapi-11.
ENTRY_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")


def create_flask_app(config):
    app = Flask(__name__)

    # See http://flask.pocoo.org/docs/latest/config/
    app.config.update(dict(DEBUG=True))
    app.config.update(config)

    if app.config.get("middleware", None):
        app.wsgi_app = app.config["middleware"](app.wsgi_app, app.config.get("middleware_config_path", None))

    error_rate = app.config["error_rate"]
    use_lro = app.config["use_lro"]

    # Section 5.3 of draft-ietf-scitt-scrapi-11 requires rate limiting, and
    # requires a 429 with Retry-After when a client exceeds the limit.
    rate_limiter = RateLimiter(
        requests=app.config.get("rate_limit_requests", 0),
        period=app.config.get("rate_limit_period", 1),
    )

    workspace_path = app.config["workspace"]
    storage_path = workspace_path / "storage"
    os.makedirs(storage_path, exist_ok=True)
    app.service_parameters_path = workspace_path / "service_parameters.json"

    clazz = TREE_ALGS[app.config["tree_alg"]]

    app.scitt_service = clazz(
        storage_path=storage_path, service_parameters_path=app.service_parameters_path
    )
    app.scitt_service.initialize_service()
    # RFC 9943 Section 6.3 requires the Transparency Service to verify the
    # Signed Statement's signature at registration. The emulator's default is
    # permissive, for interoperability testing; --verify-signature turns the
    # verification on.
    app.scitt_service.service_parameters["verifySignature"] = app.config.get(
        "verify_signature", False
    )
    print(f"Service parameters: {app.service_parameters_path}")

    @app.errorhandler(HTTPException)
    def handle_http_exception(error: HTTPException):
        """
        Section 2 of draft-ietf-scitt-scrapi-11: the body of any 4xx or 5xx
        response MUST be a Concise Problem Details object. Flask generates
        HTML for unrouted paths, rejected methods and the like, so those are
        converted here rather than only in the handlers.
        """
        return make_error(
            error.name,
            error.description or error.name,
            error.code or 500,
        )

    @app.errorhandler(Exception)
    def handle_unexpected_exception(error: Exception):
        """
        An unhandled failure is still a 5xx whose body MUST be a Concise
        Problem Details object. The detail is deliberately generic; the
        traceback goes to the log, not to the client.
        """
        app.logger.exception("Unhandled error serving %s", request.path)
        return make_error(
            "Internal Server Error",
            "The Transparency Service failed to process the request",
            500,
        )

    @app.before_request
    def enforce_rate_limit():
        """
        Section 5.3: "When a client exceeds the configured rate limit, the
        Transparency Service MUST return a 429 response (see Section 2.3.4)
        including a Retry-After header field."

        Section 5.3 leaves the per-client policy to the implementation and
        notes it typically varies by whether the client is authenticated, so
        the limit is applied per bearer token where there is one and per
        source address otherwise.
        """
        if not rate_limiter.requests:
            return None
        retry_after = rate_limiter.check(
            client_identity(request.remote_addr, request.headers.get("Authorization"))
        )
        if retry_after is None:
            return None
        return make_error(
            "Too Many Requests",
            f"Only {rate_limiter.requests} requests per "
            f"{int(rate_limiter.period)} seconds are allowed.",
            429,
            {"Retry-After": str(retry_after)},
        )

    def is_unavailable():
        # Strictly less than, so that --error-rate 0 never fails.
        return random.random() < error_rate

    def receipt_url(entry_id: str) -> str:
        """
        The URL of the Receipt resource for an EntryID (Section 2.4 of
        draft-ietf-scitt-scrapi-11), used as the Location header on both
        registration responses and on the Receipt itself.
        """
        return f"{request.host_url.rstrip('/')}/entries/{entry_id}"

    @app.route("/.well-known/scitt-keys", methods=["GET"])
    def get_scitt_keys():
        """
        Section 2.1 of draft-ietf-scitt-scrapi-11: discover the public keys
        relying parties use to verify Receipts issued by this Transparency
        Service, as a COSE Key Set serialized as application/cbor.
        """
        if is_unavailable():
            return make_unavailable_error()
        cose_key_set = app.scitt_service.keys_as_cose_key_set()
        response = make_response(encode_cose_key_set(cose_key_set), 200)
        response.headers["Content-Type"] = COSE_KEY_CONTENT_TYPE
        return response

    @app.route("/.well-known/scitt-keys/<string:kid_value>", methods=["GET"])
    def get_scitt_key(kid_value: str):
        """
        Section 2.2 of draft-ietf-scitt-scrapi-11: resolve a single COSE Key
        from a kid value contained in a previously issued Receipt.

        The base64url form of the kid is always accepted. The raw kid is also
        accepted when it is safe as a URI path segment, and both forms
        identify the same key.
        """
        if is_unavailable():
            return make_unavailable_error()

        # The base64url form is the one Section 2.2 requires this resource to
        # accept for every kid, so it is tried first; the raw kid is accepted
        # only where it is safe as a path segment, so it is the fallback.
        # Serving the key set checks that no segment addresses two keys, which
        # is what makes trying both forms unambiguous.
        candidate_kids = []
        try:
            candidate_kids.append(base64url_decode(kid_value))
        except ValueError:
            pass
        candidate_kids.append(kid_value.encode("utf-8"))

        cose_key = None
        for candidate_kid in candidate_kids:
            cose_key = app.scitt_service.key_by_kid(candidate_kid)
            if cose_key is not None:
                break

        if cose_key is None:
            return make_error(
                "No such key", "No key could be found for this kid value", 404
            )

        response = make_response(encode_cose_key(cose_key), 200)
        response.headers["Content-Type"] = COSE_KEY_CONTENT_TYPE
        return response

    @app.route("/.well-known/transparency-configuration", methods=["GET"])
    def get_transparency_configuration():
        """
        Deprecated. This resource comes from an early SCRAPI revision and no
        longer appears in draft-ietf-scitt-scrapi-11, which replaced it with
        the COSE Key Set at /.well-known/scitt-keys. It is kept for existing
        consumers of the emulator and will be removed once SCRAPI is
        published. See docs/adrs/0003-cose-key-set-key-discovery.md.
        """
        if is_unavailable():
            return make_unavailable_error()
        response = jsonify(
            {
                 "issuer": "/",
                 "registration_endpoint": f"/entries",
                 "nonce_endpoint": f"/nonce",
                 "registration_policy": f"/statements/TODO",
                 "supported_signature_algorithms": ["ES256"],
                 "jwks": {
                      "keys": app.scitt_service.keys_as_jwks(),
                 }
            }
        )
        response.headers["Deprecation"] = "true"
        response.headers["Link"] = '</.well-known/scitt-keys>; rel="successor-version"'
        return response

    def resolve_receipt(entry_id: str):
        """
        Section 2.4 of draft-ietf-scitt-scrapi-11, Resolve Receipt: 200 once
        registration is complete and the Receipt is available, 204 while
        registration is still in progress, and 404 if no Receipt exists for
        the EntryID, including when registration has failed.
        """
        if not ENTRY_ID_RE.match(entry_id):
            # Section 2.3.3 of draft-ietf-scitt-scrapi-11 defines this error.
            return make_error(
                "Invalid locator", "Operation locator is not in a valid form", 400
            )
        try:
            receipt = app.scitt_service.get_entry_receipt(entry_id)
        except RegistrationRunningError:
            response = make_response(b"", 204)
            # Section 2.4.2: SHOULD include Retry-After to help with polling,
            # and SHOULD set Cache-Control: no-store because the in-progress
            # response is transient.
            response.headers["Retry-After"] = "1"
            response.headers["Cache-Control"] = "no-store"
            return response
        except RegistrationFailedError as e:
            # Section 2.4.3: a 404 is also returned when an asynchronous
            # registration has failed, and MAY be enriched with detail
            # explaining why registration did not complete.
            return make_error("Registration Failed", str(e), 404)
        except EntryNotFoundError as e:
            return make_error("Not Found", str(e), 404)

        response = make_response(receipt, 200)
        response.headers["Content-Type"] = COSE_CONTENT_TYPE
        response.headers["Location"] = receipt_url(entry_id)
        return response

    @app.route("/entries/<string:entry_id>", methods=["GET"])
    def get_entry_receipt(entry_id: str):
        """Section 2.4 of draft-ietf-scitt-scrapi-11, Resolve Receipt."""
        if is_unavailable():
            return make_unavailable_error()
        return resolve_receipt(entry_id)

    @app.route("/entries/<string:entry_id>/receipt", methods=["GET"])
    def get_receipt(entry_id: str):
        """
        Deprecated. Section 2.4 of draft-ietf-scitt-scrapi-11 makes the entry
        resource itself the Receipt resource. Retained so existing consumers
        of the emulator keep working.
        """
        if is_unavailable():
            return make_unavailable_error()
        response = resolve_receipt(entry_id)
        response.headers["Deprecation"] = "true"
        response.headers["Link"] = f'<{receipt_url(entry_id)}>; rel="successor-version"'
        return response

    @app.route("/entries/<string:entry_id>/statement", methods=["GET"])
    def get_claim(entry_id: str):
        """
        Retrieve the registered Signed Statement.

        SCRAPI defines no resource for this; it is an emulator extension, kept
        because the bundled client and the interoperability tests rely on
        being able to read back what was registered. It moved here from
        /entries/{entryId}, which Section 2.4 makes the Receipt resource.
        """
        if is_unavailable():
            return make_unavailable_error()
        if not ENTRY_ID_RE.match(entry_id):
            return make_error(
                "Invalid locator", "Operation locator is not in a valid form", 400
            )
        try:
            claim = app.scitt_service.get_claim(entry_id)
        except EntryNotFoundError as e:
            return make_error("Not Found", str(e), 404)
        return send_file(BytesIO(claim), download_name=f"{entry_id}.cose")

    @app.route("/entries", methods=["POST"])
    def submit_claim():
        """
        Section 2.3 of draft-ietf-scitt-scrapi-11, Register Signed Statement.

        Returns 201 with the Receipt when one can be produced in a reasonable
        time, or 202 when it cannot. Either way the Location header names the
        Receipt resource, and Section 2.3.1 requires it to be the same URL for
        the same Signed Statement whichever mode was used.
        """
        if is_unavailable():
            return make_unavailable_error()
        try:
            result = app.scitt_service.submit_claim(
                request.get_data(), long_running=use_lro
            )
        except PayloadMissingError as e:
            return make_error("Payload Missing", str(e), 400)
        except UnsupportedAlgorithmError as e:
            return make_error("Bad Signature Algorithm", str(e), 400)
        except SignatureVerificationError as e:
            return make_error("Rejected", str(e), 400)
        except ClaimInvalidError as e:
            return make_error("Malformed request", str(e), 400)

        entry_id = result["entryId"]
        location = receipt_url(entry_id)

        if result["status"] == "succeeded":
            # Section 2.3.1: if the Transparency Service is able to produce a
            # Receipt within a reasonable time, it MAY return it directly.
            receipt = app.scitt_service.get_entry_receipt(entry_id)
            response = make_response(receipt, 201)
            response.headers["Content-Type"] = COSE_CONTENT_TYPE
            response.headers["Location"] = location
            return response

        # Section 2.3.2: the registration request is accepted but no Receipt
        # can be produced in a reasonable time.
        response = make_response(b"", 202)
        response.headers["Location"] = location
        response.headers["Retry-After"] = "1"
        return response

    @app.route("/operations/<string:operation_id>", methods=["GET"])
    def get_operation(operation_id: str):
        """
        Deprecated. Operations are not a SCRAPI concept; Section 2.4 of
        draft-ietf-scitt-scrapi-11 has clients poll the Receipt resource
        instead. Retained so existing consumers of the emulator keep working.
        """
        if is_unavailable():
            return make_unavailable_error()
        if not ENTRY_ID_RE.match(operation_id):
            return make_error(
                "Invalid locator", "Operation locator is not in a valid form", 400
            )
        try:
            operation = app.scitt_service.get_operation(operation_id)
        except OperationNotFoundError as e:
            return make_error("Not Found", str(e), 404)
        headers = {
            "Deprecation": "true",
            "Link": f'<{receipt_url(operation_id)}>; rel="successor-version"',
        }
        if operation["status"] == "running":
            headers["Retry-After"] = "1"
        return make_response(operation, 200, headers)

    return app


def cli(fn):
    parser = fn()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("-p", "--port", type=int, default=8000)
    parser.add_argument("--error-rate", type=float, default=0.01)
    parser.add_argument(
        "--rate-limit-requests",
        type=int,
        default=0,
        help="Requests allowed per client per --rate-limit-period, per "
        "Section 5.3 of draft-ietf-scitt-scrapi-11. 0 disables rate limiting.",
    )
    parser.add_argument(
        "--rate-limit-period",
        type=float,
        default=1.0,
        help="Length in seconds of the rate limit window",
    )
    parser.add_argument("--use-lro", action="store_true", help="Create operations for submissions")
    parser.add_argument("--tree-alg", required=True, choices=list(TREE_ALGS.keys()))
    parser.add_argument("--workspace", type=Path, default=Path("workspace"))
    parser.add_argument(
        "--middleware",
        type=lambda value: list(entrypoint_style_load(value))[0],
        nargs="*",
        default=[],
    )
    parser.add_argument("--middleware-config-path", type=Path, nargs="*", default=[])
    parser.add_argument(
        "--verify-signature",
        action="store_true",
        help="Verify each Signed Statement's signature at registration, per "
        "Section 6.3 of RFC 9943",
    )

    def cmd(args):
        app = create_flask_app(
            {
                "middleware": args.middleware,
                "middleware_config_path": args.middleware_config_path,
                "tree_alg": args.tree_alg,
                "workspace": args.workspace,
                "error_rate": args.error_rate,
                "use_lro": args.use_lro,
                "rate_limit_requests": args.rate_limit_requests,
                "rate_limit_period": args.rate_limit_period,
                "verify_signature": args.verify_signature,
            }
        )
        app.host = args.host
        app.port = args.port
        app.run(host=args.host, port=args.port)

    parser.set_defaults(func=cmd)

    return parser

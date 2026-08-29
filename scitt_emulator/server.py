# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import os
import json
from pathlib import Path
from io import BytesIO
import random

import jwt.api_jwt
import jwcrypto.jwt
import pycose.headers
from pycose.messages import Sign1Message
from flask import Flask, request, send_file, make_response, jsonify

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
from scitt_emulator.scitt import EntryNotFoundError, ClaimInvalidError, OperationNotFoundError


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


def create_flask_app(config):
    app = Flask(__name__)

    # See http://flask.pocoo.org/docs/latest/config/
    app.config.update(dict(DEBUG=True))
    app.config.update(config)

    if app.config.get("middleware", None):
        app.wsgi_app = app.config["middleware"](app.wsgi_app, app.config.get("middleware_config_path", None))

    error_rate = app.config["error_rate"]
    use_lro = app.config["use_lro"]

    workspace_path = app.config["workspace"]
    storage_path = workspace_path / "storage"
    os.makedirs(storage_path, exist_ok=True)
    app.service_parameters_path = workspace_path / "service_parameters.json"

    clazz = TREE_ALGS[app.config["tree_alg"]]

    app.scitt_service = clazz(
        storage_path=storage_path, service_parameters_path=app.service_parameters_path
    )
    app.scitt_service.initialize_service()
    print(f"Service parameters: {app.service_parameters_path}")

    def is_unavailable():
        return random.random() <= error_rate

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

        candidate_kids = [kid_value.encode("utf-8")]
        try:
            candidate_kids.append(base64url_decode(kid_value))
        except Exception:
            pass

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

    @app.route("/entries/<string:entry_id>/receipt", methods=["GET"])
    def get_receipt(entry_id: str):
        if is_unavailable():
            return make_unavailable_error()
        try:
            receipt = app.scitt_service.get_receipt(entry_id)
        except EntryNotFoundError as e:
            return make_error("Not Found", str(e), 404)
        return send_file(BytesIO(receipt), download_name=f"{entry_id}.receipt.cbor")

    @app.route("/entries/<string:entry_id>", methods=["GET"])
    def get_claim(entry_id: str):
        if is_unavailable():
            return make_unavailable_error()
        try:
            claim = app.scitt_service.get_claim(entry_id)
        except EntryNotFoundError as e:
            return make_error("Not Found", str(e), 404)
        return send_file(BytesIO(claim), download_name=f"{entry_id}.cose")

    @app.route("/entries", methods=["POST"])
    def submit_claim():
        if is_unavailable():
            return make_unavailable_error()
        try:
            if use_lro:
                result = app.scitt_service.submit_claim(request.get_data(), long_running=True)
                headers = {
                    "Location": f"{request.host_url}/operations/{result['operationId']}",
                    "Retry-After": "1"
                }
                status_code = 202
            else:
                result = app.scitt_service.submit_claim(request.get_data(), long_running=False)
                headers = {
                    "Location": f"{request.host_url}/entries/{result['entryId']}",
                }
                status_code = 201
        except ClaimInvalidError as e:
            return make_error("Malformed request", str(e), 400)
        return make_response(result, status_code, headers)

    @app.route("/operations/<string:operation_id>", methods=["GET"])
    def get_operation(operation_id: str):
        if is_unavailable():
            return make_unavailable_error()
        try:
            operation = app.scitt_service.get_operation(operation_id)
        except OperationNotFoundError as e:
            return make_error("Not Found", str(e), 404)
        headers = {}
        if operation["status"] == "running":
            headers["Retry-After"] = "1"
        return make_response(operation, 200, headers)

    return app


def cli(fn):
    parser = fn()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("-p", "--port", type=int, default=8000)
    parser.add_argument("--error-rate", type=float, default=0.01)
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

    def cmd(args):
        app = create_flask_app(
            {
                "middleware": args.middleware,
                "middleware_config_path": args.middleware_config_path,
                "tree_alg": args.tree_alg,
                "workspace": args.workspace,
                "error_rate": args.error_rate,
                "use_lro": args.use_lro
            }
        )
        app.host = args.host
        app.port = args.port
        app.run(host=args.host, port=args.port)

    parser.set_defaults(func=cmd)

    return parser

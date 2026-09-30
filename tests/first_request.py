# Copyright (c) SCITT Authors
# Licensed under the MIT License.
"""
Register one Signed Statement against a service started in this process, and
print the status code it answered.

Run as `python -m tests.first_request <statement> <workspace>` from the
repository root.

The point is the *process*. This module imports `scitt_emulator.server` and
nothing else from the package, so the request it makes is the first a real
service ever serves and the first COSE message that process ever decodes. A
test that started the service inside pytest would share an interpreter where
every module of the package is already imported, and the ordering under test
would be satisfied before the test ran.
"""

import contextlib
import pathlib
import sys
import threading
import urllib.error
import urllib.request

import cbor2
import pycose.headers
from werkzeug.serving import make_server

import scitt_emulator.server

# COSE header label 15, RFC 9597: the CWT Claims Set. The label the emulator
# registers under this module's import, and the one a Signed Statement cannot
# be verified without.
CWT_CLAIMS_ID = 15


def main(argv):
    statement = pathlib.Path(argv[1]).read_bytes()
    workspace = pathlib.Path(argv[2])

    # The invariant the request depends on: importing the module that serves
    # submissions is enough to decode one. pycose resolves a header label to a
    # class at decode time and keys its header dictionary by that class, so a
    # label registered afterwards decodes as a bare integer and every lookup
    # by class fails.
    registered = pycose.headers.CoseHeaderAttribute.get_registered_classes()
    if CWT_CLAIMS_ID not in registered:
        print(
            f"importing scitt_emulator.server did not register COSE label "
            f"{CWT_CLAIMS_ID}",
            file=sys.stderr,
        )
        return 2

    if "scitt_emulator.create_statement" in sys.modules:
        print(
            "scitt_emulator.create_statement was imported to serve a "
            "submission, so it cannot be told which import did the "
            "registering; the module that decodes must register, not the "
            "module that creates",
            file=sys.stderr,
        )
        return 3

    # The service prints its start-up and every receipt it writes. That
    # chatter goes to stderr so this module's stdout carries one line and one
    # line only: the status, which is the whole protocol.
    with contextlib.redirect_stdout(sys.stderr):
        app = scitt_emulator.server.create_flask_app(
            {
                "middleware": [],
                "middleware_config_path": [],
                "workspace": workspace,
                "error_rate": 0,
                "use_lro": False,
                "rate_limit_requests": 0,
                "rate_limit_period": 1.0,
                "verify_signature": True,
            }
        )
        server = make_server("127.0.0.1", 0, app, threaded=True)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{server.port}/entries",
                data=statement,
                headers={
                    "Content-Type": "application/cose",
                    "Accept": "application/cose",
                },
            )
            try:
                with urllib.request.urlopen(request) as response:
                    status = response.status
            except urllib.error.HTTPError as error:
                status = error.code
                print(_problem_details(error.read()), file=sys.stderr)
        finally:
            server.shutdown()
            thread.join()

    print(status)
    return 0 if status in (201, 202) else 1


def _problem_details(body: bytes) -> str:
    """A refusal, as RFC 9290 problem details when it is one."""
    try:
        return repr(cbor2.loads(body))
    except Exception:
        return repr(body)


if __name__ == "__main__":
    sys.exit(main(sys.argv))

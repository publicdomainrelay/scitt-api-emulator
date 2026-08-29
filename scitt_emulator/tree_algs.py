# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from typing import Mapping
from scitt_emulator.scitt import SCITTServiceEmulator
from scitt_emulator.ccf import CCFSCITTServiceEmulator
from scitt_emulator.rfc9162_sha256 import RFC9162SHA256SCITTServiceEmulator

TREE_ALGS: Mapping[str, SCITTServiceEmulator] = {
    # RFC9162_SHA256 is the Verifiable Data Structure of RFC 9942, and the one
    # whose Receipts are COSE Sign1 messages as Section 7 of RFC 9943
    # describes. CCF predates those documents and produces a structure with no
    # counterpart in them; see docs/adrs/0005-cose-receipts.md.
    "RFC9162_SHA256": RFC9162SHA256SCITTServiceEmulator,
    "CCF": CCFSCITTServiceEmulator,
}

try:
    # The RKVST tree algorithm depends on the "archivist" client library, which
    # is not published to PyPI. Register it only when it can be imported so the
    # rest of the emulator remains usable without it.
    from scitt_emulator.rkvst import RKVSTSCITTServiceEmulator
except ImportError:  # pragma: no cover
    pass
else:
    TREE_ALGS["RKVST"] = RKVSTSCITTServiceEmulator

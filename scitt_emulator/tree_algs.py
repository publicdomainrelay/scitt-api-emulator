# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from typing import Mapping
from scitt_emulator.scitt import SCITTServiceEmulator
from scitt_emulator.ccf import CCFSCITTServiceEmulator

TREE_ALGS: Mapping[str, SCITTServiceEmulator] = {
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

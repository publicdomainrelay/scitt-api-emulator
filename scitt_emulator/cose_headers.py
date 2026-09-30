# Copyright (c) SCITT Authors
# Licensed under the MIT License.
"""
The COSE header parameters RFC 9943 puts in a Signed Statement and a Receipt,
and the registration that makes pycose decode them.

None of the four is in the registry pycose ships. RFC 9597 registers label 15
and RFC 9942 registers 394, 395 and 396, but pycose carries neither; without
a class registered under a label, pycose decodes that label as a bare integer.

Registration is a side effect of importing this module, and **the import has
to happen before the first decode in the process**. pycose maps a label to a
registered class at decode time and keys its header dictionary by that class,
whose `__hash__` is the default identity hash -- so a header decoded before the
registration holds the integer `15` under no attribute at all, and a later
lookup by class raises `KeyError`. That is not a hypothetical: it is what made
the first submission to a freshly started `--verify-signature` service fail,
because the only import of this module used to be a lazy one inside
`verify_statement`, reached after `_validate_submission` had already decoded
the message.

`scitt.py` therefore imports this module at import time, and `_validate_submission`
-- the one place untrusted bytes are decoded -- is in that module. Nothing else
in the package should call `register_attribute`.

Readers here go by *identifier* rather than by class, so a header decoded
before registration still resolves. `SCITTServiceEmulator._validate_submission`
already read the algorithm that way, and the same tolerance belongs on every
parameter rather than on one of them.
"""

import pycose.headers

# RFC 9052 Section 3.1: the signature algorithm. pycose registers this one
# itself, and it is named here so the readers in this module all resolve their
# parameter the same way.
ALG_ID = 1
# RFC 9597: CWT Claims, Figure 3 of RFC 9943 requires it in the protected
# header of a Signed Statement and of a Receipt.
CWT_CLAIMS_ID = 15
# RFC 9943 Figure 7: the Receipts of a Transparent Statement, in the
# unprotected header of the statement.
RECEIPTS_ID = 394
# RFC 9942: the Verifiable Data Structure, in the protected header of a
# Receipt, naming the algorithm whose proofs the Receipt carries.
VDS_ID = 395
# RFC 9942: the Verifiable Data Structure Proofs, in the unprotected header of
# a Receipt, with inclusion proofs at -1 and consistency proofs at -2.
PROOFS_ID = 396


@pycose.headers.CoseHeaderAttribute.register_attribute()
class CWTClaims(pycose.headers.CoseHeaderAttribute):
    identifier = CWT_CLAIMS_ID
    fullname = "CWT_CLAIMS"


@pycose.headers.CoseHeaderAttribute.register_attribute()
class Receipts(pycose.headers.CoseHeaderAttribute):
    identifier = RECEIPTS_ID
    fullname = "RECEIPTS"


@pycose.headers.CoseHeaderAttribute.register_attribute()
class VDS(pycose.headers.CoseHeaderAttribute):
    identifier = VDS_ID
    fullname = "VERIFIABLE_DATA_STRUCTURE"


@pycose.headers.CoseHeaderAttribute.register_attribute()
class Proofs(pycose.headers.CoseHeaderAttribute):
    identifier = PROOFS_ID
    fullname = "PROOFS"


def header_value(message, identifier):
    """
    The value of a protected header parameter, found by its COSE label.

    The key in the decoded header is a registered attribute class when the
    label was registered before the decode, and a bare integer when it was
    not. Both carry the label, so both are read here; looking one of them up
    by class is what fails.

    Only the protected header is searched. Every parameter this reads is
    required to be protected, and a reader that also accepted the unprotected
    header would accept a statement whose claims an intermediary can rewrite.
    """
    for attribute, value in message.phdr.items():
        if getattr(attribute, "identifier", attribute) == identifier:
            return value
    return None


def cwt_claims(message):
    """
    The CWT Claims Set of a Signed Statement or Receipt, or None.

    RFC 9597 makes the value of the CWT Claims parameter a plain CWT Claims
    Set -- a map of claim key to value, usually `{1: iss, 2: sub}` -- and not a
    nested, separately signed CWT.
    """
    return header_value(message, CWT_CLAIMS_ID)

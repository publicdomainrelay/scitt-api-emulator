# Copyright (c) SCITT Authors
# Licensed under the MIT License.
"""
COSE Key Set handling for the key discovery resources defined by Section 2.1
and Section 2.2 of draft-ietf-scitt-scrapi-11, and COSE Key Thumbprints as
specified by RFC 9679.
"""

import base64
import binascii
import hashlib
import re
from typing import Any, List

import cbor2

# RFC 9052 Section 7, "COSE Key Objects". A COSE Key Set is an array of
# COSE Keys; both are served as application/cbor.
CONTENT_TYPE = "application/cbor"

# RFC 9052 Table 4, "Key Common Parameters"
COSE_KEY_KTY = 1
COSE_KEY_KID = 2

# RFC 9053 Table 19, "EC Key Parameters"
COSE_KEY_EC2_CRV = -1
COSE_KEY_EC2_X = -2
COSE_KEY_EC2_Y = -3

# RFC 9052 Table 5, "COSE Key Types" / RFC 9053 Table 18, "Elliptic Curves"
COSE_KEY_TYPE_EC2 = 2
COSE_KEY_CRV_P256 = 1
COSE_KEY_CRV_P384 = 2
COSE_KEY_CRV_P521 = 3

# JOSE/JWK curve names to COSE EC2 crv labels, RFC 9053 Table 18.
JWK_CRV_TO_COSE_KEY_CRV = {
    "P-256": COSE_KEY_CRV_P256,
    "P-384": COSE_KEY_CRV_P384,
    "P-521": COSE_KEY_CRV_P521,
}

# RFC 9679 Section 3, "COSE Key Thumbprint": the required members for each key
# type, which are the only members included in the thumbprint computation.
COSE_KEY_THUMBPRINT_REQUIRED_LABELS = {
    1: (COSE_KEY_KTY, -1, -2),  # OKP: kty, crv, x
    2: (COSE_KEY_KTY, -1, -2, -3),  # EC2: kty, crv, x, y
    3: (COSE_KEY_KTY, -1, -2),  # RSA: kty, n, e
    4: (COSE_KEY_KTY, -1),  # Symmetric: kty, k
    5: (COSE_KEY_KTY, -1),  # HSS-LMS: kty, pub
}


# Section 2 of RFC 7515, quoted by Section 2.2 of draft-ietf-scitt-scrapi-11:
# the URL- and filename-safe alphabet of Section 5 of RFC 4648, with all
# trailing "=" omitted.
BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")


class UnsupportedKeyTypeError(Exception):
    pass


class AmbiguousKeyIdentifierError(Exception):
    """
    Two keys in the key set are identified by the same URL.

    Section 2.2 of draft-ietf-scitt-scrapi-11: "A Transparency Service MUST
    NOT use kid values whose raw and base64url forms would make the same URL
    identify different keys."
    """


def base64url_encode(value: bytes) -> str:
    """
    Base64url without padding, as Section 2 of RFC 7515 specifies and Section
    2.2 of draft-ietf-scitt-scrapi-11 references.

    >>> base64url_encode(b"scitt")
    'c2NpdHQ'
    """
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def base64url_decode(value: str) -> bytes:
    """
    Decode base64url without padding.

    Characters outside the base64url alphabet are rejected rather than
    silently discarded, so that a value which is not base64url is recognized
    as such rather than aliasing onto some other key's identifier.

    >>> base64url_decode("c2NpdHQ")
    b'scitt'
    >>> base64url_decode("not base64url!")
    Traceback (most recent call last):
    ValueError: ...
    """
    if not value or not BASE64URL_RE.match(value):
        raise ValueError(f"Not unpadded base64url: {value!r}")
    padding = "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(value + padding)
    except binascii.Error as error:
        raise ValueError(f"Not unpadded base64url: {value!r}") from error


def deterministic_dumps(value: dict) -> bytes:
    """
    Encode a CBOR map with the deterministic encoding of Section 4.2.1 of
    RFC 8949: map keys sorted bytewise lexicographic on their *encoded* form.

    cbor2's ``canonical=True`` is the RFC 7049 canonical ordering, which
    RFC 8949 Section 4.2.3 describes as "length-first" and explicitly
    distinguishes from Section 4.2.1. The two agree only while every key
    encodes to the same number of bytes, so relying on it is a landmine for
    any key or label outside that range:

    >>> import cbor2
    >>> labels = {1: 0, 10: 0, 100: 0, -1: 0}
    >>> list(cbor2.loads(cbor2.dumps(labels, canonical=True)))
    [1, 10, -1, 100]
    >>> list(cbor2.loads(deterministic_dumps(labels)))
    [1, 10, 100, -1]
    """
    encoded_items = sorted(
        (cbor2.dumps(key), cbor2.dumps(item)) for key, item in value.items()
    )
    # A definite-length map header, then the sorted key/value pairs.
    count = len(encoded_items)
    if count < 24:
        header = bytes([0xA0 | count])
    elif count < 0x100:
        header = bytes([0xB8, count])
    elif count < 0x10000:
        header = b"\xb9" + count.to_bytes(2, "big")
    else:
        header = b"\xba" + count.to_bytes(4, "big")
    return header + b"".join(key + item for key, item in encoded_items)


def cose_key_thumbprint(cose_key: dict, hash_alg: Any = hashlib.sha256) -> bytes:
    """
    Compute the RFC 9679 COSE Key Thumbprint of a COSE Key.

    RFC 9679 Section 3: construct a COSE_Key containing only the required
    parameters for the key type, encode it with the deterministic encoding of
    Section 4.2.1 of RFC 8949, and hash the result. SHA-256 MUST be supported
    and is the default used here.

    >>> key = {1: 2, -1: 1, -2: b"x" * 32, -3: b"y" * 32}
    >>> len(cose_key_thumbprint(key))
    32
    """
    kty = cose_key.get(COSE_KEY_KTY)
    required_labels = COSE_KEY_THUMBPRINT_REQUIRED_LABELS.get(kty)
    if required_labels is None:
        raise UnsupportedKeyTypeError(f"Unknown COSE key type: {kty!r}")
    required = {}
    for label in required_labels:
        if label not in cose_key:
            raise UnsupportedKeyTypeError(
                f"COSE key of type {kty!r} is missing required label {label!r}"
            )
        required[label] = cose_key[label]
    return hash_alg(deterministic_dumps(required)).digest()


def jwk_to_cose_key(jwk: dict) -> dict:
    """
    Convert a public JWK, as the tree algorithms currently produce, into a
    COSE Key. Only EC2 keys are supported; the emulator's tree algorithms sign
    with ES256.

    The kid is the RFC 9679 COSE Key Thumbprint, which Section 2.2 of
    draft-ietf-scitt-scrapi-11 RECOMMENDS.
    """
    if jwk.get("kty") != "EC":
        raise UnsupportedKeyTypeError(
            f"Only EC keys can be converted to COSE keys, got {jwk.get('kty')!r}"
        )
    crv = JWK_CRV_TO_COSE_KEY_CRV.get(jwk.get("crv"))
    if crv is None:
        raise UnsupportedKeyTypeError(f"Unsupported curve: {jwk.get('crv')!r}")
    for coordinate in ("x", "y"):
        if not jwk.get(coordinate):
            raise UnsupportedKeyTypeError(
                f"EC JWK is missing its {coordinate!r} coordinate"
            )
    cose_key = {
        COSE_KEY_KTY: COSE_KEY_TYPE_EC2,
        COSE_KEY_EC2_CRV: crv,
        COSE_KEY_EC2_X: base64url_decode(jwk["x"]),
        COSE_KEY_EC2_Y: base64url_decode(jwk["y"]),
    }
    cose_key[COSE_KEY_KID] = cose_key_thumbprint(cose_key)
    return cose_key


def encode_cose_key_set(cose_keys: List[dict]) -> bytes:
    """
    Encode a COSE Key Set, which Section 7 of RFC 9052 defines as an array of
    COSE Keys.
    """
    return cbor2.dumps(list(cose_keys))


def encode_cose_key(cose_key: dict) -> bytes:
    return cbor2.dumps(cose_key)


def check_key_identifiers_unambiguous(cose_keys: List[dict]) -> None:
    """
    Section 2.2 of draft-ietf-scitt-scrapi-11: "A Transparency Service MUST
    NOT use kid values whose raw and base64url forms would make the same URL
    identify different keys."

    Raises AmbiguousKeyIdentifierError if any URL segment would resolve to
    more than one key.
    """
    by_segment = {}
    for cose_key in cose_keys:
        kid = cose_key.get(COSE_KEY_KID)
        if kid is None:
            continue
        for segment in kid_url_segments(kid):
            claimed = by_segment.setdefault(segment, kid)
            if claimed != kid:
                raise AmbiguousKeyIdentifierError(
                    f"Key identifiers {claimed!r} and {kid!r} are both "
                    f"addressed by /.well-known/scitt-keys/{segment}"
                )


def kid_url_segments(kid: bytes) -> List[str]:
    """
    The path segments under /.well-known/scitt-keys that identify a key.

    Section 2.2 of draft-ietf-scitt-scrapi-11: the resource MUST accept the
    base64url encoding of the kid value, without padding. If the kid value is
    safe for use as a URI path segment without percent-encoding, the resource
    MUST also accept the kid value itself.

    >>> kid_url_segments(b"kid1")
    ['a2lkMQ', 'kid1']
    >>> kid_url_segments(bytes([0xde, 0xad]))
    ['3q0']
    """
    segments = [base64url_encode(kid)]
    try:
        raw = kid.decode("ascii")
    except UnicodeDecodeError:
        return segments
    # "." and ".." are dot-segments, which Section 5.2.4 of RFC 3986 tells
    # clients to remove, so they never reach the resource.
    if raw in (".", ".."):
        return segments
    # RFC 3986 Section 2.3 unreserved characters, plus the sub-delims and
    # characters permitted in a path segment without percent-encoding.
    if raw and all(
        character.isalnum() or character in "-._~!$&'()*+,;=:@" for character in raw
    ):
        if raw not in segments:
            segments.append(raw)
    return segments

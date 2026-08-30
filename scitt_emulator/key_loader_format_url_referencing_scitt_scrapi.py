import json
import contextlib
import urllib.parse
import urllib.request
from typing import List, Optional, Tuple

import cbor2
import cwt
import cwt.algs.ec2
import pycose
import pycose.keys.ec2

# TODO Remove this once we have a example flow for proper key verification
import jwcrypto.jwk

from scitt_emulator.cose_keys import (
    COSE_KEY_EC2_CRV,
    COSE_KEY_EC2_X,
    COSE_KEY_EC2_Y,
    COSE_KEY_KID,
    COSE_KEY_KTY,
    COSE_KEY_TYPE_EC2,
    base64url_encode,
    cose_key_thumbprint,
)
from scitt_emulator.did_helpers import did_web_to_url
from scitt_emulator.key_helper_dataclasses import VerificationKey
from scitt_emulator.key_loader_format_did_jwk import to_object_jwk


CONTENT_TYPE = "application/scitt+jwk+set+json"

# Section 2.1 of draft-ietf-scitt-scrapi-11 serves a COSE Key Set as
# application/cbor.
COSE_KEY_SET_CONTENT_TYPE = "application/cbor"

# Section 2.1 of draft-ietf-scitt-scrapi-11.
SCITT_KEYS_PATH = "/.well-known/scitt-keys"
# Deprecated, from an early SCRAPI revision. Tried only when the current
# resource is absent, so that a Transparency Service which has not yet been
# updated still resolves.
TRANSPARENCY_CONFIGURATION_PATH = "/.well-known/transparency-configuration"


def _load_cose_key_set(issuer_parsed_url: urllib.parse.ParseResult) -> List[VerificationKey]:
    """
    Resolve the Transparency Service's keys from the COSE Key Set at
    /.well-known/scitt-keys (Section 2.1 of draft-ietf-scitt-scrapi-11).

    Returns an empty list if the resource is absent or does not hold a COSE
    Key Set, so that the caller can fall back to the deprecated resource.
    """
    scitt_keys_url = issuer_parsed_url._replace(path=SCITT_KEYS_PATH).geturl()
    request = urllib.request.Request(
        scitt_keys_url, headers={"Accept": COSE_KEY_SET_CONTENT_TYPE}
    )
    # urlopen raises HTTPError, a URLError, for a non-2xx status.
    try:
        with urllib.request.urlopen(request) as response:
            if response.status != 200:
                return []
            cose_key_set_bytes = response.read()
    except urllib.request.URLError:
        return []

    try:
        cose_key_set = cbor2.loads(cose_key_set_bytes)
    except Exception:
        return []
    # Section 7 of RFC 9052: a COSE Key Set is an array of COSE Keys.
    if not isinstance(cose_key_set, list):
        return []

    keys = []
    for cose_key in cose_key_set:
        cose_key_bytes = cbor2.dumps(cose_key)
        keys.append(
            VerificationKey(
                transforms=[cwt.COSEKey.from_bytes(cose_key_bytes)],
                original=cose_key,
                original_content_type=COSE_KEY_SET_CONTENT_TYPE,
                original_bytes=cose_key_bytes,
                original_bytes_encoding="cbor",
                usable=False,
                cwt=None,
                cose=None,
            )
        )
    return keys


def key_loader_format_url_referencing_scitt_scrapi(
    unverified_issuer: str,
) -> List[Tuple[cwt.COSEKey, pycose.keys.ec2.EC2Key]]:
    keys = []

    if unverified_issuer.startswith("did:web:"):
        unverified_issuer = did_web_to_url(unverified_issuer)

    if "://" not in unverified_issuer or unverified_issuer.startswith("file://"):
        return keys

    # TODO Logging for URLErrors
    unverified_issuer_parsed_url = urllib.parse.urlparse(unverified_issuer)

    # Prefer the COSE Key Set resource defined by the current SCRAPI revision.
    keys = _load_cose_key_set(unverified_issuer_parsed_url)
    if keys:
        return keys

    # Fall back to the deprecated transparency configuration resource.
    openid_configuration_url = unverified_issuer_parsed_url._replace(
        path=TRANSPARENCY_CONFIGURATION_PATH,
    ).geturl()
    with contextlib.suppress(urllib.request.URLError):
        with urllib.request.urlopen(openid_configuration_url) as response:
            if response.status == 200:
                openid_configuration = json.loads(response.read())
                jwks = openid_configuration["jwks"]
                for jwk_key_as_dict in jwks["keys"]:
                    jwk_key_as_string = json.dumps(jwk_key_as_dict)
                    jwk_key = jwcrypto.jwk.JWK.from_json(jwk_key_as_string)
                    keys.append(
                        VerificationKey(
                            transforms=[jwk_key],
                            original=jwk_key,
                            original_content_type=CONTENT_TYPE,
                            original_bytes=jwk_key_as_string.encode("utf-8"),
                            original_bytes_encoding="utf-8",
                            usable=False,
                            cwt=None,
                            cose=None,
                        )
                    )

    return keys


def transform_key_instance_jwcrypto_jwk_to_cwt_cose(
    key: jwcrypto.jwk.JWK,
) -> cwt.COSEKey:
    if not isinstance(key, jwcrypto.jwk.JWK):
        raise TypeError(key)
    return cwt.COSEKey.from_pem(
        key.export_to_pem(),
        kid=key.thumbprint(),
    )


def to_object_cose_key(verification_key: VerificationKey) -> Optional[dict]:
    """
    Convert a VerificationKey that came from a COSE Key Set into a JWK object,
    so that a Registration Policy can use a key discovered from
    /.well-known/scitt-keys. Returns None when the key did not come from a
    COSE Key Set, so this runs alongside the other key-to-object transforms.
    """
    if verification_key.original_content_type != COSE_KEY_SET_CONTENT_TYPE:
        return
    cose_key = verification_key.original
    if cose_key.get(COSE_KEY_KTY) != COSE_KEY_TYPE_EC2:
        return
    crv = {
        1: "P-256",
        2: "P-384",
        3: "P-521",
    }.get(cose_key.get(COSE_KEY_EC2_CRV))
    if crv is None:
        return
    return {
        "content_type": verification_key.original_content_type,
        "key": {
            "kty": "EC",
            "crv": crv,
            "x": base64url_encode(cose_key[COSE_KEY_EC2_X]),
            "y": base64url_encode(cose_key[COSE_KEY_EC2_Y]),
            "use": "sig",
            # kid is optional in a COSE Key (RFC 9052); fall back to the
            # RFC 9679 thumbprint, which Section 2.2 of draft-ietf-scitt-
            # scrapi-11 RECOMMENDS as the kid.
            "kid": base64url_encode(
                cose_key.get(COSE_KEY_KID) or cose_key_thumbprint(cose_key)
            ),
        },
    }

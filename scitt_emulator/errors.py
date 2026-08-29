# Copyright (c) SCITT Authors
# Licensed under the MIT License.
"""
RFC 9290 Concise Problem Details, as required by Section 2 of
draft-ietf-scitt-scrapi-11.

Errors are CBOR maps served as ``application/concise-problem-details+cbor``.
Only the two fields SCRAPI requires are used: ``title`` at key -1 and
``detail`` at key -2. Both are unadorned CBOR text strings, which RFC 9290
``oltext`` permits and which Section 2 says are interpreted as language ``en``.
"""

import cbor2

# Media type for RFC 9290 Concise Problem Details, draft-ietf-scitt-scrapi-11
# Section 2.
CONTENT_TYPE = "application/concise-problem-details+cbor"

# RFC 9290 Section 2, "Standard Problem Detail Entries"
PROBLEM_DETAILS_TITLE = -1
PROBLEM_DETAILS_DETAIL = -2


def encode_problem_details(title: str, detail: str) -> bytes:
    """
    Encode an RFC 9290 Concise Problem Details object.

    >>> import cbor2
    >>> cbor2.loads(encode_problem_details("Not Found", "No such entry"))
    {-1: 'Not Found', -2: 'No such entry'}
    """
    return cbor2.dumps(
        {
            PROBLEM_DETAILS_TITLE: title,
            PROBLEM_DETAILS_DETAIL: detail,
        }
    )


def decode_problem_details(body: bytes) -> dict:
    """
    Decode an RFC 9290 Concise Problem Details object into ``title``/``detail``.

    Raises ``ValueError`` if the body is not a valid problem details object, so
    that callers can fall back to the response's status class as Section 2 of
    draft-ietf-scitt-scrapi-11 requires.

    >>> decode_problem_details(encode_problem_details("Rejected", "Policy"))
    {'title': 'Rejected', 'detail': 'Policy'}
    """
    try:
        decoded = cbor2.loads(body)
    except Exception as error:
        raise ValueError("Not a valid CBOR document") from error
    if not isinstance(decoded, dict):
        raise ValueError("Problem details object is not a CBOR map")
    problem_details = {}
    for key, name in (
        (PROBLEM_DETAILS_TITLE, "title"),
        (PROBLEM_DETAILS_DETAIL, "detail"),
    ):
        value = decoded.get(key)
        if value is None:
            continue
        # oltext is either a text string or a tag 38 language-tagged string,
        # which is a two element array of language tag and text.
        if isinstance(value, cbor2.CBORTag) and value.tag == 38:
            value = value.value[1]
        if not isinstance(value, str):
            raise ValueError(f"Problem details {name} is not text")
        problem_details[name] = value
    if not problem_details:
        raise ValueError("Problem details object has neither title nor detail")
    return problem_details

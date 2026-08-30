# Copyright (c) SCITT Authors
# Licensed under the MIT License.
"""
Registration mutates state shared across requests, and the server is threaded.
These tests exercise the transitions concurrently.
"""
import collections
import concurrent.futures
import pathlib
import threading

import httpx
import pytest

from scitt_emulator import create_statement
from scitt_emulator.rfc9162_sha256 import RFC9162SHA256SCITTServiceEmulator

from tests.test_cli import Service


# How many concurrent registrations and polls to exercise.
REGISTRATIONS = 24


def make_service(tmp_path, use_lro=False):
    return Service(
        {
            "workspace": tmp_path / "workspace",
            "error_rate": 0,
            "use_lro": use_lro,
        }
    )


def make_statements(tmp_path, count, subject_prefix="subject"):
    paths = []
    for i in range(count):
        claim_path = tmp_path / f"claim-{i}.cose"
        create_statement.create_claim(
            claim_path,
            "did:web:example.org",
            f"{subject_prefix}-{i}",
            "application/json",
            b'{"foo": "bar"}',
        )
        paths.append(claim_path)
    return paths


def verifier(service):
    return RFC9162SHA256SCITTServiceEmulator(
        service_parameters_path=service.service_parameters_path
    )


def test_concurrent_registrations_all_produce_verifiable_receipts(tmp_path):
    """
    Every Receipt the service returns must verify, however many registrations
    are in flight at once.

    Deriving the leaf index, the inclusion proof and the root from separate
    reads of the log let a concurrent registration shift the tree underneath,
    so a Receipt was issued with a 201 whose proof reconstructed a different
    root and could never verify.
    """
    claim_paths = make_statements(tmp_path, REGISTRATIONS)

    with make_service(tmp_path) as service:

        def register(claim_path):
            return claim_path, httpx.post(
                f"{service.url}/entries",
                content=claim_path.read_bytes(),
                headers={"Content-Type": "application/cose"},
            )

        with concurrent.futures.ThreadPoolExecutor(REGISTRATIONS) as pool:
            results = list(pool.map(register, claim_paths))

        service_verifier = verifier(service)
        for claim_path, response in results:
            assert response.status_code == 201, response.content
            receipt_path = tmp_path / f"{claim_path.stem}.receipt.cbor"
            receipt_path.write_bytes(response.content)
            # Raises if the proof does not reconstruct a root the service signed.
            service_verifier.verify_receipt(claim_path, receipt_path)


def test_concurrent_registrations_append_one_leaf_each(tmp_path):
    claim_paths = make_statements(tmp_path, REGISTRATIONS)

    with make_service(tmp_path) as service:
        with concurrent.futures.ThreadPoolExecutor(REGISTRATIONS) as pool:
            list(
                pool.map(
                    lambda p: httpx.post(
                        f"{service.url}/entries",
                        content=p.read_bytes(),
                        headers={"Content-Type": "application/cose"},
                    ),
                    claim_paths,
                )
            )

        leaves = tmp_path / "workspace" / "storage" / "tree_leaves.txt"
        assert len(leaves.read_text().split()) == REGISTRATIONS


def test_registration_is_idempotent_on_entry_id(tmp_path):
    """
    The EntryID is derived from the Signed Statement, so re-registering the
    same bytes names the same Receipt resource. Appending another leaf for it
    would silently change which leaf that resource proves, and would let any
    client grow the log without bound by replaying one statement.
    """
    (claim_path,) = make_statements(tmp_path, 1)
    claim = claim_path.read_bytes()

    with make_service(tmp_path) as service:
        locations = set()
        receipts = set()
        for _ in range(3):
            response = httpx.post(
                f"{service.url}/entries",
                content=claim,
                headers={"Content-Type": "application/cose"},
            )
            assert response.status_code == 201
            locations.add(response.headers["Location"])
            receipts.add(response.content)

        assert len(locations) == 1
        assert len(receipts) == 1

        leaves = tmp_path / "workspace" / "storage" / "tree_leaves.txt"
        assert len(leaves.read_text().split()) == 1


def test_concurrent_polls_of_a_running_registration(tmp_path):
    """
    Concurrent polls of one running registration must not race each other into
    finishing it twice, and must not fail.
    """
    (claim_path,) = make_statements(tmp_path, 1)

    with make_service(tmp_path, use_lro=True) as service:
        response = httpx.post(
            f"{service.url}/entries",
            content=claim_path.read_bytes(),
            headers={"Content-Type": "application/cose"},
        )
        assert response.status_code == 202
        location = response.headers["Location"]

        with concurrent.futures.ThreadPoolExecutor(8) as pool:
            statuses = collections.Counter(
                r.status_code for r in pool.map(lambda _: httpx.get(location), range(8))
            )

        # No 500s, and the entry reaches finality exactly once: the first poll
        # to arrive sees the registration running, the rest see the Receipt.
        assert set(statuses) <= {200, 204}
        assert statuses[204] == 1
        assert statuses[200] == 7

        leaves = tmp_path / "workspace" / "storage" / "tree_leaves.txt"
        assert len(leaves.read_text().split()) == 1

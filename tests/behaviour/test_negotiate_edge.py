"""Behavioural edge tests for deterministic, bounded algorithm negotiation."""

import pytest

from agility.negotiate import (
    ENVELOPE_VERSION,
    MIN_STRENGTH,
    agility_batch,
    negotiate,
    parse_suite,
    unwrap,
)

BASE_POLICY = {
    "min_strength": MIN_STRENGTH,
    "allow_unknown": False,
    "require_key_binding": True,
}


def test_same_supported_suite_set_is_deterministic():
    weak = parse_suite("sha256:rsa:2048")
    strong = parse_suite("sha512:rsa:4096")
    suites = [weak, strong]

    first = negotiate(suites, list(suites), BASE_POLICY)
    second = negotiate(list(suites), list(suites), BASE_POLICY)

    assert first == second
    assert first["hash"] == "sha512"


def test_client_order_does_not_change_negotiation():
    weak = parse_suite("sha256:rsa:2048")
    strong = parse_suite("sha512:rsa:4096")

    forward = negotiate([weak, strong], [strong, weak], BASE_POLICY)
    reversed_order = negotiate([strong, weak], [strong, weak], BASE_POLICY)

    assert forward == reversed_order
    assert forward["hash"] == "sha512"


def test_suite_below_min_strength_is_rejected():
    strong = parse_suite("sha512:rsa:4096")
    strict_policy = {
        "min_strength": 500000,
        "allow_unknown": False,
        "require_key_binding": True,
    }

    with pytest.raises(ValueError):
        negotiate([strong], [strong], strict_policy)


def test_unknown_envelope_suite_is_rejected_not_downgraded():
    envelope = {
        "version": ENVELOPE_VERSION,
        "suite": "sha3:rsa:4096",
        "payload": {"message": "unknown"},
    }

    with pytest.raises(ValueError):
        unwrap(envelope, BASE_POLICY)


def test_batch_results_match_independent_negotiations():
    first = parse_suite("sha256:rsa:2048")
    second = parse_suite("sha512:rsa:4096")
    first_handshake = {"id": "conn-a", "client": [first], "server": [first]}
    second_handshake = {"id": "conn-b", "client": [second], "server": [second]}

    batch = agility_batch([first_handshake, second_handshake], BASE_POLICY)
    first_alone = negotiate(
        first_handshake["client"], first_handshake["server"], BASE_POLICY
    )
    second_alone = negotiate(
        second_handshake["client"], second_handshake["server"], BASE_POLICY
    )

    assert batch["conn-a"] == first_alone
    assert batch["conn-b"] == second_alone
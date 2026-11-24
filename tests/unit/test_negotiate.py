"""Contract tests for the ten defects in agility/negotiate.py."""

import pytest

from agility.negotiate import (
    ENVELOPE_VERSION,
    MIN_STRENGTH,
    agility_batch,
    bind_key,
    negotiate,
    parse_suite,
    strength,
    unwrap,
    validate_policy,
    wrap,
)

BASE_POLICY = {
    "min_strength": MIN_STRENGTH,
    "allow_unknown": False,
    "require_key_binding": True,
}


def test_parse_suite_uses_numeric_key_length_and_numeric_strength():
    weak = parse_suite("sha256:rsa:512")
    strong = parse_suite("sha256:rsa:1024")

    assert weak["bits"] == 512
    assert strong["bits"] == 1024
    assert strength(strong) > strength(weak)


def test_strength_rejects_unknown_algorithms():
    with pytest.raises(ValueError):
        strength({"hash": "md5", "sign": "rsa", "bits": 2048})

    with pytest.raises(ValueError):
        strength({"hash": "sha256", "sign": "unknown", "bits": 2048})


def test_negotiate_selects_strongest_common_suite():
    weak = parse_suite("sha256:rsa:2048")
    strong = parse_suite("sha512:rsa:4096")

    chosen = negotiate([weak, strong], [strong, weak], BASE_POLICY)

    assert chosen["hash"] == "sha512"
    assert chosen["sign"] == "rsa"
    assert strength(chosen) == strength(strong)


def test_negotiate_rejects_suites_below_min_strength():
    weak = parse_suite("sha256:rsa:1024")

    with pytest.raises(ValueError):
        negotiate([weak], [weak], BASE_POLICY)


def test_wrap_records_version_and_unwrap_checks_version_compatibility():
    suite = parse_suite("sha512:rsa:4096")
    envelope = wrap(suite, {"message": "ok"})

    assert envelope.get("version") == ENVELOPE_VERSION
    assert envelope["suite"] == "sha512:rsa:4096"
    assert unwrap(envelope, BASE_POLICY)["payload"] == {"message": "ok"}

    with pytest.raises(ValueError):
        unwrap(
            {
                "version": ENVELOPE_VERSION + 1,
                "suite": envelope["suite"],
                "payload": {},
            },
            BASE_POLICY,
        )

    with pytest.raises(ValueError):
        unwrap({"suite": envelope["suite"], "payload": {}}, BASE_POLICY)


def test_unwrap_rejects_suite_below_min_strength():
    envelope = {
        "version": ENVELOPE_VERSION,
        "suite": "sha256:rsa:1024",
        "payload": {"message": "weak"},
    }

    with pytest.raises(ValueError):
        unwrap(envelope, BASE_POLICY)


def test_unwrap_rejects_unknown_suite_instead_of_downgrading():
    envelope = {
        "version": ENVELOPE_VERSION,
        "suite": "md5:rsa:4096",
        "payload": {"message": "downgrade"},
    }

    with pytest.raises(ValueError):
        unwrap(envelope, BASE_POLICY)


def test_bind_key_rejects_key_below_suite_length():
    suite = parse_suite("sha512:rsa:2048")

    assert bind_key(suite, {"algorithm": "rsa", "bits": 2048}) is True
    assert bind_key(suite, {"algorithm": "rsa", "bits": 1024}) is False
    assert bind_key(suite, {"algorithm": "ecdsa", "bits": 2048}) is False


def test_validate_policy_rejects_allow_unknown():
    problems = validate_policy(
        {
            "min_strength": MIN_STRENGTH,
            "allow_unknown": True,
            "require_key_binding": True,
        }
    )

    assert problems == ["allow_unknown must be False"]


def test_batch_negotiation_keeps_each_connection_isolated():
    first = parse_suite("sha256:rsa:2048")
    second = parse_suite("sha512:rsa:4096")
    handshakes = [
        {"id": "conn-a", "client": [first], "server": [first]},
        {"id": "conn-b", "client": [second], "server": [second]},
    ]

    results = agility_batch(handshakes, BASE_POLICY)

    assert results["conn-a"]["hash"] == "sha256"
    assert results["conn-b"]["hash"] == "sha512"
"""Algorithm-agility negotiation primitives for the exercise."""
HASH_RANK = {'sha1': 1, 'sha256': 2, 'sha384': 3, 'sha512': 4}
SIGN_RANK = {'rsa': 1, 'ecdsa': 2, 'ed25519': 3}
ENVELOPE_VERSION = 1
MIN_STRENGTH = 204800
DEFAULT_SUITE = {'hash': 'sha256', 'sign': 'rsa', 'bits': 2048}


def parse_suite(text: str) -> dict:
    """Parse hash:signature:key-bits into a suite description.

    Key length is stored as an integer so that strength comparisons are
    numeric rather than lexicographic.  Only known hash/signature algorithms
    are accepted: an unknown algorithm must never enter negotiation.
    """
    if not isinstance(text, str):
        raise ValueError("suite must be a string")
    parts = text.split(":")
    if len(parts) != 3:
        raise ValueError("suite must have the form hash:signature:bits")
    hash_name, sign_name, bits_text = (part.strip().lower() for part in parts)
    if hash_name not in HASH_RANK:
        raise ValueError(f"unknown hash algorithm: {hash_name!r}")
    if sign_name not in SIGN_RANK:
        raise ValueError(f"unknown signature algorithm: {sign_name!r}")
    try:
        bits = int(bits_text)
    except (TypeError, ValueError):
        raise ValueError(f"key length must be an integer: {bits_text!r}") from None
    if bits <= 0:
        raise ValueError("key length must be positive")
    return {"hash": hash_name, "sign": sign_name, "bits": bits}


def _suite_components(suite: dict) -> tuple[str, str, int]:
    """Validate one suite description and return its canonical components."""
    if not isinstance(suite, dict):
        raise ValueError("suite must be a mapping")
    hash_name = suite.get("hash")
    sign_name = suite.get("sign")
    bits = suite.get("bits")
    if hash_name not in HASH_RANK:
        raise ValueError(f"unknown hash algorithm: {hash_name!r}")
    if sign_name not in SIGN_RANK:
        raise ValueError(f"unknown signature algorithm: {sign_name!r}")
    if not isinstance(bits, int) or isinstance(bits, bool) or bits <= 0:
        raise ValueError(f"key length must be a positive integer: {bits!r}")
    return hash_name, sign_name, bits


def strength(suite: dict) -> int:
    """Return a numeric score that ranks suites within one strength family.

    The score is dominated by the key length and only lightly influenced by
    algorithm rank.  Unknown algorithms raise instead of scoring zero, so a
    bogus suite can never masquerade as the weakest acceptable option.
    """
    hash_name, sign_name, bits = _suite_components(suite)
    return bits * 100 + HASH_RANK[hash_name] * 100 + SIGN_RANK[sign_name] * 10


def _eligible_suites(suites: list, min_strength: int) -> list:
    """Return the suites that meet the minimum strength, strongest first.

    Sorting is fully determined by suite content, never by input order.
    """
    ranked = []
    for suite in suites:
        score = strength(suite)
        if score >= min_strength:
            hash_name, sign_name, bits = _suite_components(suite)
            ranked.append(
                ((score, bits, HASH_RANK[hash_name], SIGN_RANK[sign_name],
                  hash_name, sign_name), suite)
            )
    ranked.sort(key=lambda item: item[0], reverse=True)
    return [suite for _, suite in ranked]


def negotiate(client: list, server: list, policy: dict) -> dict:
    """Select a mutually supported suite for one connection.

    Selection is the *strongest* suite present on both sides, independent of
    either side's ordering, and the result must satisfy the policy's minimum
    strength.
    """
    problems = validate_policy(policy)
    if problems:
        raise ValueError("; ".join(problems))
    min_strength = policy.get("min_strength", MIN_STRENGTH)

    server_keys = {_suite_components(suite) for suite in server}
    common = []
    seen = set()
    for suite in client:
        key = _suite_components(suite)
        if key in server_keys and key not in seen:
            seen.add(key)
            common.append(suite)

    if not common:
        raise ValueError("no mutually supported suite")

    eligible = _eligible_suites(common, min_strength)
    if not eligible:
        raise ValueError("no mutually supported suite meets minimum strength")
    chosen = _suite_components(eligible[0])
    return {"hash": chosen[0], "sign": chosen[1], "bits": chosen[2]}


def wrap(suite: dict, payload: object) -> dict:
    """Wrap a payload together with the suite identifier.

    The envelope always records an integer version so that cross-version
    consumers cannot reinterpret the remaining fields with new semantics.
    """
    hash_name, sign_name, bits = _suite_components(suite)
    return {
        "version": ENVELOPE_VERSION,
        "suite": f"{hash_name}:{sign_name}:{bits}",
        "payload": payload,
    }


def unwrap(envelope: dict, policy: dict) -> dict:
    """Open an envelope and return its suite and payload.

    The suite declared inside the envelope is untrusted: it is parsed, its
    algorithms must be known, and it must satisfy the active policy.  An
    unknown or too-weak suite raises rather than silently falling back to a
    default suite.
    """
    if not isinstance(envelope, dict):
        raise ValueError("envelope must be a mapping")

    version = envelope.get("version")
    if not isinstance(version, int) or isinstance(version, bool):
        raise ValueError("envelope is missing an integer version")
    if version != ENVELOPE_VERSION:
        raise ValueError(f"unsupported envelope version: {version}")

    if "suite" not in envelope:
        raise ValueError("envelope is missing its suite")
    suite = parse_suite(envelope["suite"])

    problems = validate_policy(policy)
    if problems:
        raise ValueError("; ".join(problems))
    if strength(suite) < policy.get("min_strength", MIN_STRENGTH):
        raise ValueError("envelope suite is below the minimum strength")

    if "payload" not in envelope:
        raise ValueError("envelope is missing its payload")
    return {"version": version, "suite": suite, "payload": envelope["payload"]}


def bind_key(suite: dict, key: dict) -> bool:
    """Check that a concrete key belongs to the negotiated suite.

    The key must use the negotiated signature algorithm and its length must
    not fall *below* the negotiated length; an upper bound alone would let a
    shortened key bind to a stronger suite.
    """
    hash_name, sign_name, bits = _suite_components(suite)
    if not isinstance(key, dict):
        return False
    if key.get("algorithm") != sign_name:
        return False
    key_bits = key.get("bits")
    if not isinstance(key_bits, int) or isinstance(key_bits, bool):
        return False
    return key_bits >= bits


def validate_policy(policy: dict) -> list[str]:
    """Return policy problems, using an empty list for an acceptable policy."""
    if not isinstance(policy, dict):
        return ["policy must be a mapping"]
    problems = []
    if policy.get("allow_unknown", False):
        problems.append("allow_unknown must be False")
    if "min_strength" in policy:
        min_strength = policy["min_strength"]
        if (
            not isinstance(min_strength, int)
            or isinstance(min_strength, bool)
            or min_strength < 0
        ):
            problems.append("min_strength must be a non-negative integer")
    if "require_key_binding" in policy and not isinstance(
        policy["require_key_binding"], bool
    ):
        problems.append("require_key_binding must be a boolean")
    return problems


def agility_batch(handshakes: list, policy: dict) -> dict:
    """Negotiate a collection of connections and key results by connection id.

    Every handshake is negotiated from its own client/server lists; no
    intermediate intersection or selection is shared between connections.
    """
    problems = validate_policy(policy)
    if problems:
        raise ValueError("; ".join(problems))

    results = {}
    for handshake in handshakes:
        if not isinstance(handshake, dict) or "id" not in handshake:
            raise ValueError("each handshake needs an id")
        connection_id = handshake["id"]
        if connection_id in results:
            raise ValueError(f"duplicate connection id: {connection_id!r}")
        results[connection_id] = negotiate(
            handshake.get("client", []),
            handshake.get("server", []),
            policy,
        )
    return results

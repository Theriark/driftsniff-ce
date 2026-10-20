"""Fingerprints: construction, domain separation, stored form and constant-time comparison."""

import hashlib
import hmac

import pytest

from driftsniff.core.canonical import JsonValue, canonical_dumps
from driftsniff.secrets.fingerprint import (
    DISPLAY_MAX_CHARS,
    DISPLAY_MIN_CHARS,
    Fingerprint,
    Fingerprinter,
    contains_fingerprint,
)
from driftsniff.secrets.keys import FINGERPRINT_LABEL, MasterKey

KEY = bytes(range(32))
KEY_ID = "0a1b2c3d"
OTHER_KEY = bytes(reversed(range(32)))
FINGERPRINTER = Fingerprinter(KEY, KEY_ID)
CANARY = "CANARY-0001"


def independent(resource_type: str, path: str, canonical_value: bytes, key: bytes = KEY) -> str:
    """The same computation written out with the standard library only."""
    label = b"driftsniff-fp-v1/" + resource_type.encode() + b"/" + path.encode()
    message = label + b"\x00" + canonical_value
    return hmac.new(key, message, hashlib.sha256).hexdigest()[:32]


@pytest.mark.parametrize(
    ("value", "canonical"),
    [
        (CANARY, b'"CANARY-0001"'),
        ("1", b'"1"'),
        (1, b"1"),
        (True, b"true"),
        (None, b"null"),
        (2.0, b"2"),
        ([1, "a"], b'[1,"a"]'),
        ({"b": 1, "a": 2}, b'{"a":2,"b":1}'),
    ],
)
def test_matches_an_independent_computation(value: JsonValue, canonical: bytes) -> None:
    result = FINGERPRINTER.fingerprint("unifi-wlan", "security.psk", value)
    assert canonical_dumps(value) == canonical
    assert result.digest == independent("unifi-wlan", "security.psk", canonical)
    assert result.key_id == KEY_ID
    assert len(result.digest) == 32


def test_the_same_value_in_two_fields_gives_two_fingerprints() -> None:
    first = FINGERPRINTER.fingerprint("unifi-wlan", "psk", CANARY)
    second = FINGERPRINTER.fingerprint("unifi-wlan", "radius.psk", CANARY)
    assert first.digest != second.digest


def test_the_same_value_in_two_resource_types_gives_two_fingerprints() -> None:
    first = FINGERPRINTER.fingerprint("unifi-wlan", "psk", CANARY)
    second = FINGERPRINTER.fingerprint("unifi-network", "psk", CANARY)
    assert first.digest != second.digest


def test_the_same_value_in_the_same_field_is_stable() -> None:
    first = FINGERPRINTER.fingerprint("unifi-wlan", "psk", CANARY)
    second = FINGERPRINTER.fingerprint("unifi-wlan", "psk", CANARY)
    assert first == second


def test_a_different_key_gives_a_different_fingerprint() -> None:
    other = Fingerprinter(OTHER_KEY, "ffffffff")
    first = FINGERPRINTER.fingerprint("unifi-wlan", "psk", CANARY)
    second = other.fingerprint("unifi-wlan", "psk", CANARY)
    assert first.digest != second.digest
    assert second.digest == independent("unifi-wlan", "psk", b'"CANARY-0001"', OTHER_KEY)


def test_a_string_a_number_and_a_boolean_are_different_values() -> None:
    digests = {
        FINGERPRINTER.fingerprint("unifi-wlan", "psk", "1").digest,
        FINGERPRINTER.fingerprint("unifi-wlan", "psk", 1).digest,
        FINGERPRINTER.fingerprint("unifi-wlan", "psk", True).digest,
    }
    assert len(digests) == 3


@pytest.mark.parametrize(
    ("resource_type", "path"),
    [("", "psk"), ("a/b", "psk"), ("a\x00b", "psk"), ("wlan", ""), ("wlan", "a\x00b")],
)
def test_ambiguous_names_are_refused(resource_type: str, path: str) -> None:
    with pytest.raises(ValueError, match="must be non-empty"):
        FINGERPRINTER.fingerprint(resource_type, path, 1)


def test_a_slash_in_a_field_path_is_allowed() -> None:
    assert len(FINGERPRINTER.fingerprint("wlan", "a/b", 1).digest) == 32


def test_a_value_that_is_not_json_is_refused() -> None:
    with pytest.raises(ValueError, match="NaN"):
        FINGERPRINTER.fingerprint("wlan", "psk", float("nan"))


def test_the_stored_form_round_trips() -> None:
    result = FINGERPRINTER.fingerprint("wlan", "psk", CANARY)
    marker = result.marker()
    assert marker == f"fp1:{KEY_ID}:{result.digest}"
    assert Fingerprint.parse(marker) == result


@pytest.mark.parametrize(
    "text",
    [
        "",
        "fp1:",
        f"fp1:{KEY_ID}:{'a' * 31}",
        f"fp1:{KEY_ID}:{'a' * 33}",
        f"fp1:{KEY_ID.upper()}:{'a' * 32}",
        f"fp2:{KEY_ID}:{'a' * 32}",
        f"x fp1:{KEY_ID}:{'a' * 32}",
        f"fp1:{KEY_ID}:{'g' * 32}",
    ],
)
def test_parse_refuses_anything_but_the_stored_form(text: str) -> None:
    assert Fingerprint.parse(text) is None


def test_the_display_form_is_the_first_8_to_12_characters() -> None:
    result = FINGERPRINTER.fingerprint("wlan", "psk", CANARY)
    assert result.short() == result.digest[:8]
    assert result.short(DISPLAY_MIN_CHARS) == result.digest[:8]
    assert result.short(DISPLAY_MAX_CHARS) == result.digest[:12]
    assert result.short(10) == result.digest[:10]


@pytest.mark.parametrize("chars", [0, 7, 13, 32])
def test_a_display_form_outside_8_to_12_is_refused(chars: int) -> None:
    result = FINGERPRINTER.fingerprint("wlan", "psk", CANARY)
    with pytest.raises(ValueError, match="8 to 12"):
        result.short(chars)


def test_digests_are_compared_in_constant_time(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[bytes, bytes]] = []
    real = hmac.compare_digest

    def spy(left: bytes, right: bytes) -> bool:
        calls.append((left, right))
        return real(left, right)

    monkeypatch.setattr(hmac, "compare_digest", spy)
    first = FINGERPRINTER.fingerprint("wlan", "psk", CANARY)
    assert first.same_as(FINGERPRINTER.fingerprint("wlan", "psk", CANARY)) is True
    assert first.same_as(FINGERPRINTER.fingerprint("wlan", "psk", "CANARY-0002")) is False
    assert len(calls) == 2
    assert all(len(left) == 32 and len(right) == 32 for left, right in calls)


def test_a_different_key_id_is_never_the_same_fingerprint() -> None:
    digest = "a" * 32
    assert Fingerprint(KEY_ID, digest).same_as(Fingerprint("ffffffff", digest)) is False
    assert Fingerprint(KEY_ID, digest).same_as(Fingerprint(KEY_ID, digest)) is True


def test_matches_accepts_the_right_value_and_refuses_everything_else() -> None:
    stored = FINGERPRINTER.fingerprint("wlan", "psk", CANARY)
    assert FINGERPRINTER.matches(stored, "wlan", "psk", CANARY) is True
    assert FINGERPRINTER.matches(stored, "wlan", "psk", "CANARY-0002") is False
    assert FINGERPRINTER.matches(stored, "wlan", "other", CANARY) is False
    assert FINGERPRINTER.matches(stored, "network", "psk", CANARY) is False
    other_id = Fingerprinter(OTHER_KEY, "ffffffff")
    assert other_id.matches(stored, "wlan", "psk", CANARY) is False
    same_id_other_key = Fingerprinter(OTHER_KEY, KEY_ID)
    assert same_id_other_key.matches(stored, "wlan", "psk", CANARY) is False


def test_from_master_uses_the_derived_fingerprint_key() -> None:
    master = MasterKey(KEY)
    built = Fingerprinter.from_master(master)
    expected = Fingerprinter(master.derive(FINGERPRINT_LABEL), master.key_id)
    assert built.key_id == master.key_id
    assert built.fingerprint("wlan", "psk", 1) == expected.fingerprint("wlan", "psk", 1)
    assert built.fingerprint("wlan", "psk", 1) != FINGERPRINTER.fingerprint("wlan", "psk", 1)


@pytest.mark.parametrize("size", [0, 31, 33])
def test_a_fingerprint_key_needs_exactly_32_bytes(size: int) -> None:
    with pytest.raises(ValueError, match="exactly 32 bytes"):
        Fingerprinter(bytes(size), KEY_ID)


@pytest.mark.parametrize("key_id", ["", "0A1B2C3D", "0a1b2c3", "0a1b2c3de", "zzzzzzzz"])
def test_a_key_id_is_eight_lowercase_hex_characters(key_id: str) -> None:
    with pytest.raises(ValueError, match="8 lowercase hex"):
        Fingerprinter(KEY, key_id)


def test_the_repr_never_shows_the_key() -> None:
    assert repr(FINGERPRINTER) == "Fingerprinter(key_id='0a1b2c3d')"
    assert KEY.hex() not in repr(FINGERPRINTER)


def test_a_stored_fingerprint_is_found_in_canonical_json() -> None:
    marker = FINGERPRINTER.fingerprint("wlan", "psk", CANARY).marker()
    assert contains_fingerprint(canonical_dumps({"psk": marker})) is True
    assert contains_fingerprint(canonical_dumps({"list": ["x", marker]})) is True


def test_text_that_only_mentions_a_fingerprint_is_not_found() -> None:
    marker = FINGERPRINTER.fingerprint("wlan", "psk", CANARY).marker()
    assert contains_fingerprint(canonical_dumps({"note": "see fp1 notes"})) is False
    assert contains_fingerprint(canonical_dumps({"note": f"x {marker}"})) is False
    assert contains_fingerprint(canonical_dumps({"note": f"{marker} x"})) is False
    assert contains_fingerprint(b"") is False

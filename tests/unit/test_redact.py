"""Redaction at the collector boundary: fingerprints for secrets, scanner findings, overrides."""

import copy
import json

import pytest

from driftsniff.core.canonical import JsonValue, canonical_dumps
from driftsniff.core.normalize import FieldClass, StaticTypeTable, normalize_object
from driftsniff.secrets.fingerprint import Fingerprint, Fingerprinter
from driftsniff.secrets.redact import ForcedSecret, RedactionResult, redact_object
from driftsniff.secrets.scanner import Override, Overrides, ScanRule

FINGERPRINTER = Fingerprinter(bytes(range(32)), "0a1b2c3d")
RESOURCE = "unifi-wlan"
TABLE = StaticTypeTable(
    object_key_field="_id",
    name_field="name",
    field_classes={
        "_id": FieldClass.CONFIG,
        "name": FieldClass.CONFIG,
        "notes": FieldClass.CONFIG,
        "enabled": FieldClass.CONFIG,
        "vlan": FieldClass.CONFIG,
        "other": FieldClass.CONFIG,
        "lines": FieldClass.CONFIG,
        "psk": FieldClass.SECRET,
        "radius": FieldClass.SECRET,
        "stats": FieldClass.IGNORE,
    },
)
LONG_WORD = "Zx9Qp4Lm7Vb2Nc8Kd5Rt1Yw6Hs3"


def pem_block() -> str:
    return "-----BEGIN " + "PRIVATE KEY-----\nQ0FOQVJZ\n-----END " + "PRIVATE KEY-----"


def url_with_credentials() -> str:
    return "postgresql://svc:" + "CANARY-pw-0001" + "@db.example.invalid:5432/app"


def redact(raw: dict[str, JsonValue], overrides: Overrides | None = None) -> RedactionResult:
    if overrides is None:
        return redact_object(TABLE, RESOURCE, raw, FINGERPRINTER)
    return redact_object(TABLE, RESOURCE, raw, FINGERPRINTER, overrides)


def marker_of(path: str, value: JsonValue, resource_type: str = RESOURCE) -> str:
    return FINGERPRINTER.fingerprint(resource_type, path, value).marker()


def test_secret_class_values_are_replaced_by_their_fingerprint() -> None:
    result = redact({"_id": "w1", "name": "Guest", "psk": "CANARY-psk-0001"})
    marker = marker_of("psk", "CANARY-psk-0001")
    assert result.value == {"_id": "w1", "name": "Guest", "psk": marker}
    assert "CANARY-psk-0001" not in json.dumps(result.value)
    assert result.fingerprints == 1
    assert result.has_fingerprints is True
    assert result.forced == ()


def test_ignored_fields_are_dropped_and_null_secrets_stay_null() -> None:
    result = redact({"_id": "w1", "stats": {"rx": 5}, "psk": None, "notes": None})
    assert result.value == {"_id": "w1", "psk": None, "notes": None}
    assert result.fingerprints == 0
    assert result.has_fingerprints is False


def test_a_secret_that_is_not_a_string_is_fingerprinted_as_a_whole() -> None:
    radius: JsonValue = {"host": "192.0.2.1", "port": 1812}
    result = redact({"_id": "w1", "psk": 5, "radius": radius})
    assert result.value["psk"] == marker_of("psk", 5)
    assert result.value["radius"] == marker_of("radius", radius)
    assert result.fingerprints == 2


def test_a_list_and_an_empty_string_are_fingerprinted_too() -> None:
    result = redact({"_id": "w1", "psk": ["a", "b"], "radius": ""})
    assert result.value["psk"] == marker_of("psk", ["a", "b"])
    assert result.value["radius"] == marker_of("radius", "")
    assert result.fingerprints == 2


def test_a_scanner_finding_in_a_config_field_forces_the_secret_class() -> None:
    value = pem_block()
    result = redact({"_id": "w1", "notes": value})
    assert result.value["notes"] == marker_of("notes", value)
    assert result.forced == (ForcedSecret("notes", ScanRule.PEM),)
    assert result.fingerprints == 1
    assert "PRIVATE" not in repr(result)


def test_map_and_list_members_are_scanned() -> None:
    link = url_with_credentials()
    prefixed = "ghp_" + "Q" * 20
    raw: dict[str, JsonValue] = {
        "_id": "w1",
        "other": {"note": link, "count": 3},
        "lines": ["fine", prefixed],
    }
    result = redact(raw)
    dumped = json.dumps(result.value)
    assert "CANARY-pw-0001" not in dumped
    assert prefixed not in dumped
    assert result.value["other"] == {"note": marker_of("other.note", link), "count": 3}
    assert result.value["lines"] == ["fine", marker_of("lines", prefixed)]
    assert result.forced == (
        ForcedSecret("other.note", ScanRule.URL_CREDENTIALS),
        ForcedSecret("lines", ScanRule.PREFIXED_CREDENTIAL),
    )


def test_unclassified_fields_are_scanned_too() -> None:
    value = "AKIA" + "AbCd1234EfGh5678"
    result = redact({"_id": "w1", "extra": value})
    assert result.value["extra"] == marker_of("extra", value)
    assert result.forced == (ForcedSecret("extra", ScanRule.PREFIXED_CREDENTIAL),)


def test_ordinary_values_are_left_alone() -> None:
    raw: dict[str, JsonValue] = {
        "_id": "w1",
        "name": "Guest WiFi - Building 2 (temporary)",
        "notes": "VLAN 20, guest",
        "enabled": True,
        "vlan": 20,
        "other": {"ratio": 1.5, "tags": ["a", "b"]},
    }
    result = redact(raw)
    assert result.value == raw
    assert result.forced == ()
    assert result.fingerprints == 0


def test_a_punctuated_random_token_in_a_config_field_is_not_stored_in_plaintext() -> None:
    token = "aB3x(Qz9;Lm2&Kp7!RtWv"
    result = redact({"_id": "w1", "notes": token, "name": "Guest WiFi (temporary)"})
    assert result.value["notes"] == marker_of("notes", token)
    assert token not in json.dumps(result.value)
    assert result.value["name"] == "Guest WiFi (temporary)"
    assert result.forced == (ForcedSecret("notes", ScanRule.HIGH_ENTROPY),)


def test_the_input_is_not_changed() -> None:
    raw: dict[str, JsonValue] = {
        "_id": "w1",
        "psk": "CANARY-psk-0001",
        "stats": {"rx": 1},
        "other": {"note": url_with_credentials()},
    }
    before = copy.deepcopy(raw)
    redact(raw)
    assert raw == before


def test_an_override_keeps_a_reviewed_false_positive() -> None:
    overrides = Overrides([Override(RESOURCE, "notes", "Long product codes are normal here")])
    result = redact({"_id": "w1", "notes": LONG_WORD, "name": LONG_WORD}, overrides)
    assert result.value["notes"] == LONG_WORD
    assert result.value["name"] == marker_of("name", LONG_WORD)
    assert result.forced == (ForcedSecret("name", ScanRule.HIGH_ENTROPY),)


def test_an_override_for_every_resource_type_applies() -> None:
    overrides = Overrides([Override("*", "notes", "Long product codes are normal here")])
    result = redact({"_id": "w1", "notes": LONG_WORD}, overrides)
    assert result.value["notes"] == LONG_WORD


def test_an_override_only_covers_the_rules_it_names() -> None:
    entry = Override(RESOURCE, "notes", "Codes only", frozenset({ScanRule.HIGH_ENTROPY}))
    link = url_with_credentials()
    result = redact({"_id": "w1", "notes": link}, Overrides([entry]))
    assert result.value["notes"] == marker_of("notes", link)
    assert result.forced == (ForcedSecret("notes", ScanRule.URL_CREDENTIALS),)


def test_an_override_never_touches_a_secret_class_field() -> None:
    overrides = Overrides([Override(RESOURCE, "psk", "Not allowed to matter")])
    result = redact({"_id": "w1", "psk": LONG_WORD}, overrides)
    assert result.value["psk"] == marker_of("psk", LONG_WORD)


def test_equal_secrets_in_different_fields_never_share_a_fingerprint() -> None:
    result = redact({"_id": "w1", "psk": "CANARY-shared-1", "radius": "CANARY-shared-1"})
    assert result.value["psk"] != result.value["radius"]


def test_the_same_secret_gives_the_same_fingerprint_every_time_in_one_resource_type() -> None:
    raw: dict[str, JsonValue] = {"_id": "w1", "psk": "CANARY-psk-0001"}
    first = redact(raw)
    second = redact(dict(raw))
    other_type = redact_object(TABLE, "unifi-network", raw, FINGERPRINTER)
    assert first.value == second.value
    assert first.value["psk"] != other_type.value["psk"]


def test_a_value_shaped_like_a_stored_fingerprint_is_fingerprinted_again() -> None:
    spoof = Fingerprint("0a1b2c3d", "a" * 32).marker()
    result = redact({"_id": "w1", "notes": spoof})
    assert result.value["notes"] == marker_of("notes", spoof)
    assert result.value["notes"] != spoof
    assert result.forced == (ForcedSecret("notes", ScanRule.FINGERPRINT_MARKER),)


def test_an_override_cannot_hide_a_fingerprint_look_alike() -> None:
    spoof = Fingerprint("0a1b2c3d", "a" * 32).marker()
    overrides = Overrides([Override("*", "notes", "Free text")])
    result = redact({"_id": "w1", "notes": spoof}, overrides)
    assert result.value["notes"] != spoof


def test_the_redacted_object_normalises_and_hashes_deterministically() -> None:
    raw: dict[str, JsonValue] = {
        "_id": "w1",
        "name": "Guest",
        "psk": "CANARY-psk-0001",
        "stats": {"rx": 1},
    }
    first = canonical_dumps(normalize_object(TABLE, redact(raw).value))
    second = canonical_dumps(normalize_object(TABLE, redact(copy.deepcopy(raw)).value))
    assert first == second
    assert b"CANARY-psk-0001" not in first
    assert b"stats" not in first


def test_a_raw_object_must_be_a_mapping_with_string_keys() -> None:
    with pytest.raises(TypeError, match="must be a mapping"):
        redact_object(TABLE, RESOURCE, ["x"], FINGERPRINTER)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="keys must be strings"):
        redact_object(TABLE, RESOURCE, {1: "x"}, FINGERPRINTER)  # type: ignore[dict-item]

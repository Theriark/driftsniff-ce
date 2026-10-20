"""The scanner rules (a positive and a negative test each), entropy bounds and overrides."""

from pathlib import Path

import pytest

from driftsniff.secrets import scanner
from driftsniff.secrets.fingerprint import Fingerprint
from driftsniff.secrets.scanner import (
    CREDENTIAL_PREFIXES,
    Override,
    OverrideFileError,
    Overrides,
    ScanRule,
    entropy_spans,
    load_overrides,
    parse_overrides,
    scan_text,
    shannon_entropy,
)


def pem_header() -> str:
    return "-----BEGIN " + "CERTIFICATE-----"


def pem_block() -> str:
    return "-----BEGIN " + "PRIVATE KEY-----\nQ0FOQVJZ\n-----END " + "PRIVATE KEY-----"


def jwt() -> str:
    return "eyJ" + "hbGciOiJIUzI1NiJ9" + "." + "eyJzdWIiOiJDQU5BUlkifQ" + "." + "c2lnbmF0dXJl"


def url_with_credentials() -> str:
    return "postgresql://svc:" + "CANARY-pw-0001" + "@db.example.invalid:5432/app"


# --- pem ---------------------------------------------------------------------------------


def test_a_pem_header_is_found() -> None:
    assert ScanRule.PEM in scan_text(pem_header())
    assert ScanRule.PEM in scan_text("note: " + pem_block() + " end")


@pytest.mark.parametrize(
    "text",
    [
        "BEGIN CERTIFICATE",
        "----BEGIN CERTIFICATE----",
        "-----BEGIN-----",
        "-----begin certificate-----",
        "",
    ],
)
def test_text_that_is_not_a_pem_header_is_not_flagged(text: str) -> None:
    assert ScanRule.PEM not in scan_text(text)


# --- jwt ---------------------------------------------------------------------------------


def test_a_jwt_is_found() -> None:
    assert ScanRule.JWT in scan_text(jwt())
    assert ScanRule.JWT in scan_text("Authorization failed for " + jwt())
    assert ScanRule.JWT in scan_text("eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.")


@pytest.mark.parametrize(
    "text",
    ["eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0", "xeyJabc.def.ghi", "eyJ", "1.2.3", "abc.def.ghi"],
)
def test_text_that_is_not_a_jwt_is_not_flagged(text: str) -> None:
    assert ScanRule.JWT not in scan_text(text)


# --- url credentials ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        url_with_credentials(),
        "https://user:" + "p4ss" + "@host.example.invalid/x",
        "see https://u:" + "pw" + "@h.example.invalid/x for details",
        "ftp://admin:" + "p%40ss" + "@h.example.invalid",
    ],
)
def test_a_url_with_user_and_password_is_found(text: str) -> None:
    assert ScanRule.URL_CREDENTIALS in scan_text(text)


@pytest.mark.parametrize(
    "text",
    [
        "https://user@host.example.invalid/x",
        "https://user:@host.example.invalid/x",
        "https://:pw@host.example.invalid/x",
        "https://host.example.invalid:8080/path",
        "https://host.example.invalid/path?mail=a:b@c",
        "user:pw@host",
        "://u:pw@h",
        "no url here",
    ],
)
def test_text_without_url_credentials_is_not_flagged(text: str) -> None:
    assert ScanRule.URL_CREDENTIALS not in scan_text(text)


# --- credential prefixes -----------------------------------------------------------------


def test_there_are_ten_prefixes() -> None:
    assert len(CREDENTIAL_PREFIXES) == 10


@pytest.mark.parametrize("prefix", CREDENTIAL_PREFIXES)
def test_a_credential_prefix_is_found(prefix: str) -> None:
    assert ScanRule.PREFIXED_CREDENTIAL in scan_text("key " + prefix + "AbCd1234Ef")


@pytest.mark.parametrize("prefix", CREDENTIAL_PREFIXES)
def test_a_prefix_with_a_short_body_is_not_flagged(prefix: str) -> None:
    assert ScanRule.PREFIXED_CREDENTIAL not in scan_text(prefix + "abc")


@pytest.mark.parametrize("prefix", CREDENTIAL_PREFIXES)
def test_a_prefix_inside_a_longer_word_is_not_flagged(prefix: str) -> None:
    assert ScanRule.PREFIXED_CREDENTIAL not in scan_text("x" + prefix + "AbCd1234Ef")


# --- entropy -----------------------------------------------------------------------------


def test_entropy_of_simple_strings() -> None:
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    assert str(shannon_entropy("aaaa")) == "0.0"
    assert shannon_entropy("ab") == pytest.approx(1.0)


def test_the_entropy_threshold_is_exclusive_at_4_2_bits() -> None:
    above = "abcdefghijklmnopqrss"
    below = "abcdefghijklmnoopqrr"
    assert shannon_entropy(above) == pytest.approx(4.2219, abs=1e-3)
    assert shannon_entropy(below) == pytest.approx(4.1219, abs=1e-3)
    assert ScanRule.HIGH_ENTROPY in scan_text(above)
    assert ScanRule.HIGH_ENTROPY not in scan_text(below)


def test_the_length_threshold_is_20_characters() -> None:
    assert ScanRule.HIGH_ENTROPY in scan_text("abcdefghijklmnopqrst")
    assert ScanRule.HIGH_ENTROPY not in scan_text("abcdefghijklmnopqrs")


def test_a_plain_sentence_is_not_a_secret() -> None:
    assert shannon_entropy("Guest WiFi - Building 2 (temporary)") > 4.2
    assert scan_text("Guest WiFi - Building 2 (temporary)") == ()


def test_a_long_word_inside_a_sentence_is_flagged() -> None:
    word = "Zx9Qp4Lm7Vb2Nc8Kd5Rt1Yw6Hs3"
    assert ScanRule.HIGH_ENTROPY in scan_text(f"temporary code {word} for guests")
    assert ScanRule.HIGH_ENTROPY in scan_text(f'value="{word}"')
    assert ScanRule.HIGH_ENTROPY in scan_text(word)


PUNCTUATED_TOKENS = ["aB3x(Qz9;Lm2&Kp7!RtWv", "aB3x,Qz9;Lm2(Kp7)RtWvXy", "aB3x<Qz9>Lm2<Kp7>RtWvXy"]


@pytest.mark.parametrize("token", PUNCTUATED_TOKENS)
def test_a_punctuated_single_token_is_judged_as_a_whole(token: str) -> None:
    assert ScanRule.HIGH_ENTROPY in scan_text(token)
    assert list(entropy_spans(token)) == [(0, len(token))]


def test_a_short_punctuated_token_is_not_flagged() -> None:
    assert scan_text("aB3x(Qz9;Lm2&Kp7") == ()
    assert list(entropy_spans("aB3x(Qz9;Lm2&Kp7")) == []


def test_text_with_white_space_is_still_judged_word_by_word() -> None:
    sentence = "Guest WiFi - Building 2 (temporary)"
    assert list(entropy_spans(sentence)) == []
    word = "Zx9Qp4Lm7Vb2Nc8Kd5Rt1Yw6Hs3"
    text = f"temporary code {word} for guests"
    assert list(entropy_spans(text)) == [(15, 15 + len(word))]
    assert list(entropy_spans(f'value="{word}" ok')) == [(7, 7 + len(word))]
    assert list(entropy_spans("aB3x(Qz9; Lm2&Kp7!RtWv")) == []


def test_uuids_and_hex_digests_are_exempt(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(scanner, "ENTROPY_THRESHOLD", 0.0)
    sixteen = "0123456789abcdef"
    exempt = [
        "550e8400-e29b-41d4-a716-446655440000",
        sixteen * 2,
        sixteen * 2 + "01234567",
        sixteen * 4,
    ]
    flagged = [
        sixteen * 2 + "0",
        sixteen * 3,
        "plainwordwithmanychars",
        "550e8400-e29b-41d4-a716-44665544000g",
    ]
    for text in exempt:
        assert ScanRule.HIGH_ENTROPY not in scan_text(text)
    for text in flagged:
        assert ScanRule.HIGH_ENTROPY in scan_text(text)


# --- fingerprint look-alikes -------------------------------------------------------------


def test_text_shaped_like_a_stored_fingerprint_is_found() -> None:
    marker = Fingerprint("0a1b2c3d", "a" * 32).marker()
    assert ScanRule.FINGERPRINT_MARKER in scan_text(marker)
    assert ScanRule.FINGERPRINT_MARKER in scan_text(f"was {marker} before")


@pytest.mark.parametrize("text", ["fp1:xyz", "fp1:0a1b2c3d:short", "fp2:0a1b2c3d:" + "a" * 32])
def test_other_text_is_not_a_look_alike(text: str) -> None:
    assert ScanRule.FINGERPRINT_MARKER not in scan_text(text)


def test_rules_are_reported_in_enum_order() -> None:
    marker = Fingerprint("0a1b2c3d", "a" * 32).marker()
    assert scan_text(marker + " " + pem_header()) == (ScanRule.PEM, ScanRule.FINGERPRINT_MARKER)


def test_ordinary_values_have_no_findings() -> None:
    for text in ["", "Guest", "192.0.2.10", "WPA2 Personal", "2026-10-20T08:00:00Z", "true"]:
        assert scan_text(text) == ()


# --- long values -------------------------------------------------------------------------


def test_very_long_values_are_scanned_without_stalling() -> None:
    assert ScanRule.JWT not in scan_text("eyJ" * 100_000)
    assert ScanRule.URL_CREDENTIALS not in scan_text("://" * 50_000)
    assert scan_text("a" * 300_000) == ()


# --- overrides ---------------------------------------------------------------------------

VALID = """\
version: 1
overrides:
  - resource_type: unifi-wlan
    path: description
    rules: [high_entropy]
    reason: Product codes are normal here.
  - resource_type: "*"
    path: notes
    reason: Free text.
"""


def test_the_packaged_overrides_file_loads_and_is_empty() -> None:
    assert load_overrides().entries == ()


def test_a_valid_file_is_parsed() -> None:
    entries = parse_overrides(VALID).entries
    assert entries == (
        Override(
            "unifi-wlan",
            "description",
            "Product codes are normal here.",
            frozenset({ScanRule.HIGH_ENTROPY}),
        ),
        Override("*", "notes", "Free text."),
    )


def test_a_file_can_be_loaded_from_a_path(tmp_path: Path) -> None:
    path = tmp_path / "overrides.yaml"
    path.write_text(VALID, encoding="utf-8")
    assert len(load_overrides(path).entries) == 2


def test_a_missing_file_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(OverrideFileError, match="cannot read"):
        load_overrides(tmp_path / "missing.yaml")


def test_an_empty_overrides_list_is_allowed() -> None:
    assert parse_overrides("version: 1\noverrides:\n").entries == ()
    assert parse_overrides("version: 1\n").entries == ()


def test_lookup_by_resource_type_path_and_rule() -> None:
    overrides = parse_overrides(VALID)
    assert overrides.suppresses("unifi-wlan", "description", ScanRule.HIGH_ENTROPY) is True
    assert overrides.suppresses("unifi-wlan", "description", ScanRule.JWT) is False
    assert overrides.suppresses("xo-vm", "description", ScanRule.HIGH_ENTROPY) is False
    assert overrides.suppresses("unifi-wlan", "other", ScanRule.HIGH_ENTROPY) is False
    assert overrides.suppresses("xo-vm", "notes", ScanRule.HIGH_ENTROPY) is True
    assert overrides.suppresses("xo-vm", "notes", ScanRule.URL_CREDENTIALS) is True


def test_the_fingerprint_look_alike_rule_is_never_suppressed() -> None:
    overrides = Overrides([Override("*", "notes", "Free text.")])
    assert overrides.suppresses("xo-vm", "notes", ScanRule.FINGERPRINT_MARKER) is False


def test_two_entries_for_one_path_are_refused() -> None:
    entry = Override("unifi-wlan", "notes", "Free text.")
    with pytest.raises(OverrideFileError, match="duplicate override"):
        Overrides([entry, entry])


HEAD = "version: 1\noverrides:\n"
ENTRY = "  - resource_type: a\n    path: b\n    reason: r\n"


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("", "must be a mapping with version 1"),
        ("- a\n- b\n", "must be a mapping with version 1"),
        ("version: 2\noverrides: []\n", "must be a mapping with version 1"),
        ("version: [1\n", "not valid YAML"),
        ("version: 1\nextra: 1\noverrides: []\n", "unknown keys extra"),
        ("version: 1\noverrides: {}\n", "overrides must be a list"),
        (HEAD + "  - nope\n", "override 1 must be a mapping"),
        (HEAD + "  - resource_type: a\n    path: b\n", "reason must be non-empty text"),
        (HEAD + "  - resource_type: a\n    path: ' '\n    reason: r\n", "path must be non-empty"),
        (HEAD + ENTRY + "    color: red\n", "unknown keys color"),
        (HEAD + ENTRY + "    rules: []\n", "non-empty list"),
        (HEAD + ENTRY + "    rules: jwt\n", "non-empty list"),
        (HEAD + ENTRY + "    rules: [nope]\n", "unknown rule"),
        (HEAD + ENTRY + "    rules: [fingerprint_marker]\n", "cannot be overridden"),
        (HEAD + ENTRY * 2, "duplicate override"),
    ],
)
def test_a_bad_overrides_file_is_refused_with_a_clear_message(text: str, message: str) -> None:
    with pytest.raises(OverrideFileError, match=message):
        parse_overrides(text)

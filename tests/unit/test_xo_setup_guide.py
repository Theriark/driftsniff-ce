"""The Xen Orchestra setup guide (P8-T5) agrees with the collector and claims nothing it cannot.

The guide is prose, so these tests only pin what a machine can check: the collections it names are
the ones the client reads, the excluded ones are the ones the client refuses, no address in it is a
real one, and nothing is called verified while no lab evidence file exists.
"""

import re
from pathlib import Path

from driftsniff.collectors.xo.resources import COLLECTIONS, EXCLUDED_COLLECTIONS

ROOT = Path(__file__).resolve().parents[2]
GUIDE = ROOT / "docs" / "guides" / "xo-setup.md"
LAB_EVIDENCE = ROOT / "docs" / "lab-evidence.md"
URL = re.compile(r"https?://[^\s)`>\"']+")
PLACEHOLDER_HOST = re.compile(r"\.invalid(?:[:/]|$)")


def _text() -> str:
    return GUIDE.read_text(encoding="utf-8")


def test_every_collection_the_client_reads_is_named_in_the_guide() -> None:
    text = _text()
    missing = [name for name in COLLECTIONS if f"`{name}`" not in text]
    assert not missing


def test_every_excluded_collection_is_named_in_the_guide() -> None:
    text = _text()
    missing = [name for name in EXCLUDED_COLLECTIONS if f"`{name}`" not in text]
    assert not missing


def test_the_guide_names_no_real_address() -> None:
    for url in URL.findall(_text()):
        assert PLACEHOLDER_HOST.search(url), f"not a placeholder address: {url}"
        assert "@" not in url, "an address in the guide carries a user part"


def test_nothing_is_called_verified_without_lab_evidence() -> None:
    if LAB_EVIDENCE.exists():
        return
    text = _text()
    for match in re.finditer(r"VERIFIED", text):
        assert text[max(0, match.start() - 4) : match.start()] == "NOT ", (
            "a statement is called verified but docs/lab-evidence.md does not exist"
        )


def test_the_guide_states_the_two_modes_and_the_unobservable_changes() -> None:
    text = _text()
    assert "over-privileged" in text
    assert "read-only ACL role" in text
    assert "cannot be observed" in text
    assert "never ingested" in text

"""The Xen Orchestra setup guide agrees with the collector.

The guide is prose, so these tests only pin what a machine can check: the collections it names are
the ones the client reads, the excluded ones are the ones the client refuses, no address in it is a
real one, and it states the two modes of access.
"""

import re
from pathlib import Path

from driftsniff.collectors.xo.resources import COLLECTIONS, EXCLUDED_COLLECTIONS

ROOT = Path(__file__).resolve().parents[2]
GUIDE = ROOT / "docs" / "guides" / "xo-setup.md"
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


def test_the_guide_states_the_two_modes_and_the_unobservable_changes() -> None:
    text = _text()
    assert "over-privileged" in text
    assert "read-only ACL role" in text
    assert "cannot be observed" in text
    assert "never ingested" in text

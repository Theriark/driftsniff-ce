"""The label of a list member without a declared key is a keyed hash (P9-T6, THE-810).

A member without a key is matched by its content, and the content may be a secret, so an order
detail shows it as ``member:`` and 12 characters. An unkeyed hash of the content would let anyone
who reads the detail test guesses against it; the characters are a fingerprint made with the
fingerprint key instead.
"""

import hashlib
import json
import re
from collections.abc import Mapping

from driftsniff.core.canonical import JsonValue
from driftsniff.core.normalize import (
    NORMALISER_VERSION,
    CollectionMode,
    FieldClass,
    StaticTypeTable,
)
from driftsniff.core.order import compare_order
from driftsniff.core.snapshots import CollectedObject, CollectedResource, Manifest, build_manifest
from driftsniff.secrets.fingerprint import Fingerprinter

FINGERPRINTER = Fingerprinter(bytes(range(32)), "0a1b2c3d")
OTHER = Fingerprinter(bytes(range(1, 33)), "0a1b2c3d")
CANARY = "CANARY-order-label-0001"
START = "2026-10-21T10:00:00Z"
END = "2026-10-21T10:05:00Z"
LABEL = re.compile(r"member:[0-9a-f]{12}")

TABLE = StaticTypeTable(
    object_key_field="_id",
    name_field="name",
    field_classes={"_id": FieldClass.CONFIG, "name": FieldClass.CONFIG, "chain": FieldClass.CONFIG},
    collection_modes={"chain": CollectionMode.ORDERED_KEYED},
)


def manifest(chain: list[str]) -> Manifest:
    members: list[JsonValue] = [*chain]
    state: dict[str, JsonValue] = {"_id": "fw1", "name": "fw fw1", "chain": members}
    resources = {"firewall": CollectedResource([CollectedObject("fw1", state, "fw fw1")])}
    return build_manifest(
        resources, controller_version="1.0", normaliser_version=NORMALISER_VERSION
    )


def keyless_label(fingerprinter: Fingerprinter | None) -> str:
    """The label of the member that moved when ``CANARY`` and ``second`` swap places."""
    previous = manifest([CANARY, "second", "third"])
    new = manifest(["second", CANARY, "third"])
    pending: dict[str, bytes] = {**previous.pending_states, **new.pending_states}

    def lookup(state_hash: str) -> Mapping[str, JsonValue]:
        loaded = json.loads(pending[state_hash])
        assert isinstance(loaded, dict)
        return loaded

    items = compare_order(
        previous,
        new,
        lookup,
        window_start=START,
        window_end=END,
        type_tables={"firewall": TABLE},
        fingerprinter=fingerprinter,
    )
    assert len(items) == 1
    detail = items[0].order_detail
    assert detail is not None
    return str(detail["key"])


def test_a_keyless_label_is_a_keyed_hash_not_a_hash_of_the_content() -> None:
    label = keyless_label(FINGERPRINTER)
    assert LABEL.fullmatch(label)
    assert label == keyless_label(FINGERPRINTER)
    assert label != keyless_label(OTHER)
    unkeyed = {
        f"member:{hashlib.sha256(form.encode()).hexdigest()[:12]}"
        for text in (CANARY, "second", "third")
        for form in (text, json.dumps(text))
    }
    assert label not in unkeyed


def test_without_a_fingerprinter_the_label_is_still_keyed() -> None:
    label = keyless_label(None)
    assert LABEL.fullmatch(label)
    assert label == keyless_label(None)
    assert label != keyless_label(FINGERPRINTER)

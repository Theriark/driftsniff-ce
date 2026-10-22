"""The Xen Orchestra pool fixture and the pipeline helpers the P8-T4 tests share.

``tests/fixtures/xo/pool.json`` is one small hand written pool as an admin session sees it, all 20
collections the collector reads. Everything in it is **unverified** (no lab Xen Orchestra, the
vendor reference was not read; docs/vendor-notes/xo.md). The file holds no secret value, not even
a made up one: ``@canary:<label>`` and ``@shape:<kind>:<label>`` are placeholders that
:func:`seeded` replaces with the value :class:`Seeds` gives for the label, so one label always gets
one value in a test and another value in the next one. A shape is a credential shaped text built
around that value (url, token, jwt, pem or remote); the pieces are assembled here so that no secret
scanner sees a credential in the repository.

The file also holds the simulated backup run. A backup run in Xen Orchestra snapshots the VMs,
copies the disks and deletes the snapshots again, so for a while the pool looks different: new
snapshot objects, changed snapshot and disk lists, other parents, other power and memory numbers.
``during`` is the pool in the middle of the run, ``after`` the pool when it is over; neither changes
any configuration, so a collection of either must show no change.
"""

import copy
import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any, Final, Literal

from driftsniff.collectors.xo.client import XoClient
from driftsniff.collectors.xo.resources import COLLECTIONS
from driftsniff.db.engine import Database, database_path
from driftsniff.db.migrate import upgrade_to_head
from driftsniff.sources.runs import RunPipeline, RunReport

from .fake_xo import CANARY_TOKEN, FakeXo, Scenario
from .unifi_bands import SOURCE_ID, Seeds, make_pipeline

__all__ = [
    "CANARY_TOKEN",
    "SOURCE_ID",
    "Phase",
    "Seeds",
    "benign_seeds",
    "collect",
    "kept_counts",
    "load_pool",
    "make_pipeline",
    "open_database",
    "pool_scenario",
    "seeded",
]

POOL_FILE: Final = Path(__file__).resolve().parents[1] / "fixtures" / "xo" / "pool.json"
SHAPE: Final = re.compile(r"@shape:([a-z]+):([a-z0-9-]+)")
CANARY: Final = re.compile(r"@canary:([a-z0-9-]+)")
BUILT_IN_MARKER: Final = "isDefaultTemplate"

Phase = Literal["base", "during", "after"]


def load_pool() -> dict[str, Any]:
    """The JSON of the pool, placeholders untouched."""
    loaded = json.loads(POOL_FILE.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def _url(value: str) -> str:
    return f"https://svc:{value}@host.example.invalid/api"


def _token(value: str) -> str:
    return "gh" + "p_" + value


def _jwt(value: str) -> str:
    return "ey" + "J" + "hbGciOiJIUzI1NiJ9" + "." + value + "." + "c2lnbmF0dXJl"


def _pem(value: str) -> str:
    return "-----BEGIN " + "PRIVATE KEY-----\n" + value + "\n-----END " + "PRIVATE KEY-----"


def _remote(value: str) -> str:
    return f"smb://svc:{value}@192.0.2.20/share"


SHAPES: Final[dict[str, Callable[[str], str]]] = {
    "url": _url,
    "token": _token,
    "jwt": _jwt,
    "pem": _pem,
    "remote": _remote,
}


def benign_seeds() -> Seeds:
    """Seeds whose values are plain words: the same label always gives the same text."""
    return Seeds(lambda label: f"placeholder-{label}")


def _fill(text: str, seeds: Seeds) -> str:
    def shaped(match: re.Match[str]) -> str:
        return SHAPES[match.group(1)](seeds.value(match.group(2)))

    def plain(match: re.Match[str]) -> str:
        return seeds.value(match.group(1))

    return CANARY.sub(plain, SHAPE.sub(shaped, text))


def seeded(value: Any, seeds: Seeds) -> Any:
    """``value`` with every placeholder replaced by the value ``seeds`` gives for its label."""
    if isinstance(value, str):
        return _fill(value, seeds)
    if isinstance(value, list):
        return [seeded(item, seeds) for item in value]
    if isinstance(value, dict):
        return {key: seeded(item, seeds) for key, item in value.items()}
    return value


def _set_path(item: dict[str, Any], path: str, value: Any) -> None:
    target = item
    parts = path.split(".")
    for part in parts[:-1]:
        child = target.setdefault(part, {})
        assert isinstance(child, dict)
        target = child
    target[parts[-1]] = value


def _apply(collections: dict[str, list[dict[str, Any]]], changes: list[dict[str, Any]]) -> None:
    for change in changes:
        matches = [item for item in collections[change["in"]] if item["id"] == change["id"]]
        assert len(matches) == 1, f"the change names no single object: {change['in']}"
        for path, value in change["set"].items():
            _set_path(matches[0], path, copy.deepcopy(value))


def pool_scenario(
    seeds: Seeds,
    phase: Phase = "base",
    *,
    expected_token: str | None = CANARY_TOKEN,
) -> Scenario:
    """The fake Xen Orchestra of the pool in one phase of the backup run.

    The collections that the collector never requests (snapshots, tasks, logs, alarms) are served
    too, so that a request for one of them would find objects. In ``during`` the two snapshot
    collections and the task list hold the objects of the run.
    """
    data = load_pool()
    collections = seeded(data["collections"], seeds)
    objects: dict[str, list[dict[str, Any]]] = dict(collections)
    objects.update(copy.deepcopy(data["excluded"]))
    if phase != "base":
        _apply(collections, copy.deepcopy(data["backupRun"][phase]))
    if phase == "during":
        objects.update(copy.deepcopy(data["backupRun"]["snapshotObjects"]))
    return Scenario(expected_token=expected_token, objects=objects)


def kept_counts() -> dict[str, int]:
    """How many objects of each collection the collector keeps: a built in template is dropped."""
    counts: dict[str, int] = {}
    for name, items in load_pool()["collections"].items():
        counts[name] = sum(1 for item in items if item.get(BUILT_IN_MARKER) is not True)
    assert sorted(counts) == sorted(COLLECTIONS), "the fixture must hold every collection"
    return counts


def open_database(directory: Path) -> Database:
    """A migrated database with one Xen Orchestra source (id 1)."""
    store = Database(database_path(directory))
    upgrade_to_head(store)
    with store.write() as connection:
        connection.exec_driver_sql(
            "INSERT INTO sources (id, name, type) VALUES (1, 'lab-xo', 'xo')"
        )
    return store


def collect(
    pipeline: RunPipeline, server: FakeXo, *, token: str = CANARY_TOKEN, **options: Any
) -> RunReport:
    """One run of the real client against the fake Xen Orchestra."""
    client = XoClient(server.url, token, allow_plain_http=True, **options)
    return pipeline.run(SOURCE_ID, client)

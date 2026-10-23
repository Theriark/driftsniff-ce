"""The words of a source's status (THE-991, findings of the P10 live acceptance).

F1: a failed test connection gives its reason as a sentence before "Nothing was stored.".
F2: the sources pages show the last attempt (the newest finished run, failed or not), so the
time agrees with a Failing status; a failed run does not move ``last_checked_at``.

The pages are driven through the real application with plain inserts of sources and runs, the
way the run pipeline writes them. Everything is synthetic.
"""

import re
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from html.parser import HTMLParser

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient

from driftsniff.collectors.base import ERROR_CONNECTION, Collector, CollectorError
from driftsniff.config import Settings
from driftsniff.db.engine import Database
from driftsniff.db.tables import runs, sources
from driftsniff.main import create_app
from driftsniff.secrets.crypto import CredentialCipher
from driftsniff.secrets.keys import MasterKey
from driftsniff.sources.probe import ProbeResult, ProbeTarget, start_probe
from driftsniff.sources.service import SourceService
from driftsniff.web.auth import SESSION_COOKIE, AuthService, make_password_hasher
from driftsniff.web.dashboard import DashboardService, stamp
from driftsniff.web.source_pages import SourcePages
from driftsniff.web.templating import Shell, render, sentence

ORIGIN = "http://testserver"
MASTER = MasterKey(bytes(range(32)))
CORRECT = "CANARY-correct horse battery"  # noqa: S105
BROWSER = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}
NOW = datetime(2026, 10, 23, 12, 0, tzinfo=UTC)
UNRESOLVED = "the controller address cannot be resolved"


def at(**delta: int) -> str:
    """A stored time relative to NOW (``minutes=-4`` is four minutes before)."""
    return stamp(NOW + timedelta(**delta))


class Text(HTMLParser):
    """The text of a page, whitespace collapsed."""

    def __init__(self, html: str) -> None:
        super().__init__()
        self.parts: list[str] = []
        self.feed(html)

    def handle_data(self, data: str) -> None:
        self.parts.append(data)

    def joined(self) -> str:
        return " ".join(" ".join(self.parts).split())


# ---- F1: the reason of a failed test connection is a sentence -----------------------------


def unresolved(target: ProbeTarget) -> Collector:
    raise CollectorError(ERROR_CONNECTION, UNRESOLVED)


def probe_panel(error_text: str | None) -> str:
    """The test connection panel of a failed test, as the HTMX answer renders it."""
    target = ProbeTarget(
        source_type="unifi", base_url="https://nowhere.invalid", credential=b"", options={}
    )
    result = start_probe(unresolved, target)
    assert not result.ok and result.error_text == UNRESOLVED
    if error_text is None:
        result = ProbeResult(False, error_class=ERROR_CONNECTION)
    body = render(
        "sources/_probe.html",
        Shell(title=""),
        probe=result,
        probe_rows=(),
        problems=[],
        probe_unavailable=False,
        unavailable_text=("", ""),
        now=NOW,
    )
    return " ".join(body.split())


def test_sentence_capitalises_and_ends_with_one_full_stop() -> None:
    assert sentence(UNRESOLVED) == "The controller address cannot be resolved."
    assert sentence("Already a sentence.") == "Already a sentence."
    assert sentence("HTTP 503 from the controller") == "HTTP 503 from the controller."


def test_a_failed_test_connection_says_why_in_a_sentence() -> None:
    text = probe_panel(UNRESOLVED)
    assert "The connection test failed" in text
    assert "The controller address cannot be resolved. Nothing was stored." in text
    assert "the controller address cannot be resolved Nothing" not in text


def test_a_failed_test_connection_without_a_reason_keeps_its_fixed_sentence() -> None:
    text = probe_panel(None)
    assert "The controller could not be used. Nothing was stored." in text


# ---- the application -------------------------------------------------------------------------


@pytest.fixture
def client(store: Database) -> Iterator[TestClient]:
    auth = AuthService(store, hasher=make_password_hasher(memory_kib=8, time_cost=1))
    auth.create_user("root", CORRECT, "admin")
    auth.create_user("viewer", CORRECT, "viewer")
    service = SourceService(store, CredentialCipher.from_master(MASTER))
    app = create_app(
        Settings.from_env({"DRIFTSNIFF_BASE_URL": ORIGIN, "DRIFTSNIFF_ENVIRONMENT_LABEL": "Test"}),
        master_key=MASTER,
        auth=auth,
        sources=SourcePages(store, service, clock=lambda: NOW),
        dashboard=DashboardService(store, clock=lambda: NOW),
    )
    with TestClient(app, base_url=ORIGIN, follow_redirects=False) as built:
        response = built.post("/login", data={"username": "viewer", "password": CORRECT})
        assert response.status_code == 303, response.text
        match = re.search(rf"{SESSION_COOKIE}=([^;]+)", response.headers["set-cookie"])
        assert match is not None
        built.cookies.clear()
        built.headers.update({**BROWSER, "Cookie": f"{SESSION_COOKIE}={match.group(1)}"})
        yield built


def page(client: TestClient, path: str) -> str:
    response = client.get(path)
    assert response.status_code == 200, response.text[:300]
    return response.text


def add_source(store: Database, name: str, source_type: str = "unifi") -> int:
    with store.write() as connection:
        return int(
            connection.execute(
                sa.insert(sources)
                .values(
                    name=name,
                    type=source_type,
                    base_url=None if source_type == "push" else "https://controller.example",
                    options={} if source_type == "push" else {"interval_seconds": 600},
                )
                .returning(sources.c.id)
            ).scalar_one()
        )


def add_run(store: Database, source_id: int, finished_at: str, status: str) -> None:
    """A finished run as the pipeline writes it; a failed run leaves last_checked_at alone."""
    failed = status == "failed"
    with store.write() as connection:
        connection.execute(
            sa.insert(runs).values(
                source_id=source_id,
                started_at=finished_at,
                finished_at=finished_at,
                status=status,
                error_class=ERROR_CONNECTION if failed else None,
                error_summary="the controller could not be reached" if failed else None,
            )
        )
        if not failed:
            connection.execute(
                sa.update(sources)
                .where(sources.c.id == source_id)
                .values(last_checked_at=finished_at)
            )


def list_row(html: str, name: str) -> str:
    """The text of the source list row that names ``name``."""
    rows = [Text("<tr" + row).joined() for row in html.split("<tr")[1:]]
    return next(row for row in rows if f" {name} " in f" {row} ")


# ---- F2: the last attempt agrees with the status --------------------------------------------


def test_the_last_attempt_is_the_newest_finished_run_failed_or_not(store: Database) -> None:
    failing = add_source(store, "failing-gw")
    add_run(store, failing, at(hours=-2), "ok")
    add_run(store, failing, at(minutes=-4), "failed")  # last_checked_at stays two hours back
    never_ok = add_source(store, "never-ok")
    add_run(store, never_ok, at(minutes=-6), "failed")
    healthy = add_source(store, "healthy-gw")
    add_run(store, healthy, at(minutes=-3), "ok")
    skipped = add_source(store, "skipped-gw")
    add_run(store, skipped, at(minutes=-2), "skipped")
    untouched = add_source(store, "untouched-gw")
    loaded = DashboardService(store, clock=lambda: NOW).load()
    health = {source.id: source for source in loaded.sources}
    assert health[failing].kind == "failing"
    assert health[failing].last_attempt == NOW - timedelta(minutes=4)
    assert health[never_ok].kind == "failing"
    assert health[never_ok].last_attempt == NOW - timedelta(minutes=6)
    assert health[healthy].kind == "ok"
    assert health[healthy].last_attempt == NOW - timedelta(minutes=3)
    assert health[skipped].last_attempt is None  # a skipped run is not a check
    assert health[untouched].kind == "open" and health[untouched].last_attempt is None


def test_the_pages_show_the_last_attempt_after_a_failed_run(
    store: Database, client: TestClient
) -> None:
    failing = add_source(store, "failing-gw")
    add_run(store, failing, at(days=-3), "ok")
    add_run(store, failing, at(hours=-1), "failed")  # last_checked_at stays three days back
    healthy = add_source(store, "healthy-gw")
    add_run(store, healthy, at(minutes=-2), "ok")
    untouched = add_source(store, "untouched-gw")
    listing = page(client, "/sources")
    assert "Last attempt" in Text(listing).joined()
    assert "Last check" not in Text(listing).joined()
    row = list_row(listing, "failing-gw")
    assert "Failing" in row and "1 hour ago" in row
    assert "3 days ago" not in row and "No check yet" not in row
    row = list_row(listing, "healthy-gw")
    assert "Healthy" in row and "2 minutes ago" in row
    row = list_row(listing, "untouched-gw")
    assert "No check yet" in row and "Failing" not in row and "minutes ago" not in row
    detail = Text(page(client, f"/sources/{failing}")).joined()
    assert "Failing" in detail and "Last attempt 1 hour ago" in detail
    assert "No check yet" not in detail
    detail = Text(page(client, f"/sources/{healthy}")).joined()
    assert "Healthy" in detail and "Last attempt 2 minutes ago" in detail
    detail = Text(page(client, f"/sources/{untouched}")).joined()
    assert "No check yet" in detail and "Last attempt" not in detail

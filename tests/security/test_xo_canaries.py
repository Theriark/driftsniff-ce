"""Canary leak test of the Xen Orchestra collector, one full run of the pool fixture (P8-T4).

``tests/fixtures/xo/pool.json`` has a placeholder in every place a credential can hide: the sign in
methods of a user and the device configuration of a storage connection (secret class), the user and
password part of a remote address, a server address and proxy, and the free text of VMs, templates,
hosts, pools and networks (notes, descriptions, ``PV_args``, ``otherConfig`` maps, cloud style
text). The test replaces each placeholder with a fresh canary (and makes the session credential a
canary too), runs the real client and the real run pipeline against the fake Xen Orchestra, and
then looks for every canary on every surface of the harness: the database file, its rows and the
decompressed states, the log output, the text of errors and run records, standard output and error
and the request lines the server received.

The run covers the cases where a credential is most likely to leak: the backup run, a server that
repeats the cookie it received in its error answers, a collection that fails halfway through a
line that holds a canary, and a refused credential.

Credential shaped values (a url with a password, a well known token prefix, a JWT, a PEM block) are
what the scanner recognises in free text. A plain word in a field the type table does not name is
stored as received; the table classes ``authProviders`` and ``device_config`` as secret for that
reason (docs/vendor-notes/xo.md).
"""

import json
import re
from pathlib import Path

import pytest
from contract.fake_xo import FakeXo, fake_xo
from contract.xo_pool import (
    POOL_FILE,
    Seeds,
    collect,
    make_pipeline,
    open_database,
    pool_scenario,
)

from driftsniff.collectors.xo.client import XoClient
from driftsniff.sources.runs import RunReport

from .canary import (
    SURFACE_ERRORS,
    SURFACE_OUTPUT,
    CanaryFactory,
    CanaryScanner,
    Leak,
    assert_no_leaks,
    capture_logs,
    raised_by,
    scan_database,
    scan_database_files,
    scan_error,
    scan_logs,
)

SURFACE_REQUESTS = "requests"
API_KEY_LABEL = "Xen Orchestra session credential"
LINE_LABEL = "line of a broken answer"
WRONG_LABEL = "credential the server does not know"
LABELS = re.compile(r"@(?:canary|shape:[a-z]+):([a-z0-9-]+)")
# The collector removes the user and password part of a remote address before anything else sees it,
# so these two canaries never reach the pipeline (that is what this test is for).
STRIPPED = frozenset({"remote-nfs-url", "remote-smb-url"})
NEVER_SERVED = frozenset({API_KEY_LABEL, LINE_LABEL, WRONG_LABEL})
ADMIN_ONLY = ("users", "groups", "servers", "backup-repositories")


def served_by(server: FakeXo, session: str) -> str:
    """The raw objects of every collection, as the client hands them to the pipeline."""
    client = XoClient(server.url, session, allow_plain_http=True)
    try:
        client.probe()
        return "".join(json.dumps(client.fetch(spec).objects) for spec in client.resources())
    finally:
        client.close()


def request_lines(server: FakeXo) -> str:
    """Everything the server received except the cookie, where the credential belongs."""
    return "\n".join(
        f"{request.path}?{request.query} {request.authorization}" for request in server.requests
    )


def test_a_full_run_of_the_pool_leaves_no_canary_on_any_surface(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    factory = CanaryFactory()
    seeds = Seeds(lambda label: factory.new(label).value)
    session = factory.new(API_KEY_LABEL).value
    listed = [{"id": session, "expiration": 4102444800000}]
    scenario = pool_scenario(seeds, "base", session, listed=listed)
    database = open_database(tmp_path)
    reports: list[RunReport] = []
    try:
        pipeline = make_pipeline(database)
        with capture_logs() as logs, fake_xo(scenario) as server:
            served = served_by(server, session)
            reports.append(collect(pipeline, server, session=session))
            # The backup run: other snapshots, lists, parents and numbers, the same configuration.
            scenario.objects = pool_scenario(seeds, "during").objects
            reports.append(collect(pipeline, server, session=session))
            # A server that repeats the cookie it received, and a read-only credential.
            scenario.echo_cookie = True
            scenario.status.update({name: 403 for name in ADMIN_ONLY})
            scenario.status["acl-privileges"] = 404
            reports.append(collect(pipeline, server, session=session))
            # An answer that breaks inside a line that holds a canary.
            scenario.status.clear()
            line = factory.new(LINE_LABEL).value
            scenario.raw["groups"] = (
                b'{"id": "group-ops"}\n' + f'{{"id": "group-two", "name": "{line}"'.encode() + b"\n"
            )
            reports.append(collect(pipeline, server, session=session))
            # A credential the server does not know is refused, and the refusal repeats it.
            scenario.raw.clear()
            wrong = factory.new(WRONG_LABEL).value
            reports.append(collect(pipeline, server, session=wrong))
            probe = XoClient(server.url, wrong, allow_plain_http=True)
            try:
                refused = raised_by(probe.probe)
            finally:
                probe.close()
            requests = request_lines(server)

        # The test would pass for nothing if the secrets never reached the pipeline.
        assert [report.status for report in reports] == ["ok", "ok", "partial", "partial", "failed"]
        labels = set(LABELS.findall(POOL_FILE.read_text(encoding="utf-8")))
        assert set(seeds.values) == labels
        assert len(labels) >= 19
        assert logs.lines, "nothing was logged, so the log surface was not exercised"
        for canary in factory.issued:
            if canary.where not in NEVER_SERVED | STRIPPED:
                assert canary.value in served, canary.where
            if canary.where in STRIPPED:
                assert canary.value not in served, canary.where

        scanner = CanaryScanner(factory.issued)
        leaks: list[Leak] = scan_database(scanner, database)
        leaks += scan_logs(scanner, logs)
        leaks += scan_error(scanner, "a refused probe", refused)
        for number, report in enumerate(reports, 1):
            text = f"{report.error_class} {report.error_summary}"
            leaks += scanner.find(SURFACE_ERRORS, f"summary of run report {number}", text)
        leaks += scanner.find(SURFACE_REQUESTS, "request lines without the cookie", requests)
        output = capsys.readouterr()
        leaks += scanner.find(SURFACE_OUTPUT, "standard output", output.out)
        leaks += scanner.find(SURFACE_OUTPUT, "standard error", output.err)
        assert_no_leaks(leaks)

        # Closing the database checkpoints the write-ahead log into the main file; look again.
        database.close()
        assert_no_leaks(scan_database_files(scanner, database))
    finally:
        database.close()

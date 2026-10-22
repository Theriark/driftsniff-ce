"""Canary leak test of the UniFi collector, one full run per version band (P7-T5).

Every band of ``tests/fixtures/unifi`` has a placeholder in each secret class field: the WiFi
passphrase, the RADIUS shared secret and the VPN pre-shared key of servers and tunnels. The test
replaces each placeholder with a fresh canary (and makes the API key a canary too), runs the real
client and the real run pipeline against the fake controller, and then looks for every canary on
every surface of the harness: the database file, its rows and the decompressed states, the log
output, the text of errors and the run records, and standard output and error.

The run also covers the cases where a key is most likely to leak: an unchanged second run, a
controller that echoes the key it received in its error answers, and a refused key.
"""

import json
from pathlib import Path

import pytest
from contract.fake_unifi import FakeUnifi, fake_unifi
from contract.unifi_bands import (
    BANDS,
    SECRET_FIELDS,
    Seeds,
    band_scenario,
    collect,
    make_pipeline,
    open_database,
)

from driftsniff.collectors.base import ResourceSpec
from driftsniff.collectors.unifi.client import UnifiClient
from driftsniff.collectors.unifi.resources import RESOURCE_PATHS
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

API_KEY_LABEL = "UniFi API key"
SECRET_RESOURCES = tuple(
    item.name
    for item in RESOURCE_PATHS.values()
    if item.site_path is not None and item.site_path.lstrip("/") in SECRET_FIELDS
)


def served_by(server: FakeUnifi, key: str) -> str:
    """The raw objects of the secret holding resources, as the client hands them on."""
    client = UnifiClient(server.url, key, allow_plain_http=True)
    try:
        client.probe()
        return "".join(
            json.dumps(client.fetch(ResourceSpec(name)).objects) for name in SECRET_RESOURCES
        )
    finally:
        client.close()


@pytest.mark.parametrize("band", BANDS)
def test_a_full_run_against_a_band_leaves_no_canary_on_any_surface(
    band: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    factory = CanaryFactory()
    seeds = Seeds(lambda label: factory.new(f"{band} band, {label}").value)
    key = factory.new(API_KEY_LABEL).value
    scenario = band_scenario(band, seeds)
    scenario.expected_header = key
    database = open_database(tmp_path)
    reports: list[RunReport] = []
    try:
        pipeline = make_pipeline(database)
        with capture_logs() as logs, fake_unifi(scenario) as server:
            served = served_by(server, key)
            reports.append(collect(pipeline, server, key=key))
            reports.append(collect(pipeline, server, key=key))
            # A controller that repeats the key it received in the body of its error answers.
            scenario.echo_header = True
            scenario.status.update({"radius/profiles": 403, "networks": 404})
            reports.append(collect(pipeline, server, key=key))
            # The key is refused, and the refusal repeats it.
            scenario.expected_header = "the key the controller expects"
            reports.append(collect(pipeline, server, key=key))
            probe = UnifiClient(server.url, key, allow_plain_http=True)
            try:
                refused = raised_by(probe.probe)
            finally:
                probe.close()

        # The test would pass for nothing if the secrets never reached the pipeline.
        assert [report.status for report in reports] == ["ok", "ok", "partial", "failed"]
        assert len(seeds.values) == 2 * len(SECRET_FIELDS)
        assert logs.lines, "nothing was logged, so the log surface was not exercised"
        for canary in factory.issued:
            if canary.where != API_KEY_LABEL:
                assert canary.value in served

        scanner = CanaryScanner(factory.issued)
        leaks: list[Leak] = scan_database(scanner, database)
        leaks += scan_logs(scanner, logs)
        leaks += scan_error(scanner, "a refused probe", refused)
        for number, report in enumerate(reports, 1):
            text = f"{report.error_class} {report.error_summary}"
            leaks += scanner.find(SURFACE_ERRORS, f"summary of run report {number}", text)
        output = capsys.readouterr()
        leaks += scanner.find(SURFACE_OUTPUT, "standard output", output.out)
        leaks += scanner.find(SURFACE_OUTPUT, "standard error", output.err)
        assert_no_leaks(leaks)

        # Closing the database checkpoints the write-ahead log into the main file; look again.
        database.close()
        assert_no_leaks(scan_database_files(scanner, database))
    finally:
        database.close()

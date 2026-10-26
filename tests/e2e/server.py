"""A real driftsniff process for the browser journeys (P10-T9, THE-1315).

The journeys talk to the application the way a person does: ``driftsniff serve`` runs as a child
process on a free loopback port with a temporary data directory and a temporary key file. Before
it starts, the Development fixture (docs/dev-fixture.md) is written into that directory with
``seed_fixture`` and a pipeline without a notifier, so the screens have changes of every severity
while the address guard of the fixture, which only allows a Development host, stays untouched.
The one-time setup code is read from the log of the child, as an operator reads it from the
container log. Nothing here uses the network beyond 127.0.0.1.
"""

import http.client
import os
import re
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO

from driftsniff.db.engine import Database, database_path
from driftsniff.db.migrate import upgrade_to_head
from driftsniff.devfixture import _StepClock, seed_fixture
from driftsniff.rules.engine import RuleEngine
from driftsniff.rules.loader import load_rules
from driftsniff.secrets.crypto import CredentialCipher
from driftsniff.secrets.fingerprint import Fingerprinter
from driftsniff.secrets.keys import ensure_master_key
from driftsniff.secrets.scanner import load_overrides
from driftsniff.sources.runs import RunPipeline
from driftsniff.sources.service import SourceService

ROOT = Path(__file__).resolve().parents[2]
LOOPBACK = "127.0.0.1"
START_TIMEOUT_SECONDS = 90.0
SETUP_CODE = re.compile(r"first-run setup code \(shown once\): (\S+)")
SERVE = "import sys; from driftsniff.cli import main; sys.exit(main(['serve']))"


@dataclass
class LiveApp:
    """The running application: where it listens, its setup code and what it logged."""

    base_url: str
    setup_code: str
    process: subprocess.Popen[str]
    lines: list[str] = field(default_factory=list)

    def log_text(self) -> str:
        """The log so far, without the line that carries the one-time code."""
        return "\n".join(line for line in list(self.lines) if "setup code" not in line)

    def stop(self) -> None:
        """End the child process: ask first, then insist."""
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=15)


def free_port() -> int:
    """A TCP port on the loopback address that nobody listens on right now."""
    with socket.socket() as probe:
        probe.bind((LOOPBACK, 0))
        return int(probe.getsockname()[1])


def seed_synthetic_changes(data_dir: Path, key_file: Path) -> None:
    """Migrate the database and run the four fixture documents through the real pipeline."""
    data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    database = Database(database_path(data_dir))
    try:
        upgrade_to_head(database)
        master_key = ensure_master_key(key_file, fingerprints_exist=False)
        clock = _StepClock()
        pipeline = RunPipeline(
            database,
            RuleEngine(load_rules()),
            Fingerprinter.from_master(master_key),
            overrides=load_overrides(),
            clock=clock,
        )
        service = SourceService(database, CredentialCipher.from_master(master_key))
        report = seed_fixture(database, service, pipeline, clock)
        assert report.pushed == 4
        assert report.events == 3
    finally:
        database.close()


def _pump(stream: IO[str], lines: list[str]) -> None:
    for line in stream:
        lines.append(line.rstrip("\n"))


def _healthy(port: int) -> bool:
    connection = http.client.HTTPConnection(LOOPBACK, port, timeout=2)
    try:
        connection.request("GET", "/healthz")
        return connection.getresponse().status == 200
    except (OSError, http.client.HTTPException):
        return False
    finally:
        connection.close()


def start_app(work_dir: Path) -> LiveApp:
    """Seed the fixture, start ``driftsniff serve`` and wait until it answers."""
    data_dir = work_dir / "data"
    key_file = work_dir / "keys" / "master.key"
    seed_synthetic_changes(data_dir, key_file)
    port = free_port()
    base_url = f"http://{LOOPBACK}:{port}"
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(work_dir),
        "LANG": "C.UTF-8",
        "PYTHONUNBUFFERED": "1",
        "PYTHONPATH": str(ROOT / "src"),
        "DRIFTSNIFF_PORT": str(port),
        "DRIFTSNIFF_BASE_URL": base_url,
        "DRIFTSNIFF_DATA_DIR": str(data_dir),
        "DRIFTSNIFF_KEY_FILE": str(key_file),
        "DRIFTSNIFF_ENVIRONMENT_LABEL": "Journeys",
    }
    process = subprocess.Popen(  # noqa: S603
        [sys.executable, "-c", SERVE],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    assert process.stdout is not None
    lines: list[str] = []
    threading.Thread(target=_pump, args=(process.stdout, lines), daemon=True).start()
    app = LiveApp(base_url=base_url, setup_code="", process=process, lines=lines)
    deadline = time.monotonic() + START_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if process.poll() is not None:
            app.stop()
            raise RuntimeError(f"the application stopped while starting:\n{app.log_text()}")
        found = next((m for m in map(SETUP_CODE.search, list(lines)) if m), None)
        if found is not None and _healthy(port):
            app.setup_code = found.group(1)
            return app
        time.sleep(0.25)
    app.stop()
    raise RuntimeError(f"the application did not answer in time:\n{app.log_text()}")

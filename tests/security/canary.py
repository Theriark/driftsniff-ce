"""Canary leak harness (P3-T4, core part).

A canary is a synthetic secret: ``CANARY-`` followed by 24 random hex characters (a value whose
Shannon entropy is below 3.9 bits per character, so the scanner's entropy rule, which fires above
4.2, never decides whether a canary is hidden or found). The harness
puts unique canaries into every secret-class field and every free-text field of a fake source,
runs the real collection path (redact, normalise, build the manifest, store), then looks for the
canaries on every surface where a credential must never appear:

- the database file, its write-ahead log and its shared-memory file, byte for byte;
- every column of every table, and the decompressed content of every compressed column (stored
  states and manifests are zstd frames, so a plain byte search of the file cannot see inside);
- the captured log output, formatted the way the application's handlers format it, with the
  application's log filter installed;
- the text of raised errors, including the traceback and the chained causes;
- standard output and standard error (the tests do that with pytest's capture).

A search looks for the whole canary and for its random hex part alone, so a leak that dropped the
prefix is found too. A hit names the surface, the location and the label of the canary (where it
was injected), never the canary itself.

Free-text canaries are credential-shaped on purpose: free text is configuration, and the scanner
only fingerprints a value that looks like a credential (a URL with a password, a PEM block, a JWT,
a well-known prefix). A plain ``CANARY-<hex>`` sentence in a description is stored as written;
that is by design and ``test_canary_leaks.py`` pins it. Secret-class fields take the plain canary.

Later phases extend the harness to notifications, API output and exports (P9) and to the real
collectors (P7, P8): add a surface function here that returns leaks, and call it from the test.
"""

import base64
import hashlib
import logging
import secrets
import traceback
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

import sqlalchemy as sa

from driftsniff.core.canonical import JsonValue
from driftsniff.core.collection import CollectionResult, record_collection
from driftsniff.core.normalize import FieldClass, StaticTypeTable, normalize_object
from driftsniff.core.runs import start_run
from driftsniff.core.snapshots import CollectedObject, CollectedResource, build_manifest
from driftsniff.core.states import StoredDataError, decompress_bytes
from driftsniff.db.engine import Database
from driftsniff.secrets.crypto import CredentialCipher
from driftsniff.secrets.fingerprint import Fingerprinter
from driftsniff.secrets.redact import ForcedSecret, RedactingFilter, redact_object
from driftsniff.secrets.scanner import shannon_entropy

CANARY_PREFIX = "CANARY-"
CANARY_HEX_CHARS = 24
CANARY_MAX_ENTROPY = 3.9
MAX_DECOMPRESSED_BYTES = 256 * 1024 * 1024
START = datetime(2026, 10, 21, 8, 0, 0, tzinfo=UTC)

SURFACE_FILE = "database file"
SURFACE_ROWS = "database rows"
SURFACE_LOGS = "logs"
SURFACE_ERRORS = "errors"
SURFACE_OUTPUT = "output"

LOG_LEVEL = logging.DEBUG


@dataclass(frozen=True, slots=True)
class Canary:
    """One synthetic secret and the label of the place it was injected into."""

    value: str
    where: str

    @property
    def hex_part(self) -> str:
        return self.value.removeprefix(CANARY_PREFIX)


@dataclass(frozen=True, slots=True)
class Leak:
    """A canary found on a surface. ``location`` says where on the surface."""

    surface: str
    location: str
    where: str

    def describe(self) -> str:
        return f"{self.surface} / {self.location}: canary injected into {self.where}"


class CanaryLeakError(AssertionError):
    """Raised by ``assert_no_leaks``; the message never contains a canary value."""


class CanaryFactory:
    """Issues unique canaries and remembers every one it issued."""

    def __init__(self) -> None:
        self._issued: dict[str, Canary] = {}

    def new(self, where: str) -> Canary:
        while True:
            value = CANARY_PREFIX + secrets.token_hex(CANARY_HEX_CHARS // 2)
            if value not in self._issued and shannon_entropy(value) < CANARY_MAX_ENTROPY:
                break
        canary = Canary(value, where)
        self._issued[value] = canary
        return canary

    @property
    def issued(self) -> tuple[Canary, ...]:
        return tuple(self._issued.values())


class CanaryScanner:
    """Looks for any issued canary in bytes or text."""

    def __init__(self, canaries: Iterable[Canary]) -> None:
        self._needles: list[tuple[bytes, Canary]] = []
        for canary in canaries:
            self._needles.append((canary.value.encode("utf-8"), canary))
            self._needles.append((canary.hex_part.encode("ascii"), canary))

    def find(self, surface: str, location: str, data: bytes | str) -> list[Leak]:
        """Every canary found in ``data``, each reported once."""
        body = data.encode("utf-8", errors="replace") if isinstance(data, str) else data
        found: dict[str, Leak] = {}
        for needle, canary in self._needles:
            if needle in body and canary.value not in found:
                found[canary.value] = Leak(surface, location, canary.where)
        return list(found.values())

    def find_in_encodings(self, surface: str, location: str, data: bytes) -> list[Leak]:
        """Like ``find``, and also in the base64 text of ``data`` read as a stored value."""
        leaks = self.find(surface, location, data)
        try:
            decoded = base64.b64decode(data, validate=True)
        except ValueError:
            return leaks
        return leaks + self.find(surface, location + " (base64 decoded)", decoded)


def assert_no_leaks(leaks: Iterable[Leak]) -> None:
    """Fail with one line per leak; pass when the list is empty."""
    found = list(leaks)
    if found:
        lines = "\n".join(f"  - {leak.describe()}" for leak in found)
        raise CanaryLeakError(f"{len(found)} canary leak(s):\n{lines}")


# --- database surfaces -------------------------------------------------------------------------


def scan_database_files(scanner: CanaryScanner, database: Database) -> list[Leak]:
    """Search the database file, the write-ahead log and the shared-memory file as bytes."""
    leaks: list[Leak] = []
    for suffix in ("", "-wal", "-shm"):
        path = Path(str(database.path) + suffix)
        if path.is_file():
            leaks.extend(scanner.find(SURFACE_FILE, path.name, path.read_bytes()))
    return leaks


def _value_surfaces(value: object) -> Iterator[tuple[str, bytes]]:
    """The byte strings to search for one column value, with a note on how they were made."""
    if value is None:
        return
    if isinstance(value, bytes | bytearray | memoryview):
        raw = bytes(value)
        yield "raw", raw
        try:
            yield "decompressed", decompress_bytes(raw, MAX_DECOMPRESSED_BYTES)
        except StoredDataError:
            pass
        return
    if isinstance(value, str):
        yield "text", value.encode("utf-8", errors="replace")
        return
    yield "text", str(value).encode("utf-8", errors="replace")


def scan_database_rows(scanner: CanaryScanner, database: Database) -> list[Leak]:
    """Search every column of every table; compressed columns are also searched decompressed."""
    leaks: list[Leak] = []
    metadata = sa.MetaData()
    with database.read() as connection:
        metadata.reflect(bind=connection)
        for table in metadata.sorted_tables:
            for number, row in enumerate(connection.execute(sa.select(table)).mappings(), 1):
                for column, value in row.items():
                    for how, data in _value_surfaces(value):
                        location = f"{table.name}.{column} row {number} ({how})"
                        leaks.extend(scanner.find_in_encodings(SURFACE_ROWS, location, data))
    return leaks


def scan_database(scanner: CanaryScanner, database: Database) -> list[Leak]:
    """Every database surface: file bytes first, then rows and decompressed contents."""
    return scan_database_files(scanner, database) + scan_database_rows(scanner, database)


# --- log and error surfaces --------------------------------------------------------------------


class _Collector(logging.Handler):
    """Keeps every record formatted as the application's handlers format it."""

    def __init__(self) -> None:
        super().__init__(LOG_LEVEL)
        self.addFilter(RedactingFilter())
        self.setFormatter(logging.Formatter("%(levelname)s %(name)s %(message)s"))
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        # The filter has already run: the message, its arguments and the exception are scrubbed.
        # The extra attributes of the record are not, so they are part of what is searched.
        extras = {key: value for key, value in vars(record).items() if key not in _STANDARD_FIELDS}
        text = self.format(record)
        self.lines.append(text + ("" if not extras else f" extra={extras!r}"))


_STANDARD_FIELDS = frozenset(vars(logging.makeLogRecord({}))) | {"message", "asctime"}


@dataclass(slots=True)
class LogCapture:
    """The log text captured while a ``capture_logs`` block ran."""

    lines: list[str] = field(default_factory=list)

    @property
    def text(self) -> str:
        return "\n".join(self.lines)


@contextmanager
def capture_logs() -> Iterator[LogCapture]:
    """Capture all logging, from every logger, with the application's log filter installed."""
    root = logging.getLogger()
    handler = _Collector()
    previous_level = root.level
    root.addHandler(handler)
    root.setLevel(LOG_LEVEL)
    captured = LogCapture()
    try:
        yield captured
    finally:
        root.removeHandler(handler)
        root.setLevel(previous_level)
        captured.lines = handler.lines


def scan_logs(scanner: CanaryScanner, captured: LogCapture) -> list[Leak]:
    leaks: list[Leak] = []
    for number, line in enumerate(captured.lines, 1):
        leaks.extend(scanner.find(SURFACE_LOGS, f"log line {number}", line))
    return leaks


def error_text(error: BaseException) -> str:
    """The message, the full traceback and every chained cause or context of ``error``."""
    return "".join(traceback.format_exception(error)) + repr(error) + repr(error.args)


def raised_by(call: Callable[[], object]) -> BaseException:
    """Run ``call``, which must raise, and return what it raised."""
    try:
        call()
    except Exception as error:
        return error
    raise AssertionError("the call was expected to raise and did not")


def scan_errors(scanner: CanaryScanner, errors: Mapping[str, BaseException]) -> list[Leak]:
    """Search the text of each error; the key names the call that raised it."""
    return [leak for name, error in errors.items() for leak in scan_error(scanner, name, error)]


def scan_error(scanner: CanaryScanner, name: str, error: BaseException) -> list[Leak]:
    return scanner.find(SURFACE_ERRORS, f"error from {name}", error_text(error))


# --- the fake source ---------------------------------------------------------------------------

WLAN = "unifi-wlan"
SERVER = "xo-server"

WLAN_TYPE = StaticTypeTable(
    object_key_field="_id",
    name_field="name",
    field_classes={
        "_id": FieldClass.CONFIG,
        "name": FieldClass.CONFIG,
        "vlan": FieldClass.CONFIG,
        "enabled": FieldClass.CONFIG,
        "x_passphrase": FieldClass.SECRET,
        "radius_secret": FieldClass.SECRET,
        "api_tokens": FieldClass.SECRET,
        "description": FieldClass.CONFIG,
        "notes": FieldClass.CONFIG,
        "options.shared_key": FieldClass.SECRET,
    },
)
SERVER_TYPE = StaticTypeTable(
    object_key_field="_id",
    name_field="name",
    field_classes={
        "_id": FieldClass.CONFIG,
        "name": FieldClass.CONFIG,
        "label": FieldClass.CONFIG,
        "address": FieldClass.CONFIG,
        "password": FieldClass.SECRET,
        "apiToken": FieldClass.SECRET,
    },
)
TYPE_TABLES: Mapping[str, StaticTypeTable] = {WLAN: WLAN_TYPE, SERVER: SERVER_TYPE}

OBJECTS_PER_RESOURCE = 3


def _url_with_password(canary: Canary) -> str:
    return "https://svc:" + canary.value + "@controller.example.invalid/api"


def _prefixed_token(canary: Canary) -> str:
    return "gh" + "p_" + canary.value


def _jwt_like(canary: Canary) -> str:
    return "ey" + "J" + "hbGciOiJIUzI1NiJ9" + "." + canary.value + "." + "c2lnbmF0dXJl"


def _pem_block(canary: Canary) -> str:
    return "-----BEGIN " + "PRIVATE KEY-----\n" + canary.value + "\n-----END " + "PRIVATE KEY-----"


SHAPES: tuple[Callable[[Canary], str], ...] = (
    _url_with_password,
    _prefixed_token,
    _jwt_like,
    _pem_block,
)


class FakeSource:
    """Makes raw controller objects whose secret and free-text fields hold fresh canaries.

    Every call of ``raw_objects`` issues new canaries, so a second revision has its own. The
    free-text fields hold the canary inside a credential-shaped value (see the module text); the
    shape changes from field to field so every scanner rule that can carry a canary is used.
    """

    def __init__(self, factory: CanaryFactory) -> None:
        self._factory = factory
        self._shape = 0
        self.secret_locations: list[tuple[str, str, str]] = []
        self.free_text_locations: list[tuple[str, str, str]] = []

    def _secret(self, resource: str, key: str, path: str) -> str:
        self.secret_locations.append((resource, key, path))
        return self._factory.new(f"{resource}/{key}/{path} (secret)").value

    def _free_text(self, resource: str, key: str, path: str) -> str:
        shape = SHAPES[self._shape % len(SHAPES)]
        self._shape += 1
        self.free_text_locations.append((resource, key, path))
        canary = self._factory.new(f"{resource}/{key}/{path} (free text)")
        return "ticket 4711: " + shape(canary) + " handled by the network team"

    def raw_objects(self, revision: int) -> dict[str, list[dict[str, JsonValue]]]:
        """One revision of the controller: three WLANs and three servers."""
        wlans: list[dict[str, JsonValue]] = []
        servers: list[dict[str, JsonValue]] = []
        for number in range(OBJECTS_PER_RESOURCE):
            key = f"w{number}"
            wlans.append(
                {
                    "_id": key,
                    "name": f"Lab {number}",
                    "vlan": 100 + number,
                    "enabled": True,
                    "x_passphrase": self._secret(WLAN, key, "x_passphrase"),
                    "radius_secret": self._secret(WLAN, key, "radius_secret"),
                    "api_tokens": [
                        self._secret(WLAN, key, "api_tokens"),
                        self._secret(WLAN, key, "api_tokens"),
                    ],
                    "description": self._free_text(WLAN, key, "description"),
                    "comment": self._free_text(WLAN, key, "comment"),
                    "notes": [self._free_text(WLAN, key, "notes"), f"revision {revision}"],
                    "options": {
                        "owner_note": self._free_text(WLAN, key, "options.owner_note"),
                        "shared_key": self._secret(WLAN, key, "options.shared_key"),
                        "vendor": {"hint": self._free_text(WLAN, key, "options.vendor.hint")},
                    },
                }
            )
            key = f"s{number}"
            servers.append(
                {
                    "_id": key,
                    "name": f"Pool {number}",
                    "label": self._free_text(SERVER, key, "label"),
                    "address": self._free_text(SERVER, key, "address"),
                    "password": self._secret(SERVER, key, "password"),
                    "apiToken": self._secret(SERVER, key, "apiToken"),
                }
            )
        return {WLAN: wlans, SERVER: servers}


@dataclass(frozen=True, slots=True)
class CollectionReport:
    """What one fake collection did, besides storing."""

    result: CollectionResult
    fingerprints: int
    forced: tuple[ForcedSecret, ...]


def at(second: int) -> str:
    return (START + timedelta(seconds=second)).strftime("%Y-%m-%dT%H:%M:%SZ")


def collect(
    database: Database,
    fingerprinter: Fingerprinter,
    raw: Mapping[str, list[dict[str, JsonValue]]],
    *,
    source_id: int,
    second: int,
) -> CollectionReport:
    """Redact, normalise, store: the path a collector takes, with a fake source's objects."""
    resources: dict[str, CollectedResource] = {}
    fingerprints = 0
    forced: list[ForcedSecret] = []
    for resource, objects in raw.items():
        table = TYPE_TABLES[resource]
        collected: list[CollectedObject] = []
        for raw_object in objects:
            redacted = redact_object(table, resource, raw_object, fingerprinter)
            fingerprints += redacted.fingerprints
            forced.extend(redacted.forced)
            state = normalize_object(table, redacted.value)
            key = state[table.object_key_field or "_id"]
            name = state.get(table.name_field or "name")
            display_name = name if isinstance(name, str) else None
            collected.append(CollectedObject(str(key), state, display_name))
        resources[resource] = CollectedResource(collected)
    manifest = build_manifest(resources, controller_version="canary-1.0")
    logging.getLogger("driftsniff.canary").info(
        "collected %d objects of %d resources", manifest.object_count, len(resources)
    )
    with database.write() as connection:
        run_id = start_run(connection, source_id, at(second))
        result = record_collection(
            connection,
            source_id=source_id,
            run_id=run_id,
            manifest=manifest,
            bytes_fetched=0,
            finished_at=at(second + 1),
        )
    return CollectionReport(result, fingerprints, tuple(forced))


def insert_source(
    database: Database, factory: CanaryFactory, cipher: CredentialCipher, source_id: int
) -> None:
    """A source whose credential and push key are canaries, stored as the product stores them.

    The credential is encrypted with the credential key; of the push key only its SHA-256 is kept.
    """
    credential = factory.new("source credential")
    push_key = factory.new("source push key")
    sealed = cipher.encrypt(source_id, credential.value.encode("utf-8"))
    with database.write() as connection:
        connection.execute(
            sa.text(
                "INSERT INTO sources (id, name, type, credential_ciphertext, key_id, "
                "push_token_hash) VALUES (:id, 'canary-source', 'push', :ciphertext, :key_id, "
                ":hash)"
            ),
            {
                "id": source_id,
                "ciphertext": sealed.ciphertext,
                "key_id": sealed.key_id,
                "hash": hashlib.sha256(push_key.value.encode("utf-8")).hexdigest(),
            },
        )

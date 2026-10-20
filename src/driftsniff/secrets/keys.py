"""Master key management: create, load and derive the keys the other secrets modules use.

The master key is 32 random bytes in a file on the key volume (mode 0400 or 0600). Stored secret
fingerprints can only be checked with the key that made them, so the file is never replaced:
if fingerprints exist and the file is gone, the application refuses to start (exit code 4)
instead of silently creating a new key. Purpose keys come from HKDF-SHA256, one label each.

Creating the key is atomic: it is written to a private temporary file and published with a hard
link, which fails when the name exists. Two processes that start together agree on one key, and
no process can read a half-written file.
"""

import hashlib
import os
import stat
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

import sqlalchemy as sa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from driftsniff.db.engine import Database
from driftsniff.db.tables import DEFAULT_WORKSPACE_ID, settings

KEY_BYTES = 32
KEY_ID_HEX_CHARS = 8
KEY_FILE_MODE = 0o400
ALLOWED_KEY_FILE_MODES = (0o400, 0o600)
EXIT_KEY_MISSING = 4
EXIT_KEY_UNUSABLE = 1

FP_IN_USE_SETTING = "fp_in_use"
FP_IN_USE_VALUE = "1"

FINGERPRINT_LABEL = "driftsniff/fingerprint/v1"
CREDENTIAL_LABEL = "driftsniff/credential/v1"
SESSION_LABEL = "driftsniff/session/v1"
WEBHOOK_LABEL = "driftsniff/webhook/v1"

# A file that is still being written (file systems without hard links) is re-read this often.
_SETTLE_ATTEMPTS = 10
_SETTLE_DELAY_SECONDS = 0.05

_MISSING_WITH_FINGERPRINTS = (
    "master key file {path} is missing but secret fingerprints are already stored. A new key "
    "would make every stored fingerprint and encrypted credential unverifiable, so driftsniff "
    "never creates a replacement. Restore the key file from your backup of the key volume "
    "and start again."
)
_BAD_MODE = (
    "master key file {path} has mode {mode:04o}; it must be 0400 or 0600. Restrict it with "
    "chmod 0400 and start again."
)
_NOT_REGULAR = "cannot read master key file {path}: not a regular file"
_WRONG_SIZE = "master key file {path} must hold exactly 32 bytes"


class MasterKeyError(Exception):
    """Base class for master key problems; messages never contain key material."""


class MasterKeyMissingError(MasterKeyError):
    """The key file does not exist (and must not be replaced)."""


class MasterKeyInvalidError(MasterKeyError):
    """The key file cannot be read, has a bad mode, or does not hold exactly 32 bytes."""


class MasterKeyTruncatedError(MasterKeyInvalidError):
    """The key file holds fewer than 32 bytes (it may still be being written)."""


@dataclass(frozen=True, slots=True)
class DerivedKeys:
    """The four purpose keys (32 bytes each); the repr never shows them."""

    fingerprint: bytes = field(repr=False)
    credential: bytes = field(repr=False)
    session: bytes = field(repr=False)
    webhook: bytes = field(repr=False)


class MasterKey:
    """The master key material and its key id; the repr shows only the key id."""

    __slots__ = ("_material", "key_id")

    def __init__(self, material: bytes) -> None:
        if len(material) != KEY_BYTES:
            raise MasterKeyInvalidError(f"a master key must hold exactly {KEY_BYTES} bytes")
        self._material = material
        self.key_id = hashlib.sha256(material).hexdigest()[:KEY_ID_HEX_CHARS]

    def derive(self, label: str) -> bytes:
        """HKDF-SHA256 (no salt, the label as info) to 32 bytes."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=KEY_BYTES,
            salt=None,
            info=label.encode("utf-8"),
        )
        return hkdf.derive(self._material)

    def derived_keys(self) -> DerivedKeys:
        """Derive all four purpose keys."""
        return DerivedKeys(
            fingerprint=self.derive(FINGERPRINT_LABEL),
            credential=self.derive(CREDENTIAL_LABEL),
            session=self.derive(SESSION_LABEL),
            webhook=self.derive(WEBHOOK_LABEL),
        )

    def __repr__(self) -> str:
        return f"MasterKey(key_id={self.key_id!r})"


def load_master_key(path: Path) -> MasterKey:
    """Read the key file.

    A symbolic link, a directory or any other file that is not a regular file is refused; so is
    a file whose mode is not 0400 or 0600 (checked on the opened file, not on the name) and a
    file that does not hold exactly 32 bytes.
    """
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        raise MasterKeyMissingError(f"master key file {path} not found") from None
    except OSError as error:
        raise MasterKeyInvalidError(
            f"cannot open master key file {path}: {error.strerror}"
        ) from None
    try:
        handle = os.fdopen(descriptor, "rb")
    except OSError as error:
        os.close(descriptor)
        raise MasterKeyInvalidError(
            f"cannot read master key file {path}: {error.strerror}"
        ) from None
    with handle:
        try:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise MasterKeyInvalidError(_NOT_REGULAR.format(path=path))
            mode = stat.S_IMODE(info.st_mode)
            if mode not in ALLOWED_KEY_FILE_MODES:
                raise MasterKeyInvalidError(_BAD_MODE.format(path=path, mode=mode))
            material = handle.read(KEY_BYTES + 1)
        except OSError as error:
            raise MasterKeyInvalidError(
                f"cannot read master key file {path}: {error.strerror}"
            ) from None
    if len(material) != KEY_BYTES:
        if len(material) < KEY_BYTES:
            raise MasterKeyTruncatedError(_WRONG_SIZE.format(path=path))
        raise MasterKeyInvalidError(_WRONG_SIZE.format(path=path))
    return MasterKey(material)


def _load_settled(path: Path) -> MasterKey:
    """Load the key, waiting a moment while a file that is too short is still being written."""
    for _ in range(_SETTLE_ATTEMPTS - 1):
        try:
            return load_master_key(path)
        except MasterKeyTruncatedError:
            time.sleep(_SETTLE_DELAY_SECONDS)
    return load_master_key(path)


def _remove_quietly(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass


def _write_exclusive(path: Path, material: bytes) -> None:
    """Create ``path`` with exclusive create and mode 0400, write and sync; remove it on failure.

    Raises FileExistsError when ``path`` exists; that file is never touched.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags, KEY_FILE_MODE)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(material)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        # This process created the file a moment ago, so removing the partial file is safe.
        _remove_quietly(path)
        raise


def _create_key_file(path: Path) -> MasterKey:
    """Publish a new random key at ``path`` all at once; raises FileExistsError if it exists.

    The key is written and synced to a private temporary file in the same directory, then
    hard-linked to its final name. The link is atomic and fails when the name exists, so no other
    process can read a half-written key and an existing key is never replaced. On a file system
    without hard links the key is created in place with exclusive create instead; readers then
    wait for the file to settle (see ``_load_settled``).
    """
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    material = os.urandom(KEY_BYTES)
    temporary = path.with_name(f".{path.name}.{os.urandom(8).hex()}.tmp")
    _write_exclusive(temporary, material)
    try:
        os.link(temporary, path)
    except FileExistsError:
        raise
    except OSError:
        _write_exclusive(path, material)
    finally:
        _remove_quietly(temporary)
    return MasterKey(material)


def ensure_master_key(path: Path, *, fingerprints_exist: bool) -> MasterKey:
    """Load the master key, creating it only when no fingerprint depends on it.

    An existing file is never overwritten. When fingerprints exist and the file is missing,
    MasterKeyMissingError is raised and nothing is created. Two processes that find no key and
    create one together end up with the same key: the one that loses the race loads the winner's.
    """
    try:
        return _load_settled(path)
    except MasterKeyMissingError:
        if fingerprints_exist:
            raise MasterKeyMissingError(_MISSING_WITH_FINGERPRINTS.format(path=path)) from None
    try:
        return _create_key_file(path)
    except FileExistsError:
        # Another process created the key between our check and our create: use its key.
        return _load_settled(path)


def fingerprints_in_use(database: Database) -> bool:
    """True once the first secret fingerprint has been stored (setting fp_in_use)."""
    with database.read() as connection:
        value = connection.execute(
            sa.select(settings.c.value).where(
                settings.c.workspace_id == DEFAULT_WORKSPACE_ID,
                settings.c.key == FP_IN_USE_SETTING,
            )
        ).scalar_one_or_none()
    return value == FP_IN_USE_VALUE


def mark_fingerprints_in_use_in(connection: sa.Connection) -> None:
    """Record that a fingerprint exists, inside the caller's transaction.

    Call it in the transaction that stores the first fingerprint (before the insert), so the
    flag and the fingerprint commit together or not at all. Storing a state does this itself.
    """
    connection.execute(
        sqlite_insert(settings)
        .values(
            workspace_id=DEFAULT_WORKSPACE_ID,
            key=FP_IN_USE_SETTING,
            value=FP_IN_USE_VALUE,
        )
        .on_conflict_do_nothing()
    )


def mark_fingerprints_in_use(database: Database) -> None:
    """Record that a fingerprint exists, in a transaction of its own."""
    with database.write() as connection:
        mark_fingerprints_in_use_in(connection)


def master_key_or_exit(path: Path, database: Database) -> MasterKey:
    """Startup entry point: return the master key or stop the process with an exit code.

    Exit code 4 when fingerprints exist but the key file is missing; exit code 1 when the key
    file cannot be used (unreadable, wrong size or mode, a link) or cannot be created.
    """
    try:
        return ensure_master_key(path, fingerprints_exist=fingerprints_in_use(database))
    except MasterKeyMissingError as error:
        print(f"driftsniff: {error}", file=sys.stderr)
        raise SystemExit(EXIT_KEY_MISSING) from None
    except MasterKeyInvalidError as error:
        print(f"driftsniff: {error}", file=sys.stderr)
        raise SystemExit(EXIT_KEY_UNUSABLE) from None
    except OSError as error:
        message = f"driftsniff: cannot create master key file {path}: {error.strerror}"
        print(message, file=sys.stderr)
        raise SystemExit(EXIT_KEY_UNUSABLE) from None

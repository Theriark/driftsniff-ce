"""Source credential encryption: AES-256-GCM with the credential key.

The stored value is the base64 text of

    version byte 1 | 12 random nonce bytes | ciphertext followed by the 16 byte GCM tag

The associated data binds the value to the source it belongs to and to the key that made it:
``driftsniff-credential-v1/source/<source id>/key/<key id>``. A value copied to another source,
or whose ``key_id`` column was edited, therefore fails to decrypt. The key id is also stored in
the ``key_id`` column of the source so a rekey can tell which values still need re-encrypting.

Nothing in this module puts a key, a credential or decrypted text into an error message.
"""

import base64
import binascii
import os
from dataclasses import dataclass
from typing import Self

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from driftsniff.secrets.keys import CREDENTIAL_LABEL, KEY_BYTES, MasterKey

VERSION_BYTE = 1
NONCE_BYTES = 12
TAG_BYTES = 16
MAX_CREDENTIAL_BYTES = 64 * 1024
_KEY_ID_CHARS = 8


class CredentialCryptoError(Exception):
    """Base class for credential encryption problems; messages never contain secret text."""


class CredentialDecryptError(CredentialCryptoError):
    """A stored credential cannot be decrypted: wrong key, wrong source, or damaged data."""


@dataclass(frozen=True, slots=True)
class EncryptedCredential:
    """What goes into the ``credential_ciphertext`` and ``key_id`` columns of a source."""

    ciphertext: str
    key_id: str


def associated_data(source_id: int, key_id: str) -> bytes:
    """The authenticated, unencrypted context of a stored credential."""
    return f"driftsniff-credential-v1/source/{source_id}/key/{key_id}".encode("ascii")


def channel_associated_data(channel_id: int, key_id: str) -> bytes:
    """The same for the configuration of a notification channel (P9-T4).

    A different text from ``associated_data``, so a source credential can never be opened as a
    channel configuration, or the other way round, even when both have the same id.
    """
    return f"driftsniff-channel-v1/channel/{channel_id}/key/{key_id}".encode("ascii")


class CredentialCipher:
    """Encrypts and decrypts source credentials with one credential key.

    The repr shows only the key id.
    """

    __slots__ = ("_aead", "key_id")

    def __init__(self, key: bytes, key_id: str) -> None:
        if len(key) != KEY_BYTES:
            raise ValueError(f"a credential key must hold exactly {KEY_BYTES} bytes")
        if len(key_id) != _KEY_ID_CHARS:
            raise ValueError("a key id is 8 hex characters")
        self._aead = AESGCM(key)
        self.key_id = key_id

    @classmethod
    def from_master(cls, master: MasterKey) -> Self:
        """Use the credential key derived from ``master``."""
        return cls(master.derive(CREDENTIAL_LABEL), master.key_id)

    def encrypt(self, source_id: int, plaintext: bytes) -> EncryptedCredential:
        """Encrypt a credential of a source; a fresh random nonce is used every time."""
        return self._seal(plaintext, associated_data(source_id, self.key_id))

    def decrypt(self, source_id: int, ciphertext: str, key_id: str) -> bytes:
        """Decrypt the stored value of a source.

        ``key_id`` is the id stored next to the value. A value made with another key is refused
        before any decryption is tried; a wrong key, a value of another source, an edited
        ``key_id`` and damaged data all fail with CredentialDecryptError.
        """
        return self._open(ciphertext, key_id, associated_data(source_id, key_id))

    def encrypt_channel(self, channel_id: int, plaintext: bytes) -> EncryptedCredential:
        """Encrypt the configuration of a notification channel (bound to the channel id)."""
        return self._seal(plaintext, channel_associated_data(channel_id, self.key_id))

    def decrypt_channel(self, channel_id: int, ciphertext: str, key_id: str) -> bytes:
        """Decrypt the stored configuration of a channel; the failures are those of ``decrypt``."""
        return self._open(ciphertext, key_id, channel_associated_data(channel_id, key_id))

    def _seal(self, plaintext: bytes, context: bytes) -> EncryptedCredential:
        if len(plaintext) > MAX_CREDENTIAL_BYTES:
            raise CredentialCryptoError(f"a credential is larger than {MAX_CREDENTIAL_BYTES} bytes")
        nonce = os.urandom(NONCE_BYTES)
        sealed = self._aead.encrypt(nonce, plaintext, context)
        packed = bytes([VERSION_BYTE]) + nonce + sealed
        return EncryptedCredential(base64.b64encode(packed).decode("ascii"), self.key_id)

    def _open(self, ciphertext: str, key_id: str, context: bytes) -> bytes:
        if key_id != self.key_id:
            raise CredentialDecryptError(
                f"the credential was encrypted with key {key_id}, but key {self.key_id} is loaded"
            )
        try:
            packed = base64.b64decode(ciphertext, validate=True)
        except (binascii.Error, ValueError):
            raise CredentialDecryptError("the stored credential is not valid base64") from None
        if len(packed) < 1 + NONCE_BYTES + TAG_BYTES:
            raise CredentialDecryptError("the stored credential is too short")
        if packed[0] != VERSION_BYTE:
            raise CredentialDecryptError(f"unknown credential format version {packed[0]}")
        nonce = packed[1 : 1 + NONCE_BYTES]
        sealed = packed[1 + NONCE_BYTES :]
        try:
            return self._aead.decrypt(nonce, sealed, context)
        except InvalidTag:
            raise CredentialDecryptError(
                "the stored credential cannot be decrypted: wrong key or damaged data"
            ) from None

    def __repr__(self) -> str:
        return f"CredentialCipher(key_id={self.key_id!r})"

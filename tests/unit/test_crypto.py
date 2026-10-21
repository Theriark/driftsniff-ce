"""Credential encryption: format, associated data, fresh nonces and clean failures."""

import base64

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from driftsniff.secrets.crypto import (
    MAX_CREDENTIAL_BYTES,
    NONCE_BYTES,
    CredentialCipher,
    CredentialCryptoError,
    CredentialDecryptError,
    associated_data,
)
from driftsniff.secrets.keys import KEY_BYTES, MasterKey

MATERIAL = bytes(range(KEY_BYTES))
OTHER_MATERIAL = bytes(reversed(range(KEY_BYTES)))
CANARY = b"CANARY-credential-0001"
MASTER = MasterKey(MATERIAL)
OTHER_MASTER = MasterKey(OTHER_MATERIAL)


def cipher() -> CredentialCipher:
    return CredentialCipher.from_master(MASTER)


def credential_key(material: bytes) -> bytes:
    """The credential key computed with the cryptography library directly."""
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"driftsniff/credential/v1")
    return hkdf.derive(material)


def test_a_credential_decrypts_to_the_original() -> None:
    sealed = cipher().encrypt(7, CANARY)
    assert cipher().decrypt(7, sealed.ciphertext, sealed.key_id) == CANARY


def test_the_stored_key_id_is_the_master_key_id() -> None:
    assert cipher().encrypt(7, CANARY).key_id == MASTER.key_id


def test_the_stored_value_has_the_documented_layout() -> None:
    sealed = cipher().encrypt(7, CANARY)
    packed = base64.b64decode(sealed.ciphertext, validate=True)
    assert packed[0] == 1
    nonce = packed[1 : 1 + NONCE_BYTES]
    assert len(packed) == 1 + NONCE_BYTES + len(CANARY) + 16
    aead = AESGCM(credential_key(MATERIAL))
    plain = aead.decrypt(nonce, packed[1 + NONCE_BYTES :], associated_data(7, MASTER.key_id))
    assert plain == CANARY


def test_the_associated_data_is_the_source_id_and_the_key_id() -> None:
    assert associated_data(7, "0a1b2c3d") == b"driftsniff-credential-v1/source/7/key/0a1b2c3d"


def test_every_encryption_uses_a_fresh_nonce() -> None:
    first = cipher().encrypt(7, CANARY)
    second = cipher().encrypt(7, CANARY)
    assert first.ciphertext != second.ciphertext


def test_the_plaintext_does_not_appear_in_the_stored_value() -> None:
    sealed = cipher().encrypt(7, CANARY)
    assert CANARY not in sealed.ciphertext.encode()
    assert CANARY not in base64.b64decode(sealed.ciphertext)


def test_an_empty_credential_round_trips() -> None:
    sealed = cipher().encrypt(7, b"")
    assert cipher().decrypt(7, sealed.ciphertext, sealed.key_id) == b""


def test_a_credential_that_is_too_large_is_refused() -> None:
    with pytest.raises(CredentialCryptoError, match="larger than"):
        cipher().encrypt(7, b"x" * (MAX_CREDENTIAL_BYTES + 1))


def test_the_largest_allowed_credential_round_trips() -> None:
    body = b"x" * MAX_CREDENTIAL_BYTES
    sealed = cipher().encrypt(7, body)
    assert cipher().decrypt(7, sealed.ciphertext, sealed.key_id) == body


def test_a_wrong_key_id_fails_cleanly_before_any_decryption() -> None:
    sealed = cipher().encrypt(7, CANARY)
    other = CredentialCipher.from_master(OTHER_MASTER)
    with pytest.raises(CredentialDecryptError, match="encrypted with key") as raised:
        other.decrypt(7, sealed.ciphertext, sealed.key_id)
    assert CANARY.decode() not in str(raised.value)


def test_a_wrong_key_with_the_right_key_id_fails_cleanly() -> None:
    sealed = cipher().encrypt(7, CANARY)
    impostor = CredentialCipher(credential_key(OTHER_MATERIAL), MASTER.key_id)
    with pytest.raises(CredentialDecryptError, match="wrong key or damaged data"):
        impostor.decrypt(7, sealed.ciphertext, sealed.key_id)


def test_a_credential_moved_to_another_source_fails() -> None:
    sealed = cipher().encrypt(7, CANARY)
    with pytest.raises(CredentialDecryptError, match="wrong key or damaged data"):
        cipher().decrypt(8, sealed.ciphertext, sealed.key_id)


def test_a_flipped_bit_fails() -> None:
    sealed = cipher().encrypt(7, CANARY)
    packed = bytearray(base64.b64decode(sealed.ciphertext))
    packed[-1] ^= 1
    damaged = base64.b64encode(bytes(packed)).decode("ascii")
    with pytest.raises(CredentialDecryptError, match="wrong key or damaged data"):
        cipher().decrypt(7, damaged, sealed.key_id)


def test_text_that_is_not_base64_fails() -> None:
    with pytest.raises(CredentialDecryptError, match="not valid base64"):
        cipher().decrypt(7, "not base64 at all!", MASTER.key_id)


def test_text_with_non_ascii_characters_fails() -> None:
    with pytest.raises(CredentialDecryptError, match="not valid base64"):
        cipher().decrypt(7, "café", MASTER.key_id)


def test_a_value_that_is_too_short_fails() -> None:
    short = base64.b64encode(b"\x01" + b"\x00" * 20).decode("ascii")
    with pytest.raises(CredentialDecryptError, match="too short"):
        cipher().decrypt(7, short, MASTER.key_id)


def test_an_unknown_format_version_fails() -> None:
    sealed = cipher().encrypt(7, CANARY)
    packed = bytearray(base64.b64decode(sealed.ciphertext))
    packed[0] = 2
    changed = base64.b64encode(bytes(packed)).decode("ascii")
    with pytest.raises(CredentialDecryptError, match="version 2"):
        cipher().decrypt(7, changed, sealed.key_id)


def test_a_key_of_the_wrong_size_is_refused() -> None:
    with pytest.raises(ValueError, match="exactly 32 bytes"):
        CredentialCipher(b"short", "0a1b2c3d")


def test_a_key_id_of_the_wrong_length_is_refused() -> None:
    with pytest.raises(ValueError, match="8 hex characters"):
        CredentialCipher(credential_key(MATERIAL), "abc")


def test_the_repr_shows_only_the_key_id() -> None:
    shown = repr(cipher())
    assert MASTER.key_id in shown
    assert credential_key(MATERIAL).hex() not in shown

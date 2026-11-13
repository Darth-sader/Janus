"""Key model + dev/test storage: redaction, round trips, encryption."""

from __future__ import annotations

import json

import pytest

from crypto import DevKeyStore, InvalidKeyError, MLDSAProvider, PrivateKey, PublicKey, SerializationError


# --------------------------------------------------------------------- #
# key model hygiene
# --------------------------------------------------------------------- #
def test_private_key_never_renders_material():
    sk = PrivateKey("mldsa65", b"\xde\xad\xbe\xef" * 8)
    for text in (repr(sk), str(sk)):
        assert "redacted" in text
        assert "deadbeef" not in text
        assert b"\xde\xad\xbe\xef" not in text.encode()


def test_public_key_renders_fingerprint_only():
    pk = PublicKey("rsa4096", b"\x01" * 550)
    text = repr(pk)
    assert "fingerprint" in text and pk.data.hex() not in text


def test_keys_are_immutable():
    pk = PublicKey("mldsa65", b"\x01" * 16)
    with pytest.raises(Exception):
        pk.data = b"\x02" * 16  # type: ignore[misc]


def test_keypair_requires_matching_algorithms():
    from crypto.keys import KeyPair

    with pytest.raises(ValueError):
        KeyPair("mldsa65", PrivateKey("rsa4096", b"x"), PublicKey("mldsa65", b"y"))


def test_keys_reject_empty_material():
    with pytest.raises(ValueError):
        PublicKey("mldsa65", b"")
    with pytest.raises(ValueError):
        PrivateKey("mldsa65", b"")
    with pytest.raises(ValueError):
        PublicKey("", b"x")


# --------------------------------------------------------------------- #
# dev/test storage
# --------------------------------------------------------------------- #
@pytest.fixture()
def store(tmp_path):
    return DevKeyStore(tmp_path / "keys")


def test_keypair_storage_round_trip(store, mldsa_provider):
    kp = mldsa_provider.generate_keypair()
    store.save_keypair("mldsa-primary", kp)
    restored = store.load_keypair("mldsa-primary")
    assert restored == kp


def test_rsa_keypair_storage_round_trip(store, rsa_provider):
    kp = rsa_provider.generate_keypair()
    store.save_keypair("ca-root", kp)
    restored = store.load_keypair("ca-root")
    assert restored == kp


def test_encrypted_private_key_round_trip(store, mldsa_provider):
    kp = mldsa_provider.generate_keypair()
    store.save_private_key("secret", kp.private_key, passphrase="correct horse battery staple")
    # file must not contain plaintext key material
    raw = json.loads((store._dir / "secret.key.json").read_text())
    assert raw["encrypted"] is True
    assert kp.private_key.data not in json.dumps(raw).encode()

    restored = store.load_private_key("secret", passphrase="correct horse battery staple")
    assert restored == kp.private_key


def test_wrong_passphrase_fails(store, mldsa_provider):
    kp = mldsa_provider.generate_keypair()
    store.save_private_key("secret2", kp.private_key, passphrase="right")
    with pytest.raises(SerializationError):
        store.load_private_key("secret2", passphrase="wrong")


def test_encrypted_key_requires_passphrase(store, mldsa_provider):
    kp = mldsa_provider.generate_keypair()
    store.save_private_key("secret3", kp.private_key, passphrase="pw")
    with pytest.raises(SerializationError):
        store.load_private_key("secret3")


def test_inconsistent_keypair_rejected(store, mldsa_provider, rsa_keypair):
    kp = mldsa_provider.generate_keypair()
    store.save_private_key("mixed", kp.private_key)
    store.save_public_key("mixed", rsa_keypair.public_key)
    with pytest.raises(InvalidKeyError):
        store.load_keypair("mixed")


def test_saved_files_exist_with_documented_names(store, mldsa_provider):
    kp = mldsa_provider.generate_keypair()
    key_path, pub_path = store.save_keypair("demo", kp)
    assert key_path.name == "demo.key.json"
    assert pub_path.name == "demo.pub.json"
    payload = json.loads(pub_path.read_text())
    assert payload["algorithm"] == "mldsa65"

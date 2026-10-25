"""RSA-4096 provider: success paths, rejection paths, serialization."""

from __future__ import annotations

import pytest

from crypto import (
    InvalidKeyError,
    MalformedSignatureError,
    PrivateKey,
    PublicKey,
    RSA4096Provider,
    SerializationError,
    SigningError,
)

pytestmark = pytest.mark.usefixtures("rsa_provider", "rsa_keypair")


# --------------------------------------------------------------------- #
# key generation
# --------------------------------------------------------------------- #
def test_generate_keypair_types(rsa_provider, rsa_keypair):
    assert rsa_keypair.algorithm == "rsa4096"
    assert isinstance(rsa_keypair.private_key, PrivateKey)
    assert isinstance(rsa_keypair.public_key, PublicKey)


def test_generate_keypair_is_usable(rsa_provider, rsa_keypair, message):
    sig = rsa_provider.sign(message, rsa_keypair.private_key)
    assert rsa_provider.verify(message, sig, rsa_keypair.public_key) is True


def test_keypair_algorithm_consistency(rsa_keypair):
    assert rsa_keypair.private_key.algorithm == rsa_keypair.public_key.algorithm == rsa_keypair.algorithm


# --------------------------------------------------------------------- #
# sign / verify success
# --------------------------------------------------------------------- #
def test_sign_produces_rsa4096_sized_signature(rsa_provider, rsa_keypair, message):
    sig = rsa_provider.sign(message, rsa_keypair.private_key)
    assert len(sig) == 512  # 4096-bit modulus


def test_verify_ok(rsa_provider, rsa_keypair, message):
    sig = rsa_provider.sign(message, rsa_keypair.private_key)
    assert rsa_provider.verify(message, sig, rsa_keypair.public_key)


def test_signing_is_not_strictly_deterministic_but_always_verifies(rsa_provider, rsa_keypair, message):
    # PSS uses a random salt: two signatures over the same message differ,
    # and both must verify.  This documents the scheme explicitly.
    s1 = rsa_provider.sign(message, rsa_keypair.private_key)
    s2 = rsa_provider.sign(message, rsa_keypair.private_key)
    assert rsa_provider.verify(message, s1, rsa_keypair.public_key)
    assert rsa_provider.verify(message, s2, rsa_keypair.public_key)


# --------------------------------------------------------------------- #
# rejection paths
# --------------------------------------------------------------------- #
def test_modified_message_fails(rsa_provider, rsa_keypair, message):
    sig = rsa_provider.sign(message, rsa_keypair.private_key)
    assert rsa_provider.verify(message + b" ", sig, rsa_keypair.public_key) is False


def test_signature_from_different_key_fails(rsa_provider, rsa_keypair, message):
    other = rsa_provider.generate_keypair()
    sig = rsa_provider.sign(message, other.private_key)
    assert rsa_provider.verify(message, sig, rsa_keypair.public_key) is False


def test_garbage_signature_returns_false(rsa_provider, rsa_keypair, message):
    assert rsa_provider.verify(message, b"\x00" * 512, rsa_keypair.public_key) is False


def test_empty_signature_returns_false(rsa_provider, rsa_keypair, message):
    assert rsa_provider.verify(message, b"", rsa_keypair.public_key) is False


def test_wrong_type_message_raises(rsa_provider, rsa_keypair):
    with pytest.raises(SigningError):
        rsa_provider.sign("not-bytes", rsa_keypair.private_key)  # type: ignore[arg-type]


# --------------------------------------------------------------------- #
# key validation
# --------------------------------------------------------------------- #
def test_wrong_size_private_key_rejected(rsa_provider, message):
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
    from cryptography.hazmat.primitives.serialization import (
        Encoding, NoEncryption, PrivateFormat,
    )
    small = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
    sk = PrivateKey("rsa4096", small.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption()))
    with pytest.raises(InvalidKeyError):
        rsa_provider.sign(message, sk)


def test_wrong_size_public_key_rejected(rsa_provider, rsa_keypair, message):
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    small = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pk = PublicKey("rsa4096", small.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo))
    with pytest.raises(InvalidKeyError):
        rsa_provider.verify(message, b"\x00" * 512, pk)


def test_malformed_private_key_rejected(rsa_provider, message):
    with pytest.raises(InvalidKeyError):
        rsa_provider.sign(message, PrivateKey("rsa4096", b"not-a-key"))


def test_malformed_public_key_rejected(rsa_provider, rsa_keypair, message):
    with pytest.raises(InvalidKeyError):
        rsa_provider.verify(message, b"\x00" * 512, PublicKey("rsa4096", b"not-a-key"))


def test_key_from_other_algorithm_rejected(rsa_provider, rsa_keypair, message, mldsa_keypair):
    with pytest.raises(InvalidKeyError):
        rsa_provider.sign(message, mldsa_keypair.private_key)
    with pytest.raises(InvalidKeyError):
        rsa_provider.verify(message, b"\x00" * 512, mldsa_keypair.public_key)


def test_raw_key_objects_rejected(rsa_provider, rsa_keypair, message):
    with pytest.raises(InvalidKeyError):
        rsa_provider.sign(message, rsa_keypair.private_key.data)  # type: ignore[arg-type]


# --------------------------------------------------------------------- #
# serialization round trips
# --------------------------------------------------------------------- #
def test_public_key_round_trip(rsa_provider, rsa_keypair):
    wire = rsa_provider.serialize_public_key(rsa_keypair.public_key)
    assert isinstance(wire, bytes) and wire
    restored = rsa_provider.deserialize_public_key(wire)
    assert restored == rsa_keypair.public_key
    assert rsa_provider.serialize_public_key(restored) == wire  # deterministic


def test_signature_round_trip(rsa_provider, rsa_keypair, message):
    sig = rsa_provider.sign(message, rsa_keypair.public_key and rsa_keypair.private_key)
    wire = rsa_provider.serialize_signature(sig)
    assert rsa_provider.deserialize_signature(wire) == sig


def test_deserialize_public_key_rejects_garbage(rsa_provider):
    with pytest.raises(SerializationError):
        rsa_provider.deserialize_public_key(b"junk")


def test_deserialize_public_key_rejects_wrong_size(rsa_provider, rsa_keypair):
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    small = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(InvalidKeyError):
        rsa_provider.deserialize_public_key(
            small.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        )


def test_serialize_signature_rejects_empty(rsa_provider):
    with pytest.raises(MalformedSignatureError):
        rsa_provider.serialize_signature(b"")


# --------------------------------------------------------------------- #
# security hygiene
# --------------------------------------------------------------------- #
def test_private_key_repr_is_redacted(rsa_keypair):
    text = repr(rsa_keypair.private_key) + str(rsa_keypair.private_key)
    assert "redacted" in text
    assert rsa_keypair.private_key.data.hex() not in text


def test_errors_do_not_leak_key_material(rsa_provider, message):
    sk = PrivateKey("rsa4096", b"\x01" * 16)
    try:
        rsa_provider.sign(message, sk)
    except InvalidKeyError as exc:
        assert b"\x01" * 16 not in str(exc).encode()
        assert sk.data.hex() not in str(exc)


def test_provider_is_a_crypto_provider(rsa_provider):
    from crypto_agility.interfaces import CryptoProvider

    assert isinstance(rsa_provider, CryptoProvider)


def test_documented_scheme_is_explicit(rsa_provider):
    caps = rsa_provider.capabilities()
    assert "PSS" in caps.parameter_set and "SHA-256" in caps.parameter_set
    assert caps.quantum_vulnerable is True

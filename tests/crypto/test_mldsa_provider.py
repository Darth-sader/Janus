"""ML-DSA provider (FIPS 204): success paths, rejection paths,
parameter-set consistency, serialization."""

from __future__ import annotations

import pytest

from crypto import (
    InvalidKeyError,
    MLDSAProvider,
    MalformedSignatureError,
    PrivateKey,
    PublicKey,
    SerializationError,
    SigningError,
)

KNOWN_SETS = ["mldsa44", "mldsa65", "mldsa87"]


# --------------------------------------------------------------------- #
# parameter-set handling
# --------------------------------------------------------------------- #
@pytest.mark.parametrize("parameter_set", KNOWN_SETS)
def test_all_parameter_sets_round_trip(parameter_set, message):
    provider = MLDSAProvider(parameter_set)
    kp = provider.generate_keypair()
    sig = provider.sign(message, kp.private_key)
    assert provider.verify(message, sig, kp.public_key) is True
    assert provider.verify(message + b"!", sig, kp.public_key) is False


def test_unknown_parameter_set_rejected():
    with pytest.raises(InvalidKeyError):
        MLDSAProvider("mldsa99")


def test_parameter_set_recorded_in_capabilities():
    caps = MLDSAProvider("mldsa65").capabilities()
    assert caps.parameter_set == "ML-DSA-65"
    assert caps.algorithm_id == "mldsa65"
    assert caps.standard == "FIPS 204 (ML-DSA)"
    assert caps.quantum_vulnerable is False
    assert caps.security_level == "NIST category 3"


def test_fips204_sizes(mldsa_provider):
    # FIPS 204 ML-DSA-65: pk 1952, sk 4032, sig 3309
    assert mldsa_provider.public_key_size() == 1952
    assert mldsa_provider.secret_key_size() == 4032
    assert mldsa_provider.signature_size() == 3309


# --------------------------------------------------------------------- #
# cross-parameter-set isolation
# --------------------------------------------------------------------- #
def test_key_from_other_parameter_set_rejected(message):
    p44, p65 = MLDSAProvider("mldsa44"), MLDSAProvider("mldsa65")
    kp44 = p44.generate_keypair()
    with pytest.raises(InvalidKeyError):
        p65.sign(message, kp44.private_key)
    with pytest.raises(InvalidKeyError):
        p65.verify(message, b"\x00" * 3309, kp44.public_key)


# --------------------------------------------------------------------- #
# sign / verify
# --------------------------------------------------------------------- #
def test_verify_ok(mldsa_provider, mldsa_keypair, message):
    sig = mldsa_provider.sign(message, mldsa_keypair.private_key)
    assert mldsa_provider.verify(message, sig, mldsa_keypair.public_key)


def test_modified_message_fails(mldsa_provider, mldsa_keypair, message):
    sig = mldsa_provider.sign(message, mldsa_keypair.private_key)
    assert mldsa_provider.verify(message + b" ", sig, mldsa_keypair.public_key) is False


def test_signature_from_different_key_fails(mldsa_provider, mldsa_keypair, message):
    other = mldsa_provider.generate_keypair()
    sig = mldsa_provider.sign(message, other.private_key)
    assert mldsa_provider.verify(message, sig, mldsa_keypair.public_key) is False


def test_truncated_signature_fails(mldsa_provider, mldsa_keypair, message):
    sig = mldsa_provider.sign(message, mldsa_keypair.private_key)
    assert mldsa_provider.verify(message, sig[:-1], mldsa_keypair.public_key) is False


def test_wrong_type_message_raises(mldsa_provider, mldsa_keypair):
    with pytest.raises(SigningError):
        mldsa_provider.sign("not-bytes", mldsa_keypair.private_key)  # type: ignore[arg-type]


def test_malformed_keys_rejected(mldsa_provider, message):
    with pytest.raises(InvalidKeyError):
        mldsa_provider.sign(message, PrivateKey("mldsa65", b"short"))
    with pytest.raises(InvalidKeyError):
        mldsa_provider.verify(message, b"x" * 3309, PublicKey("mldsa65", b"short"))


def test_raw_key_objects_rejected(mldsa_provider, mldsa_keypair, message):
    with pytest.raises(InvalidKeyError):
        mldsa_provider.sign(message, mldsa_keypair.private_key.data)  # type: ignore[arg-type]


# --------------------------------------------------------------------- #
# serialization
# --------------------------------------------------------------------- #
def test_public_key_round_trip(mldsa_provider, mldsa_keypair):
    wire = mldsa_provider.serialize_public_key(mldsa_keypair.public_key)
    restored = mldsa_provider.deserialize_public_key(wire)
    assert restored == mldsa_keypair.public_key
    assert mldsa_provider.serialize_public_key(restored) == wire


def test_signature_round_trip(mldsa_provider, mldsa_keypair, message):
    sig = mldsa_provider.sign(message, mldsa_keypair.private_key)
    assert mldsa_provider.deserialize_signature(mldsa_provider.serialize_signature(sig)) == sig


def test_deserialize_public_key_wrong_length(mldsa_provider):
    with pytest.raises(SerializationError):
        mldsa_provider.deserialize_public_key(b"x" * 100)


def test_serialize_signature_wrong_length(mldsa_provider):
    with pytest.raises(MalformedSignatureError):
        mldsa_provider.serialize_signature(b"x" * 100)


def test_same_interface_as_rsa(mldsa_provider, rsa_provider):
    # ML-DSA must be invocable through exactly the same interface as RSA.
    from crypto_agility.interfaces import CryptoProvider

    for provider in (mldsa_provider, rsa_provider):
        assert isinstance(provider, CryptoProvider)
        kp = provider.generate_keypair()
        sig = provider.sign(b"interface parity check", kp.private_key)
        assert provider.verify(b"interface parity check", sig, kp.public_key) is True
        assert provider.verify(b"other message", sig, kp.public_key) is False

"""SLH-DSA provider (FIPS 205) - the additional hash-based PQ candidate."""

from __future__ import annotations

import pytest

from crypto import (
    InvalidKeyError,
    SLHDSAProvider,
    MalformedSignatureError,
    SerializationError,
)

SET = "slhdsa-sha2-128s"


def test_fips205_sizes(slhdsa_provider):
    # FIPS 205 SLH-DSA-SHA2-128s: pk 32, sk 64, sig 7856
    assert slhdsa_provider.public_key_size() == 32
    assert slhdsa_provider.secret_key_size() == 64
    assert slhdsa_provider.signature_size() == 7856


def test_keygen_sign_verify(slhdsa_provider, slhdsa_keypair, message):
    sig = slhdsa_provider.sign(message, slhdsa_keypair.private_key)
    assert len(sig) == 7856
    assert slhdsa_provider.verify(message, sig, slhdsa_keypair.public_key) is True


def test_modified_message_fails(slhdsa_provider, slhdsa_keypair, message):
    sig = slhdsa_provider.sign(message, slhdsa_keypair.private_key)
    assert slhdsa_provider.verify(message + b" ", sig, slhdsa_keypair.public_key) is False


def test_wrong_key_signature_fails(slhdsa_provider, message):
    k1 = slhdsa_provider.generate_keypair()
    k2 = slhdsa_provider.generate_keypair()
    sig = slhdsa_provider.sign(message, k1.private_key)
    assert slhdsa_provider.verify(message, sig, k2.public_key) is False


def test_parameter_set_isolation(message):
    p = SLHDSAProvider(SET)
    kp = p.generate_keypair()
    other = SLHDSAProvider("slhdsa-shake-128s")
    with pytest.raises(InvalidKeyError):
        other.sign(message, kp.private_key)


def test_unknown_parameter_set_rejected():
    with pytest.raises(InvalidKeyError):
        SLHDSAProvider("slhdsa-lamport-1")


def test_serialization_round_trips(slhdsa_provider, slhdsa_keypair, message):
    wire_pk = slhdsa_provider.serialize_public_key(slhdsa_keypair.public_key)
    assert slhdsa_provider.deserialize_public_key(wire_pk) == slhdsa_keypair.public_key
    sig = slhdsa_provider.sign(message, slhdsa_keypair.private_key)
    assert slhdsa_provider.deserialize_signature(slhdsa_provider.serialize_signature(sig)) == sig
    with pytest.raises(SerializationError):
        slhdsa_provider.deserialize_public_key(b"x" * 31)
    with pytest.raises(MalformedSignatureError):
        slhdsa_provider.serialize_signature(b"x" * 7855)


def test_registered_as_secondary_pq_family(slhdsa_provider):
    caps = slhdsa_provider.capabilities()
    assert caps.family == "pq"
    assert caps.standard == "FIPS 205 (SLH-DSA)"
    assert caps.quantum_vulnerable is False

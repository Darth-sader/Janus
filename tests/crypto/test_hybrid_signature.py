"""Phase 2 acceptance matrix: hybrid signing, verification policy,
serialization, and every rejection case from the specification."""

from __future__ import annotations

import base64
import json

import pytest

from crypto import MLDSAProvider, RSA4096Provider, SigningError
from crypto.hybrid import (
    HYBRID_ALGORITHM_ID,
    HybridAcceptancePolicy,
    HybridCryptoProvider,
    HybridSignature,
    HybridSigner,
    HybridVerifier,
)
from crypto.verification import VerificationStatus

from crypto.errors import MalformedSignatureError


@pytest.fixture(scope="module")
def hybrid_env():
    rsa, mldsa = RSA4096Provider(), MLDSAProvider("mldsa65")
    return {
        "rsa": rsa,
        "mldsa": mldsa,
        "keys_a": (rsa.generate_keypair(), mldsa.generate_keypair()),
        "keys_b": (rsa.generate_keypair(), mldsa.generate_keypair()),
    }


@pytest.fixture(scope="module")
def signer(hybrid_env):
    return HybridSigner(hybrid_env["rsa"], hybrid_env["mldsa"])


@pytest.fixture(scope="module")
def verifier(hybrid_env):
    return HybridVerifier(hybrid_env["rsa"], hybrid_env["mldsa"])


@pytest.fixture(scope="module")
def good_signature(hybrid_env, signer, message):
    (rkp, mkp) = hybrid_env["keys_a"]
    return signer.sign(message, rkp.private_key, mkp.private_key)


def good_keys(hybrid_env):
    rkp, mkp = hybrid_env["keys_a"]
    return rkp.public_key, mkp.public_key


def statuses(result):
    return {c.component: c.status for c in result.components}


# --------------------------------------------------------------------- #
# 1. valid message + valid component signatures
# --------------------------------------------------------------------- #
def test_valid_signature_accepted(verifier, good_signature, hybrid_env, message):
    rpk, mpk = good_keys(hybrid_env)
    result = verifier.verify(message, good_signature, rpk, mpk)
    assert result.accepted is True
    st = statuses(result)
    assert st["rsa_signature"] is VerificationStatus.VERIFIED
    assert st["mldsa_signature"] is VerificationStatus.VERIFIED


def test_both_components_sign_the_same_message(hybrid_env, signer, message):
    # the defining property of the parallel/composite construction
    rkp, mkp = hybrid_env["keys_a"]
    rsa, mldsa = hybrid_env["rsa"], hybrid_env["mldsa"]
    hybrid = signer.sign(message, rkp.private_key, mkp.private_key)
    assert rsa.verify(message, hybrid.rsa_signature, rkp.public_key)
    assert mldsa.verify(message, hybrid.mldsa_signature, mkp.public_key)


def test_algorithm_identifier_matches_components(good_signature):
    assert good_signature.algorithm == HYBRID_ALGORITHM_ID == "RSA4096-MLDSA"


# --------------------------------------------------------------------- #
# 2. modified message
# --------------------------------------------------------------------- #
def test_modified_message_rejected(verifier, good_signature, hybrid_env, message):
    rpk, mpk = good_keys(hybrid_env)
    result = verifier.verify(b"tampered: " + message, good_signature, rpk, mpk)
    assert result.accepted is False
    st = statuses(result)
    assert st["rsa_signature"] is VerificationStatus.INVALID
    assert st["mldsa_signature"] is VerificationStatus.INVALID


# --------------------------------------------------------------------- #
# 3./4. one invalid component is enough to reject (strict policy)
# --------------------------------------------------------------------- #
def test_invalid_rsa_component_rejected(verifier, good_signature, hybrid_env, message):
    rpk, mpk = good_keys(hybrid_env)
    forged = HybridSignature(
        algorithm=good_signature.algorithm,
        rsa_signature=b"\x00" * 512,                      # invalid RSA component
        mldsa_signature=good_signature.mldsa_signature,   # valid PQ component
    )
    result = verifier.verify(message, forged, rpk, mpk)
    assert result.accepted is False
    st = statuses(result)
    assert st["rsa_signature"] is VerificationStatus.INVALID
    assert st["mldsa_signature"] is VerificationStatus.VERIFIED


def test_invalid_mldsa_component_rejected(verifier, good_signature, hybrid_env, message):
    rpk, mpk = good_keys(hybrid_env)
    forged = HybridSignature(
        algorithm=good_signature.algorithm,
        rsa_signature=good_signature.rsa_signature,       # valid classical
        mldsa_signature=good_signature.mldsa_signature[:-1] + bytes([good_signature.mldsa_signature[-1] ^ 1]),
    )
    result = verifier.verify(message, forged, rpk, mpk)
    assert result.accepted is False
    st = statuses(result)
    assert st["mldsa_signature"] is VerificationStatus.INVALID
    assert st["rsa_signature"] is VerificationStatus.VERIFIED


# --------------------------------------------------------------------- #
# 5. missing components
# --------------------------------------------------------------------- #
def test_missing_mldsa_component_rejected(verifier, good_signature, hybrid_env, message):
    rpk, mpk = good_keys(hybrid_env)
    partial = HybridSignature(good_signature.algorithm, rsa_signature=good_signature.rsa_signature)
    result = verifier.verify(message, partial, rpk, mpk)
    assert result.accepted is False
    assert statuses(result)["mldsa_signature"] is VerificationStatus.MISSING


def test_missing_rsa_component_rejected(verifier, good_signature, hybrid_env, message):
    rpk, mpk = good_keys(hybrid_env)
    partial = HybridSignature(good_signature.algorithm, mldsa_signature=good_signature.mldsa_signature)
    result = verifier.verify(message, partial, rpk, mpk)
    assert result.accepted is False
    assert statuses(result)["rsa_signature"] is VerificationStatus.MISSING


def test_empty_signature_rejected(verifier, hybrid_env, message):
    rpk, mpk = good_keys(hybrid_env)
    result = verifier.verify(message, HybridSignature(), rpk, mpk)
    assert result.accepted is False
    st = statuses(result)
    assert st["rsa_signature"] is VerificationStatus.MISSING
    assert st["mldsa_signature"] is VerificationStatus.MISSING


# --------------------------------------------------------------------- #
# 6. wrong public keys
# --------------------------------------------------------------------- #
def test_wrong_rsa_public_key_rejected(verifier, good_signature, hybrid_env, message):
    _rkp, mkp = hybrid_env["keys_a"]
    wrong_rpk, _ = hybrid_env["keys_b"]
    result = verifier.verify(message, good_signature, wrong_rpk.public_key, mkp.public_key)
    assert result.accepted is False
    st = statuses(result)
    assert st["rsa_signature"] is VerificationStatus.INVALID
    assert st["mldsa_signature"] is VerificationStatus.VERIFIED


def test_wrong_mldsa_public_key_rejected(verifier, good_signature, hybrid_env, message):
    rkp, _ = hybrid_env["keys_a"]
    _, wrong_mkp = hybrid_env["keys_b"]
    result = verifier.verify(message, good_signature, rkp.public_key, wrong_mkp.public_key)
    assert result.accepted is False


def test_keys_from_entirely_other_algorithm_rejected(verifier, good_signature, hybrid_env, message, mldsa_keypair):
    rpk, mpk = good_keys(hybrid_env)
    result = verifier.verify(message, good_signature, mldsa_keypair.public_key, mpk)
    assert result.accepted is False
    assert statuses(result)["rsa_signature"] is VerificationStatus.KEY_MISMATCH


# --------------------------------------------------------------------- #
# 7. corrupted serialized hybrid object
# --------------------------------------------------------------------- #
def test_corrupted_bytes_rejected(verifier, hybrid_env, message):
    rpk, mpk = good_keys(hybrid_env)
    corrupt = bytearray(HybridSignature(rsa_signature=b"x" * 512, mldsa_signature=b"y" * 3309).to_json_bytes())
    corrupt[len(corrupt) // 2] ^= 0xFF
    result = verifier.verify(message, bytes(corrupt), rpk, mpk)
    assert result.accepted is False
    assert "malformed serialized hybrid signature" in result.reason


def test_non_json_bytes_rejected(verifier, hybrid_env, message):
    rpk, mpk = good_keys(hybrid_env)
    result = verifier.verify(message, b"\x00\x01not-json", rpk, mpk)
    assert result.accepted is False


def test_json_with_missing_fields_rejected(verifier, hybrid_env, message):
    rpk, mpk = good_keys(hybrid_env)
    payload = json.dumps({"algorithm": "RSA4096-MLDSA", "rsa_signature": "AAAA"}).encode()
    result = verifier.verify(message, payload, rpk, mpk)
    assert result.accepted is False


def test_bad_base64_component_rejected(verifier, hybrid_env, message):
    rpk, mpk = good_keys(hybrid_env)
    payload = json.dumps(
        {"algorithm": "RSA4096-MLDSA", "rsa_signature": "!!!not-base64!!!", "mldsa_signature": "AAAA"}
    ).encode()
    result = verifier.verify(message, payload, rpk, mpk)
    assert result.accepted is False


def test_empty_component_in_serialized_form_rejected(verifier, hybrid_env, message):
    rpk, mpk = good_keys(hybrid_env)
    payload = json.dumps(
        {"algorithm": "RSA4096-MLDSA", "rsa_signature": "", "mldsa_signature": base64.b64encode(b"y" * 10).decode()}
    ).encode()
    result = verifier.verify(message, payload, rpk, mpk)
    assert result.accepted is False


# --------------------------------------------------------------------- #
# 8. unsupported algorithm identifier
# --------------------------------------------------------------------- #
def test_unsupported_algorithm_identifier_rejected(verifier, hybrid_env, message):
    rpk, mpk = good_keys(hybrid_env)
    bogus = HybridSignature.__new__(HybridSignature)  # bypass constructor validation
    object.__setattr__(bogus, "algorithm", "RSA4096-DILITHIUM")
    object.__setattr__(bogus, "rsa_signature", b"x" * 512)
    object.__setattr__(bogus, "mldsa_signature", b"y" * 3309)
    result = verifier.verify(message, bogus, rpk, mpk)
    assert result.accepted is False
    st = statuses(result)
    assert st["rsa_signature"] is VerificationStatus.UNSUPPORTED_ALGORITHM
    assert st["mldsa_signature"] is VerificationStatus.UNSUPPORTED_ALGORITHM


def test_constructor_rejects_unsupported_algorithm_id():
    with pytest.raises(MalformedSignatureError):
        HybridSignature(algorithm="DSA-ML", rsa_signature=b"x", mldsa_signature=b"y")


# --------------------------------------------------------------------- #
# 9. serialization round trip
# --------------------------------------------------------------------- #
def test_json_round_trip(good_signature):
    wire = good_signature.to_json_bytes()
    assert HybridSignature.from_json_bytes(wire) == good_signature
    # determinism: same object -> same bytes
    assert good_signature.to_json_bytes() == wire


def test_serialized_form_matches_spec_representation(good_signature):
    obj = json.loads(good_signature.to_json_bytes())
    assert set(obj) == {"algorithm", "rsa_signature", "mldsa_signature"}
    assert obj["algorithm"] == "RSA4096-MLDSA"
    base64.b64decode(obj["rsa_signature"], validate=True)
    base64.b64decode(obj["mldsa_signature"], validate=True)


# --------------------------------------------------------------------- #
# 10. failure of one signing operation -> no partial result
# --------------------------------------------------------------------- #
class _ExplodingProvider(MLDSAProvider):
    """Simulates a PQ backend failure mid-signing."""

    def sign(self, message, private_key, context=None):
        raise SigningError("simulated ML-DSA backend failure")


def test_partial_signing_failure_returns_no_signature(hybrid_env, message):
    rsa, mldsa = hybrid_env["rsa"], hybrid_env["mldsa"]
    rkp, mkp = hybrid_env["keys_a"]
    broken_signer = HybridSigner(rsa, _ExplodingProvider("mldsa65"))
    with pytest.raises(SigningError):
        broken_signer.sign(message, rkp.private_key, mkp.private_key)


def test_signer_refuses_mismatched_keys(hybrid_env, message):
    rsa, mldsa = hybrid_env["rsa"], hybrid_env["mldsa"]
    rkp, mkp = hybrid_env["keys_a"]
    signer = HybridSigner(rsa, mldsa)
    with pytest.raises(SigningError):
        signer.sign(message, mkp.private_key, mkp.private_key)  # RSA slot given an ML-DSA key
    with pytest.raises(SigningError):
        signer.sign(message, rkp.private_key, rkp.private_key)  # PQ slot given an RSA key


def test_signer_validates_provider_families(mldsa_provider, rsa_provider, rsa_keypair):
    with pytest.raises(SigningError):
        HybridSigner(mldsa_provider, rsa_provider)  # wrong way round


# --------------------------------------------------------------------- #
# policy is explicit and strict
# --------------------------------------------------------------------- #
def test_policy_is_strict_two_component(verifier):
    assert verifier.policy is HybridAcceptancePolicy.STRICT_TWO_COMPONENT
    assert verifier.policy.value == "strict-two-component"


# --------------------------------------------------------------------- #
# hybrid through the generic provider interface (crypto-agility path)
# --------------------------------------------------------------------- #
def test_hybrid_provider_generic_interface(hybrid_env, message):
    rsa, mldsa = hybrid_env["rsa"], hybrid_env["mldsa"]
    provider = HybridCryptoProvider(rsa, mldsa)
    kp = provider.generate_keypair()
    sig = provider.sign(message, kp.private_key)
    assert provider.verify(message, sig, kp.public_key) is True
    assert provider.verify(message + b"!", sig, kp.public_key) is False

    # detailed diagnostics still available
    detailed = provider.verify_detailed(message + b"!", sig, kp.public_key)
    assert detailed.accepted is False

    # key/signature serialization round trips
    assert provider.deserialize_public_key(provider.serialize_public_key(kp.public_key)) == kp.public_key
    assert provider.deserialize_signature(provider.serialize_signature(sig)) == sig


def test_hybrid_provider_key_is_composite(hybrid_env, message):
    rsa, mldsa = hybrid_env["rsa"], hybrid_env["mldsa"]
    provider = HybridCryptoProvider(rsa, mldsa)
    kp = provider.generate_keypair()
    obj = json.loads(kp.public_key.data)
    assert set(obj) == {"rsa", "mldsa"}

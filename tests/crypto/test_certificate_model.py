"""Phase 3: conceptual hybrid certificate model + the certificate-to-crypto
contract used by the PKI layer."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from crypto import MLDSAProvider, RSA4096Provider
from crypto.certificates import (
    CERTIFICATE_PROFILE,
    CertificateSigningService,
    CertificateValidationRequest,
    CertificateVerificationService,
    HybridCertificateModel,
)
from crypto.errors import SigningError
from crypto.hybrid import HybridSigner, HybridVerifier
from crypto.verification import VerificationStatus


VALIDITY = timedelta(days=365)


def make_certificate(serial=42, rpk=None, mpk=None, **overrides):
    now = datetime.now(timezone.utc)
    fields = dict(
        subject=f"CN=SUBSTATION-{serial:03d}",
        issuer="CN=Grid-Intermediate-CA",
        serial_number=serial,
        not_before=now,
        not_after=now + VALIDITY,
        classical_public_key=rpk,
        pq_public_key=mpk,
        extensions={"migrationStatus": b"HYBRID"},
    )
    fields.update(overrides)
    return HybridCertificateModel(**fields)


@pytest.fixture(scope="module")
def pki_env():
    rsa, mldsa = RSA4096Provider(), MLDSAProvider("mldsa65")
    ca = (rsa.generate_keypair(), mldsa.generate_keypair())
    subject = (rsa.generate_keypair(), mldsa.generate_keypair())
    other_ca = (rsa.generate_keypair(), mldsa.generate_keypair())
    return {
        "rsa": rsa,
        "mldsa": mldsa,
        "ca": ca,
        "subject": subject,
        "other_ca": other_ca,
        "signing": CertificateSigningService(HybridSigner(rsa, mldsa)),
        "verifying": CertificateVerificationService(HybridVerifier(rsa, mldsa)),
    }


@pytest.fixture(scope="module")
def issued_certificate(pki_env):
    (rkp, mkp) = pki_env["subject"]
    cert = make_certificate(serial=17, rpk=rkp.public_key, mpk=mkp.public_key)
    return pki_env["signing"].sign_certificate(cert, pki_env["ca"][0].private_key, pki_env["ca"][1].private_key)


# --------------------------------------------------------------------- #
# data model
# --------------------------------------------------------------------- #
def test_model_holds_both_components_and_signature_info(issued_certificate):
    cert = issued_certificate
    assert cert.classical_public_key.algorithm == "rsa4096"
    assert cert.pq_public_key.algorithm == "mldsa65"
    assert cert.signature_algorithm == "RSA4096-MLDSA"
    assert cert.signature is not None and cert.is_signed()


def test_model_validation_rules(mldsa_keypair, rsa_keypair):
    now = datetime.now(timezone.utc)
    with pytest.raises(Exception):
        make_certificate(serial=-1, rpk=rsa_keypair.public_key, mpk=mldsa_keypair.public_key)
    with pytest.raises(Exception):
        make_certificate(
            serial=1,
            rpk=rsa_keypair.public_key,
            mpk=mldsa_keypair.public_key,
            not_before=now,
            not_after=now,  # empty validity interval
        )
    with pytest.raises(Exception):
        make_certificate(serial=1, rpk=mldsa_keypair.public_key, mpk=mldsa_keypair.public_key)  # swapped keys
    with pytest.raises(Exception):
        make_certificate(serial=1, rpk=rsa_keypair.public_key, mpk=rsa_keypair.public_key)


def test_tbs_is_deterministic_and_signature_free(issued_certificate):
    tbs = issued_certificate.to_be_signed_bytes()
    obj = json.loads(tbs)
    assert "signature" not in obj
    assert obj["profile"] == CERTIFICATE_PROFILE
    assert issued_certificate.to_be_signed_bytes() == tbs


def test_any_field_change_changes_tbs(issued_certificate, mldsa_keypair):
    tbs = issued_certificate.to_be_signed_bytes()
    changed = replace(issued_certificate, serial_number=issued_certificate.serial_number + 1)
    assert changed.to_be_signed_bytes() != tbs
    changed_ext = replace(issued_certificate, extensions={"migrationStatus": b"PQ"})
    assert changed_ext.to_be_signed_bytes() != tbs


def test_dict_round_trip(issued_certificate):
    restored = HybridCertificateModel.from_dict(issued_certificate.to_dict())
    assert restored.to_be_signed_bytes() == issued_certificate.to_be_signed_bytes()
    assert restored.signature == issued_certificate.signature


# --------------------------------------------------------------------- #
# signing contract
# --------------------------------------------------------------------- #
def test_sign_certificate_populates_hybrid_signature(pki_env, issued_certificate):
    sig = issued_certificate.signature
    assert sig.algorithm == "RSA4096-MLDSA"
    assert sig.rsa_signature and sig.mldsa_signature


def test_refuses_to_double_sign(pki_env, issued_certificate):
    with pytest.raises(SigningError):
        pki_env["signing"].sign_certificate(
            issued_certificate, pki_env["ca"][0].private_key, pki_env["ca"][1].private_key
        )


def test_signature_algorithm_mismatch_detected(pki_env):
    (rkp, mkp) = pki_env["subject"]
    cert = make_certificate(serial=99, rpk=rkp.public_key, mpk=mkp.public_key, signature_algorithm="RSA4096-MLDSA")
    # tamper with the declared algorithm after construction
    object.__setattr__(cert, "signature_algorithm", "RSA3072-MLDSA")
    with pytest.raises(SigningError):
        pki_env["signing"].sign_certificate(cert, pki_env["ca"][0].private_key, pki_env["ca"][1].private_key)


# --------------------------------------------------------------------- #
# verification contract / flow
# --------------------------------------------------------------------- #
def test_certificate_signature_verifies(pki_env, issued_certificate):
    result = pki_env["verifying"].verify_certificate_signature(
        issued_certificate, pki_env["ca"][0].public_key, pki_env["ca"][1].public_key
    )
    assert result.accepted is True
    assert [c.status for c in result.components] == [VerificationStatus.VERIFIED, VerificationStatus.VERIFIED]


def test_certificate_tampering_detected(pki_env, issued_certificate):
    forged = replace(issued_certificate, subject="CN=SUBSTATION-999")
    result = pki_env["verifying"].verify_certificate_signature(
        forged, pki_env["ca"][0].public_key, pki_env["ca"][1].public_key
    )
    assert result.accepted is False


def test_wrong_issuer_keys_detected(pki_env, issued_certificate):
    result = pki_env["verifying"].verify_certificate_signature(
        issued_certificate, pki_env["other_ca"][0].public_key, pki_env["other_ca"][1].public_key
    )
    assert result.accepted is False


def test_unsigned_certificate_rejected(pki_env, issued_certificate):
    unsigned = replace(issued_certificate, signature=None)
    result = pki_env["verifying"].verify_certificate_signature(
        unsigned, pki_env["ca"][0].public_key, pki_env["ca"][1].public_key
    )
    assert result.accepted is False
    assert "no signature" in result.reason


def test_validation_request_handoff_object(pki_env, issued_certificate):
    outcome = pki_env["verifying"].verify_request(
        CertificateValidationRequest(
            certificate=issued_certificate,
            issuer_classical_public_key=pki_env["ca"][0].public_key,
            issuer_pq_public_key=pki_env["ca"][1].public_key,
        )
    )
    assert outcome.signature_accepted is True
    assert outcome.signature_algorithm == "RSA4096-MLDSA"


def test_extract_public_keys_contract(pki_env, issued_certificate):
    keys = pki_env["verifying"].extract_public_keys(issued_certificate)
    assert keys["classical"] == issued_certificate.classical_public_key
    assert keys["pq"] == issued_certificate.pq_public_key


# --------------------------------------------------------------------- #
# boundary: not an X.509 encoding
# --------------------------------------------------------------------- #
def test_profile_is_explicitly_not_x509():
    assert "NOT" in CERTIFICATE_PROFILE and "X.509" in CERTIFICATE_PROFILE

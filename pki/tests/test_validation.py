import json
from datetime import timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from pki.ca import create_intermediate_ca, create_root_ca
from pki.issuance import issue_certificate
from pki.models import CertMode, ValidationReason
from pki.trust import TrustStore
from pki.validation import ValidationPolicy, validate_certificate

R = ValidationReason


def _reasons(result):
    return [i.reason for i in result.issues]


def _tamper(cert, old: bytes, new: bytes):
    der = cert.public_bytes(serialization.Encoding.DER)
    assert old in der
    return x509.load_der_x509_certificate(der.replace(old, new, 1))


def test_valid_chain(leaf, intermediate_ca, trust_store):
    result = validate_certificate(leaf.certificate, trust_store, [intermediate_ca.certificate])
    assert result.valid
    assert result.reason is R.OK
    assert result.mode is CertMode.CLASSICAL
    assert len(result.chain) == 3
    assert "CN=app.example.test" in result.chain[0]
    assert "CN=Test Root CA" in result.chain[-1]


def test_result_is_json_serialisable(leaf, intermediate_ca, trust_store):
    result = validate_certificate(leaf.certificate, trust_store, [intermediate_ca.certificate])
    data = json.loads(json.dumps(result.to_dict()))
    assert data["valid"] is True and data["reason"] == "OK" and data["issues"] == []


def test_root_validates_on_its_own(root_ca, trust_store):
    assert validate_certificate(root_ca.certificate, trust_store).valid


def test_expired_certificate(leaf, intermediate_ca, trust_store):
    later = leaf.certificate.not_valid_after_utc + timedelta(days=1)
    result = validate_certificate(leaf.certificate, trust_store, [intermediate_ca.certificate], at_time=later)
    assert not result.valid
    assert result.reason is R.EXPIRED
    assert "app.example.test" in result.issues[0].subject


def test_not_yet_valid(leaf, intermediate_ca, trust_store):
    earlier = leaf.certificate.not_valid_before_utc - timedelta(days=1)
    result = validate_certificate(leaf.certificate, trust_store, [intermediate_ca.certificate], at_time=earlier)
    assert result.reason is R.NOT_YET_VALID


def test_tampered_signature(leaf, intermediate_ca, trust_store):
    sig = leaf.certificate.signature
    forged = _tamper(leaf.certificate, sig[-8:], bytes(b ^ 0xFF for b in sig[-8:]))
    result = validate_certificate(forged, trust_store, [intermediate_ca.certificate])
    assert result.reason is R.BAD_SIGNATURE


def test_tampered_content(leaf, intermediate_ca, trust_store):
    # Change the domain name: the signature no longer matches the content.
    forged = _tamper(leaf.certificate, b"www.example.test", b"www.evilcorp.xyz")
    result = validate_certificate(forged, trust_store, [intermediate_ca.certificate])
    assert result.reason is R.BAD_SIGNATURE


def test_missing_intermediate(leaf, trust_store):
    result = validate_certificate(leaf.certificate, trust_store)
    assert result.reason is R.BAD_CHAIN
    assert "not found" in result.issues[0].message


def test_untrusted_root(leaf, intermediate_ca, root_ca):
    result = validate_certificate(leaf.certificate, TrustStore(), [intermediate_ca.certificate, root_ca.certificate])
    assert _reasons(result) == [R.UNTRUSTED_ROOT]


def test_impostor_root_with_same_name(leaf, intermediate_ca, config):
    impostor = create_root_ca("Test Root CA", config)
    result = validate_certificate(leaf.certificate, TrustStore([impostor.certificate]), [intermediate_ca.certificate])
    assert result.reason is R.BAD_SIGNATURE


def test_leaf_cannot_act_as_ca(leaf, intermediate_ca, trust_store):
    # Sign a certificate with the leaf's key, pretending the leaf is a CA.
    from pki.ca import build_name
    from datetime import datetime, timezone
    from cryptography.hazmat.primitives import hashes
    now = datetime.now(timezone.utc)
    rogue = (
        x509.CertificateBuilder()
        .subject_name(build_name("rogue.example.test"))
        .issuer_name(leaf.certificate.subject)
        .public_key(leaf.private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + timedelta(days=30))
        .sign(leaf.private_key, hashes.SHA256())
    )
    result = validate_certificate(rogue, trust_store, [intermediate_ca.certificate, leaf.certificate])
    assert result.reason is R.BAD_CHAIN
    assert "not a CA" in result.issues[0].message


def test_path_length_exceeded(intermediate_ca, trust_store):
    # The intermediate has path_length=0, so it may not sign another CA.
    sub_ca = create_intermediate_ca(intermediate_ca, "Sub CA")
    sub_leaf = issue_certificate(sub_ca, "deep.example.test")
    result = validate_certificate(sub_leaf.certificate, trust_store, [sub_ca.certificate, intermediate_ca.certificate])
    assert R.BAD_CHAIN in _reasons(result)
    assert any("path length" in i.message for i in result.issues)


def test_reports_every_problem(leaf, intermediate_ca, root_ca):
    later = leaf.certificate.not_valid_after_utc + timedelta(days=1)
    result = validate_certificate(leaf.certificate, TrustStore(), [intermediate_ca.certificate, root_ca.certificate],
                                  at_time=later)
    assert _reasons(result)[:2] == [R.UNTRUSTED_ROOT, R.EXPIRED]


def test_trust_store_only_accepts_roots(intermediate_ca, leaf):
    with pytest.raises(ValueError):
        TrustStore([intermediate_ca.certificate])
    with pytest.raises(ValueError):
        TrustStore([leaf.certificate])


def test_trust_store_add_and_remove(root_ca):
    store = TrustStore()
    store.add(root_ca.certificate)
    assert store.is_trusted(root_ca.certificate) and len(store) == 1
    store.remove(root_ca.certificate)
    assert not store.is_trusted(root_ca.certificate)


def test_require_revocation_check_without_crl(leaf, intermediate_ca, trust_store):
    result = validate_certificate(leaf.certificate, trust_store, [intermediate_ca.certificate],
                                  policy=ValidationPolicy(require_revocation_check=True))
    assert result.reason is R.REVOCATION_UNKNOWN

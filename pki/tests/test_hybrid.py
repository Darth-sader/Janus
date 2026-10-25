"""Hybrid (RSA + ML-DSA), pure PQ and mixed classical/hybrid chains."""
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from pki import hybrid
from pki.ca import CertificateAuthority, build_name, create_intermediate_ca, create_root_ca
from pki.issuance import issue_certificate
from pki.keystore import load_private_key, save_private_key
from pki.lifecycle import CertificateManager
from pki.models import CertMode, ValidationReason
from pki.parsing import parse_certificate
from pki.revocation import RevocationRegistry
from pki.signatures import verify_signatures
from pki.trust import TrustStore
from pki.validation import ValidationPolicy, validate_certificate

R = ValidationReason
REQUIRE_PQ = ValidationPolicy(require_pq=True)


def _validate(cert, store, intermediates, **kwargs):
    return validate_certificate(cert, store, intermediates, **kwargs)


# ---------- structure ----------

def test_hybrid_leaf_carries_both_keys_and_signatures(hybrid_leaf, hybrid_intermediate):
    cert = hybrid_leaf.certificate
    assert hybrid.is_hybrid(cert)
    assert hybrid.alt_signature(cert) is not None
    assert verify_signatures(cert, hybrid_intermediate.certificate) == ["RSA", "ML-DSA-65"]


def test_hybrid_record(hybrid_leaf):
    record = parse_certificate(hybrid_leaf.certificate)
    assert record.mode is CertMode.HYBRID
    assert record.public_key_algorithm == "RSA-2048 + ML-DSA-65"
    assert record.signature_algorithm == "sha256WithRSAEncryption + ML-DSA-65"


def test_legacy_software_still_reads_it(hybrid_leaf):
    # All hybrid extensions are non-critical, so RSA-only software can ignore them.
    exts = [e for e in hybrid_leaf.certificate.extensions if e.oid.dotted_string.startswith("2.5.29.7")]
    assert len(exts) == 3 and not any(e.critical for e in exts)


def test_hybrid_certificate_is_larger(hybrid_leaf, leaf):
    size = lambda c: len(c.public_bytes(serialization.Encoding.DER))
    assert size(hybrid_leaf.certificate) > 4 * size(leaf.certificate)


# ---------- validation ----------

def test_hybrid_chain_validates(hybrid_leaf, hybrid_intermediate, hybrid_trust_store):
    result = _validate(hybrid_leaf.certificate, hybrid_trust_store, [hybrid_intermediate.certificate], policy=REQUIRE_PQ)
    assert result.valid
    assert result.mode is CertMode.HYBRID


def test_forged_rsa_with_wrong_ml_dsa_is_rejected(hybrid_intermediate, hybrid_trust_store):
    # Simulates a quantum attacker who can forge the CA's RSA signature but not its ML-DSA one.
    attacker_key = hybrid.HybridPrivateKey(hybrid_intermediate.private_key.classical,
                                           hybrid.generate_ml_dsa_key("ML-DSA-65"))
    attacker = CertificateAuthority(hybrid_intermediate.certificate, attacker_key,
                                    hybrid_intermediate.signer, hybrid_intermediate.config)
    forged = issue_certificate(attacker, "forged.example.test")
    result = _validate(forged.certificate, hybrid_trust_store, [hybrid_intermediate.certificate])
    assert result.reason is R.BAD_PQ_SIGNATURE


def test_tampering_with_ml_dsa_signature_breaks_rsa_too(hybrid_leaf, hybrid_intermediate, hybrid_trust_store):
    der = hybrid_leaf.certificate.public_bytes(serialization.Encoding.DER)
    sig = hybrid.alt_signature(hybrid_leaf.certificate)
    i = der.find(sig) + 100
    tampered = x509.load_der_x509_certificate(der[:i] + bytes([der[i] ^ 0xFF]) + der[i + 1:])
    result = _validate(tampered, hybrid_trust_store, [hybrid_intermediate.certificate])
    assert result.reason is R.BAD_SIGNATURE


def test_missing_ml_dsa_signature_value_is_rejected(hybrid_intermediate, hybrid_trust_store):
    now = datetime.now(timezone.utc)
    key = hybrid_intermediate.private_key
    cert = (
        x509.CertificateBuilder()
        .subject_name(build_name("stripped.example.test"))
        .issuer_name(hybrid_intermediate.certificate.subject)
        .public_key(key.classical.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + timedelta(days=30))
        .add_extension(hybrid.alt_signature_algorithm_extension(key.pq.public_key()), critical=False)
        .sign(key.classical, hashes.SHA256())
    )
    result = _validate(cert, hybrid_trust_store, [hybrid_intermediate.certificate])
    assert result.reason is R.BAD_PQ_SIGNATURE


# ---------- mixed chains ----------

def test_hybrid_ca_issues_classical_cert_for_legacy_asset(hybrid_intermediate, hybrid_trust_store):
    legacy = issue_certificate(hybrid_intermediate, "legacy-rtu.example.test", mode=CertMode.CLASSICAL)
    assert not hybrid.is_hybrid(legacy.certificate)
    ok = _validate(legacy.certificate, hybrid_trust_store, [hybrid_intermediate.certificate])
    assert ok.valid and ok.mode is CertMode.CLASSICAL
    strict = _validate(legacy.certificate, hybrid_trust_store, [hybrid_intermediate.certificate], policy=REQUIRE_PQ)
    assert [i.reason for i in strict.issues] == [R.POLICY_VIOLATION]
    assert "legacy-rtu" in strict.issues[0].subject


def test_hybrid_ca_issues_pq_only_cert(hybrid_intermediate, hybrid_trust_store):
    pq = issue_certificate(hybrid_intermediate, "pq-ready.example.test", mode=CertMode.PQ)
    result = _validate(pq.certificate, hybrid_trust_store, [hybrid_intermediate.certificate], policy=REQUIRE_PQ)
    assert result.valid and result.mode is CertMode.PQ
    usage = pq.certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    assert usage.digital_signature and not usage.key_encipherment


def test_classical_intermediate_under_hybrid_root(hybrid_root, hybrid_trust_store):
    inter = create_intermediate_ca(hybrid_root, "Classical Sub CA", mode=CertMode.CLASSICAL)
    leaf = issue_certificate(inter, "mixed.example.test")
    assert _validate(leaf.certificate, hybrid_trust_store, [inter.certificate]).valid
    with pytest.raises(ValueError):
        issue_certificate(inter, "nope.example.test", mode=CertMode.HYBRID)


def test_classical_ca_cannot_issue_hybrid_or_pq(intermediate_ca, root_ca):
    with pytest.raises(ValueError):
        issue_certificate(intermediate_ca, "x.example.test", mode=CertMode.HYBRID)
    with pytest.raises(ValueError):
        issue_certificate(intermediate_ca, "x.example.test", mode=CertMode.PQ)
    with pytest.raises(ValueError):
        create_intermediate_ca(root_ca, "Hybrid under classical", mode=CertMode.HYBRID)


# ---------- pure PQ ----------

def test_pure_pq_hierarchy(pq_root):
    inter = create_intermediate_ca(pq_root, "PQ Intermediate CA")
    leaf = issue_certificate(inter, "pq-only.example.test")
    store = TrustStore([pq_root.certificate])
    result = _validate(leaf.certificate, store, [inter.certificate], policy=REQUIRE_PQ)
    assert result.valid and result.mode is CertMode.PQ
    assert parse_certificate(leaf.certificate).signature_algorithm == "ML-DSA-65"
    with pytest.raises(ValueError):
        issue_certificate(inter, "legacy.example.test", mode=CertMode.CLASSICAL)


def test_pq_ca_revocation(pq_root):
    inter = create_intermediate_ca(pq_root, "PQ Revoking CA")
    leaf = issue_certificate(inter, "pq-revoked.example.test")
    registry = RevocationRegistry(inter)
    registry.revoke(leaf.certificate)
    result = _validate(leaf.certificate, TrustStore([pq_root.certificate]), [inter.certificate],
                       crls=[registry.generate_crl()])
    assert result.reason is R.REVOKED


# ---------- migration-aware PKI ----------

def test_migrate_classical_to_hybrid_to_pq(intermediate_ca, root_ca, hybrid_intermediate, hybrid_root):
    manager = CertificateManager()
    mc = manager.issue(intermediate_ca, "substation-017.example.test")
    classical_cert = mc.certificate
    store = TrustStore([root_ca.certificate, hybrid_root.certificate])
    intermediates = [intermediate_ca.certificate, hybrid_intermediate.certificate]

    manager.migrate(mc.cert_id, CertMode.HYBRID, ca=hybrid_intermediate)
    assert mc.mode is CertMode.HYBRID
    assert "migrate classical -> hybrid" in mc.history[-1].note
    assert _validate(mc.certificate, store, intermediates, crls=manager.current_crls(), policy=REQUIRE_PQ).valid
    old = _validate(classical_cert, store, intermediates, crls=manager.current_crls())
    assert old.reason is R.REVOKED

    manager.migrate(mc.cert_id, CertMode.PQ)
    assert mc.mode is CertMode.PQ
    assert len(mc.previous_serials) == 2
    assert _validate(mc.certificate, store, intermediates, crls=manager.current_crls(), policy=REQUIRE_PQ).valid


# ---------- key storage ----------

def test_hybrid_key_round_trip(tmp_path, hybrid_leaf):
    path = tmp_path / "hybrid.key.pem"
    save_private_key(hybrid_leaf.private_key, path, b"correct horse")
    loaded = load_private_key(path, b"correct horse")
    assert isinstance(loaded, hybrid.HybridPrivateKey)
    message = b"hello"
    hybrid_leaf.private_key.pq.public_key().verify(loaded.pq.sign(message), message)
    assert loaded.classical.private_numbers() == hybrid_leaf.private_key.classical.private_numbers()

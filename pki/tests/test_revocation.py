from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509

from pki.ca import create_intermediate_ca, create_root_ca
from pki.issuance import issue_certificate
from pki.models import ValidationReason
from pki.revocation import RevocationRegistry
from pki.validation import ValidationPolicy, validate_certificate

R = ValidationReason
REQUIRE_CRL = ValidationPolicy(require_revocation_check=True)


def test_revoked_leaf(intermediate_ca, trust_store):
    leaf = issue_certificate(intermediate_ca, "revoked.example.test")
    registry = RevocationRegistry(intermediate_ca)
    registry.revoke(leaf.certificate, x509.ReasonFlags.key_compromise)
    result = validate_certificate(leaf.certificate, trust_store, [intermediate_ca.certificate],
                                  crls=[registry.generate_crl()])
    assert result.reason is R.REVOKED
    assert "keyCompromise" in result.issues[0].message


def test_other_certificates_unaffected(leaf, intermediate_ca, trust_store):
    other = issue_certificate(intermediate_ca, "other.example.test")
    registry = RevocationRegistry(intermediate_ca)
    registry.revoke(other.certificate)
    result = validate_certificate(leaf.certificate, trust_store, [intermediate_ca.certificate],
                                  crls=[registry.generate_crl()])
    assert result.valid


def test_revoked_intermediate(root_ca, config, trust_store):
    inter = create_intermediate_ca(root_ca, "Compromised Intermediate")
    leaf = issue_certificate(inter, "victim.example.test")
    registry = RevocationRegistry(root_ca)
    registry.revoke(inter.certificate, x509.ReasonFlags.ca_compromise)
    result = validate_certificate(leaf.certificate, trust_store, [inter.certificate], crls=[registry.generate_crl()])
    assert result.reason is R.REVOKED
    assert "Compromised Intermediate" in result.issues[0].subject


def test_crl_contents(intermediate_ca):
    leaf = issue_certificate(intermediate_ca, "listed.example.test")
    registry = RevocationRegistry(intermediate_ca)
    registry.revoke(leaf.certificate, x509.ReasonFlags.superseded)
    crl = registry.generate_crl()
    assert crl.issuer == intermediate_ca.certificate.subject
    assert crl.is_signature_valid(intermediate_ca.certificate.public_key())
    entry = crl.get_revoked_certificate_by_serial_number(leaf.certificate.serial_number)
    assert entry.extensions.get_extension_for_class(x509.CRLReason).value.reason is x509.ReasonFlags.superseded
    assert registry.is_revoked(leaf.certificate)


def test_crl_number_increases(intermediate_ca):
    registry = RevocationRegistry(intermediate_ca)
    numbers = [registry.generate_crl().extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
               for _ in range(2)]
    assert numbers == [1, 2]


def test_cannot_revoke_twice(intermediate_ca):
    leaf = issue_certificate(intermediate_ca, "twice.example.test")
    registry = RevocationRegistry(intermediate_ca)
    registry.revoke(leaf.certificate)
    with pytest.raises(ValueError):
        registry.revoke(leaf.certificate)


def test_cannot_revoke_another_cas_certificate(root_ca, leaf):
    with pytest.raises(ValueError):
        RevocationRegistry(root_ca).revoke(leaf.certificate)


def test_fresh_crls_satisfy_required_check(leaf, root_ca, intermediate_ca, trust_store):
    crls = [RevocationRegistry(root_ca).generate_crl(), RevocationRegistry(intermediate_ca).generate_crl()]
    result = validate_certificate(leaf.certificate, trust_store, [intermediate_ca.certificate],
                                  crls=crls, policy=REQUIRE_CRL)
    assert result.valid


def test_expired_crl_is_not_used(leaf, root_ca, intermediate_ca, trust_store):
    old = datetime.now(timezone.utc) - timedelta(days=10)
    crls = [RevocationRegistry(root_ca).generate_crl(),
            RevocationRegistry(intermediate_ca).generate_crl(now=old, validity_days=1)]
    result = validate_certificate(leaf.certificate, trust_store, [intermediate_ca.certificate],
                                  crls=crls, policy=REQUIRE_CRL)
    assert result.reason is R.REVOCATION_UNKNOWN
    assert "expired" in result.issues[0].message


def test_forged_crl_is_ignored(leaf, intermediate_ca, trust_store, config):
    # An attacker CA with the same name tries to revoke our leaf.
    attacker_root = create_root_ca("Attacker Root", config)
    impostor = create_intermediate_ca(attacker_root, "Test Intermediate CA")
    forged = RevocationRegistry(impostor)
    forged.revoke(leaf.certificate)
    result = validate_certificate(leaf.certificate, trust_store, [intermediate_ca.certificate],
                                  crls=[forged.generate_crl()])
    assert result.valid
    strict = validate_certificate(leaf.certificate, trust_store, [intermediate_ca.certificate],
                                  crls=[forged.generate_crl()], policy=REQUIRE_CRL)
    assert any("signature is invalid" in i.message for i in strict.issues)


def test_revocation_is_not_retroactive(intermediate_ca, trust_store):
    leaf = issue_certificate(intermediate_ca, "later.example.test")
    revoked_at = leaf.certificate.not_valid_before_utc + timedelta(hours=1)
    registry = RevocationRegistry(intermediate_ca)
    registry.revoke(leaf.certificate, when=revoked_at)
    crl = registry.generate_crl()
    before = validate_certificate(leaf.certificate, trust_store, [intermediate_ca.certificate], crls=[crl],
                                  at_time=revoked_at - timedelta(minutes=30))
    after = validate_certificate(leaf.certificate, trust_store, [intermediate_ca.certificate], crls=[crl],
                                 at_time=revoked_at + timedelta(minutes=30))
    assert before.valid
    assert after.reason is R.REVOKED

from datetime import timedelta

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

from pki.issuance import issue_certificate


def test_leaf_signed_by_intermediate(intermediate_ca, leaf):
    cert = leaf.certificate
    assert cert.issuer == intermediate_ca.certificate.subject
    cert.verify_directly_issued_by(intermediate_ca.certificate)


def test_leaf_is_not_a_ca(leaf):
    bc = leaf.certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca is False
    ku = leaf.certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    assert not ku.key_cert_sign


def test_leaf_has_server_auth_and_san(leaf):
    eku = leaf.certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert ExtendedKeyUsageOID.SERVER_AUTH in eku
    san = leaf.certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == ["app.example.test", "www.example.test"]


def test_san_defaults_to_common_name(intermediate_ca):
    issued = issue_certificate(intermediate_ca, "api.example.test")
    san = issued.certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == ["api.example.test"]


def test_leaf_validity_period(intermediate_ca):
    issued = issue_certificate(intermediate_ca, "short.example.test", validity_days=30)
    c = issued.certificate
    assert c.not_valid_after_utc - c.not_valid_before_utc == timedelta(days=30)


def test_leaf_cannot_outlive_issuer(intermediate_ca):
    issued = issue_certificate(intermediate_ca, "long.example.test", validity_days=100_000)
    assert issued.certificate.not_valid_after_utc == intermediate_ca.certificate.not_valid_after_utc


def test_serial_numbers_are_unique(intermediate_ca):
    serials = {issue_certificate(intermediate_ca, f"h{i}.example.test").certificate.serial_number
               for i in range(3)}
    assert len(serials) == 3


def test_leaf_key_matches_certificate(leaf):
    assert leaf.private_key.public_key().public_numbers() == \
        leaf.certificate.public_key().public_numbers()

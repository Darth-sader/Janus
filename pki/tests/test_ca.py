import pytest
from cryptography import x509

from pki.ca import create_root_ca
from pki.models import CertMode


def _basic_constraints(cert):
    return cert.extensions.get_extension_for_class(x509.BasicConstraints).value


def test_root_is_self_signed_ca(root_ca):
    cert = root_ca.certificate
    assert cert.subject == cert.issuer
    cert.verify_directly_issued_by(cert)  # raises if signature is bad
    bc = _basic_constraints(cert)
    assert bc.ca is True
    assert bc.path_length == 1


def test_root_key_usage_allows_cert_signing(root_ca):
    ku = root_ca.certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    assert ku.key_cert_sign and ku.crl_sign


def test_intermediate_signed_by_root(root_ca, intermediate_ca):
    inter = intermediate_ca.certificate
    assert inter.issuer == root_ca.certificate.subject
    inter.verify_directly_issued_by(root_ca.certificate)
    bc = _basic_constraints(inter)
    assert bc.ca is True
    assert bc.path_length == 0


def test_intermediate_does_not_outlive_root(root_ca, intermediate_ca):
    assert intermediate_ca.certificate.not_valid_after_utc <= root_ca.certificate.not_valid_after_utc


def test_intermediate_aki_matches_root_ski(root_ca, intermediate_ca):
    ski = root_ca.certificate.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    aki = intermediate_ca.certificate.extensions.get_extension_for_class(
        x509.AuthorityKeyIdentifier).value
    assert aki.key_identifier == ski.digest


def test_intermediate_not_signed_by_other_root(intermediate_ca, config):
    other_root = create_root_ca("Other Root CA", config)
    with pytest.raises(Exception):
        intermediate_ca.certificate.verify_directly_issued_by(other_root.certificate)


def test_root_mode_follows_config(hybrid_root, pq_root):
    assert hybrid_root.mode is CertMode.HYBRID
    assert pq_root.mode is CertMode.PQ

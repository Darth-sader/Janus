"""Leaf (end-entity) certificate issuance."""
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

from pki.ca import CertificateAuthority, authority_key_identifier, build_name
from pki.models import CertMode
from pki.provider import mode_of_key, signer_for


@dataclass
class IssuedCertificate:
    certificate: x509.Certificate
    private_key: Any


def issue_certificate(
    issuer: CertificateAuthority,
    common_name: str,
    dns_names: list[str] | None = None,
    validity_days: int | None = None,
    mode: CertMode | None = None,
    private_key: Any = None,
) -> IssuedCertificate:
    """Issue a server certificate.

    `mode` defaults to the issuer's mode, so a hybrid CA can still issue a
    classical certificate for a legacy asset. Pass `private_key` to reuse an
    existing key (renewal without key rotation); its type decides the mode.
    """
    if private_key is not None:
        key_mode = mode_of_key(private_key)
        if mode is not None and mode is not key_mode:
            raise ValueError(f"a {key_mode.value} key cannot be used for a {mode.value} certificate")
        mode = key_mode
    signer = signer_for(mode or issuer.mode, issuer.config)
    key = private_key if private_key is not None else signer.generate_private_key()
    public_key = signer.public_key(key)
    now = datetime.now(timezone.utc)
    days = validity_days if validity_days is not None else issuer.config.leaf_validity_days
    # A leaf must not outlive its issuing CA.
    not_after = min(now + timedelta(days=days), issuer.certificate.not_valid_after_utc)
    dns_names = dns_names or [common_name]

    builder = (
        x509.CertificateBuilder()
        .subject_name(build_name(common_name))
        .issuer_name(issuer.certificate.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                # ML-DSA keys can only sign, so key encipherment is RSA-only.
                digital_signature=True, key_encipherment=signer.mode is not CertMode.PQ,
                content_commitment=False, data_encipherment=False, key_agreement=False,
                key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in dns_names]), critical=False
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(authority_key_identifier(issuer.certificate), critical=False)
    )
    builder = signer.add_subject_key(builder, key)
    cert = signer.sign(builder, issuer.private_key)
    return IssuedCertificate(cert, key)

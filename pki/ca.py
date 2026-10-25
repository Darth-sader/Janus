"""Root CA and Intermediate CA creation."""
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography import x509
from cryptography.x509.oid import NameOID

from pki.config import PKIConfig
from pki.models import CertMode
from pki.provider import CertificateSigner, get_signer, signer_for


@dataclass
class CertificateAuthority:
    certificate: x509.Certificate
    private_key: Any
    signer: CertificateSigner
    config: PKIConfig

    @property
    def mode(self) -> CertMode:
        return self.signer.mode


def build_name(common_name: str, organization: str = "PQC Migration Prototype") -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])


def ca_key_usage() -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=True, key_cert_sign=True, crl_sign=True,
        content_commitment=False, key_encipherment=False, data_encipherment=False,
        key_agreement=False, encipher_only=False, decipher_only=False,
    )


def authority_key_identifier(issuer_cert: x509.Certificate) -> x509.AuthorityKeyIdentifier:
    ski = issuer_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    return x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski)


def create_root_ca(common_name: str, config: PKIConfig | None = None) -> CertificateAuthority:
    config = config or PKIConfig()
    signer = get_signer(config)
    key = signer.generate_private_key()
    public_key = signer.public_key(key)
    name = build_name(common_name)
    now = datetime.now(timezone.utc)

    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)  # self-signed
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=config.root_validity_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(ca_key_usage(), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
    )
    builder = signer.add_subject_key(builder, key)
    cert = signer.sign(builder, key)
    return CertificateAuthority(cert, key, signer, config)


def create_intermediate_ca(
    root: CertificateAuthority, common_name: str, mode: CertMode | None = None,
) -> CertificateAuthority:
    """Create an intermediate CA signed by `root`; `mode` defaults to the root's mode."""
    config = root.config
    signer = signer_for(mode, config) if mode else root.signer
    key = signer.generate_private_key()
    public_key = signer.public_key(key)
    now = datetime.now(timezone.utc)
    # An intermediate must not outlive the root that signed it.
    not_after = min(now + timedelta(days=config.intermediate_validity_days),
                    root.certificate.not_valid_after_utc)

    builder = (
        x509.CertificateBuilder()
        .subject_name(build_name(common_name))
        .issuer_name(root.certificate.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(ca_key_usage(), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(authority_key_identifier(root.certificate), critical=False)
    )
    builder = signer.add_subject_key(builder, key)
    cert = signer.sign(builder, root.private_key)
    return CertificateAuthority(cert, key, signer, config)

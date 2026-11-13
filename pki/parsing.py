"""Certificate loading and parsing into CertificateRecord."""
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from pki import hybrid
from pki.models import CertificateRecord, CertMode, CertRole


def load_certificate(data: bytes | str) -> x509.Certificate:
    """Load a certificate from PEM or DER bytes."""
    if isinstance(data, str):
        data = data.encode()
    if data.lstrip().startswith(b"-----BEGIN"):
        return x509.load_pem_x509_certificate(data)
    return x509.load_der_x509_certificate(data)


def to_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _key_name(key) -> str:
    if isinstance(key, rsa.RSAPublicKey):
        return f"RSA-{key.key_size}"
    if isinstance(key, hybrid.ML_DSA_PUBLIC_TYPES):
        return hybrid.ml_dsa_name(key)
    return type(key).__name__


def _public_key_algorithm(cert: x509.Certificate) -> str:
    name = _key_name(cert.public_key())
    alt = hybrid.alt_public_key(cert)
    return f"{name} + {_key_name(alt)}" if alt is not None else name


def _signature_algorithm(cert: x509.Certificate) -> str:
    oid = cert.signature_algorithm_oid
    name = hybrid.ML_DSA_SIGNATURE_OIDS.get(oid.dotted_string) or oid._name or oid.dotted_string
    alt_name = hybrid.alt_signature_algorithm_name(cert)
    return f"{name} + {alt_name}" if alt_name else name


def _role(cert: x509.Certificate, is_ca: bool) -> CertRole:
    if not is_ca:
        return CertRole.LEAF
    return CertRole.ROOT_CA if cert.subject == cert.issuer else CertRole.INTERMEDIATE_CA


def certificate_mode(cert: x509.Certificate) -> CertMode:
    if isinstance(cert.public_key(), hybrid.ML_DSA_PUBLIC_TYPES):
        return CertMode.PQ
    return CertMode.HYBRID if hybrid.is_hybrid(cert) else CertMode.CLASSICAL


def parse_certificate(cert: x509.Certificate | bytes | str) -> CertificateRecord:
    if not isinstance(cert, x509.Certificate):
        cert = load_certificate(cert)

    try:
        is_ca = cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        is_ca = False

    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        dns_names = san.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        dns_names = []

    return CertificateRecord(
        serial_number=format(cert.serial_number, "x"),
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        role=_role(cert, is_ca),
        is_ca=is_ca,
        public_key_algorithm=_public_key_algorithm(cert),
        signature_algorithm=_signature_algorithm(cert),
        mode=certificate_mode(cert),
        fingerprint_sha256=cert.fingerprint(hashes.SHA256()).hex(),
        san_dns_names=dns_names,
    )

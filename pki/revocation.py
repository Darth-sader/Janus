"""Revocation using Certificate Revocation Lists (CRLs).

DEFAULT (confirm with team, open question 5): CRLs only; OCSP is not
implemented. Each CA keeps a RevocationRegistry and publishes a signed CRL,
which validation.py checks.

CRLs are signed with the CA's RSA key, or its ML-DSA key for a PQ-only CA.
A hybrid CA's CRL carries only the RSA signature in this prototype.
"""
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa

from pki.ca import CertificateAuthority, authority_key_identifier
from pki.hybrid import HybridPrivateKey


@dataclass(frozen=True)
class RevokedEntry:
    serial_number: int
    revoked_at: datetime
    reason: x509.ReasonFlags


def _crl_signing_key(ca_key: Any) -> tuple[Any, hashes.HashAlgorithm | None]:
    if isinstance(ca_key, HybridPrivateKey):
        return ca_key.classical, hashes.SHA256()
    if isinstance(ca_key, rsa.RSAPrivateKey):
        return ca_key, hashes.SHA256()
    return ca_key, None  # ML-DSA signs without a separate hash


class RevocationRegistry:
    """The revoked certificates of one CA, published as signed CRLs."""

    def __init__(self, ca: CertificateAuthority):
        self.ca = ca
        self._entries: dict[int, RevokedEntry] = {}
        self._crl_number = 0

    def revoke(self, cert: x509.Certificate, reason: x509.ReasonFlags = x509.ReasonFlags.unspecified,
               when: datetime | None = None) -> RevokedEntry:
        if cert.issuer != self.ca.certificate.subject:
            raise ValueError("certificate was not issued by this CA")
        if cert.serial_number in self._entries:
            raise ValueError(f"certificate {cert.serial_number:x} is already revoked")
        entry = RevokedEntry(cert.serial_number, when or datetime.now(timezone.utc), reason)
        self._entries[cert.serial_number] = entry
        return entry

    def is_revoked(self, cert: x509.Certificate) -> bool:
        return cert.serial_number in self._entries

    @property
    def entries(self) -> list[RevokedEntry]:
        return list(self._entries.values())

    def generate_crl(self, now: datetime | None = None, validity_days: int | None = None) -> x509.CertificateRevocationList:
        now = now or datetime.now(timezone.utc)
        days = validity_days if validity_days is not None else self.ca.config.crl_validity_days
        self._crl_number += 1
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(self.ca.certificate.subject)
            .last_update(now)
            .next_update(now + timedelta(days=days))
            .add_extension(x509.CRLNumber(self._crl_number), critical=False)
            .add_extension(authority_key_identifier(self.ca.certificate), critical=False)
        )
        for entry in self._entries.values():
            revoked = (
                x509.RevokedCertificateBuilder()
                .serial_number(entry.serial_number)
                .revocation_date(entry.revoked_at)
                .add_extension(x509.CRLReason(entry.reason), critical=False)
                .build()
            )
            builder = builder.add_revoked_certificate(revoked)
        key, algorithm = _crl_signing_key(self.ca.private_key)
        return builder.sign(private_key=key, algorithm=algorithm)

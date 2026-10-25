"""Signing abstraction: one signer per certificate mode.

Everything in ca.py / issuance.py signs through a CertificateSigner, never by
calling RSA or ML-DSA directly, so changing algorithms means changing this
file only. When Person 1's CryptoProvider is ready, these signers can
delegate key generation and signing to it.

A signer describes the certificate being *made* (its subject's keys). The
issuer's key decides what the issuer can sign with:

    issuer key      can issue
    RSA             classical
    RSA + ML-DSA    classical, hybrid, PQ
    ML-DSA          PQ
"""
from typing import Any, Protocol

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa

from pki import hybrid
from pki.config import PKIConfig
from pki.hybrid import HybridPrivateKey
from pki.models import CertMode


class CertificateSigner(Protocol):
    name: str
    mode: CertMode

    def generate_private_key(self) -> Any: ...

    def public_key(self, private_key: Any) -> Any:
        """The key placed in the certificate's SubjectPublicKeyInfo."""

    def add_subject_key(self, builder: x509.CertificateBuilder, private_key: Any) -> x509.CertificateBuilder:
        """Add any extra subject key material (the ML-DSA key of a hybrid certificate)."""

    def sign(self, builder: x509.CertificateBuilder, issuer_key: Any) -> x509.Certificate: ...


def _classical_part(issuer_key: Any) -> rsa.RSAPrivateKey:
    if isinstance(issuer_key, HybridPrivateKey):
        return issuer_key.classical
    if isinstance(issuer_key, rsa.RSAPrivateKey):
        return issuer_key
    raise ValueError("this issuer has no RSA key, so it cannot sign classical or hybrid certificates")


def _pq_part(issuer_key: Any) -> Any:
    if isinstance(issuer_key, HybridPrivateKey):
        return issuer_key.pq
    if isinstance(issuer_key, hybrid.ML_DSA_PRIVATE_TYPES):
        return issuer_key
    raise ValueError("this issuer has no ML-DSA key, so it cannot sign hybrid or PQ certificates")


class RSASigner:
    """Classical RSA + SHA-256."""
    mode = CertMode.CLASSICAL

    def __init__(self, key_size: int = 4096):
        self.key_size = key_size
        self.name = f"RSA-{key_size}"

    def generate_private_key(self) -> rsa.RSAPrivateKey:
        return rsa.generate_private_key(public_exponent=65537, key_size=self.key_size)

    def public_key(self, private_key: rsa.RSAPrivateKey) -> rsa.RSAPublicKey:
        return private_key.public_key()

    def add_subject_key(self, builder: x509.CertificateBuilder, private_key: Any) -> x509.CertificateBuilder:
        return builder

    def sign(self, builder: x509.CertificateBuilder, issuer_key: Any) -> x509.Certificate:
        return builder.sign(private_key=_classical_part(issuer_key), algorithm=hashes.SHA256())


class MLDSASigner:
    """Post-quantum only: ML-DSA keys and signatures."""
    mode = CertMode.PQ

    def __init__(self, algorithm: str = "ML-DSA-65"):
        self.algorithm = algorithm
        self.name = algorithm

    def generate_private_key(self) -> Any:
        return hybrid.generate_ml_dsa_key(self.algorithm)

    def public_key(self, private_key: Any) -> Any:
        return private_key.public_key()

    def add_subject_key(self, builder: x509.CertificateBuilder, private_key: Any) -> x509.CertificateBuilder:
        return builder

    def sign(self, builder: x509.CertificateBuilder, issuer_key: Any) -> x509.Certificate:
        return builder.sign(private_key=_pq_part(issuer_key), algorithm=None)


class HybridSigner:
    """RSA + ML-DSA. See hybrid.py for how the two signatures are encoded."""
    mode = CertMode.HYBRID

    def __init__(self, key_size: int = 4096, algorithm: str = "ML-DSA-65"):
        self.classical = RSASigner(key_size)
        self.pq = MLDSASigner(algorithm)
        self.name = f"{self.classical.name} + {self.pq.name}"

    def generate_private_key(self) -> HybridPrivateKey:
        return HybridPrivateKey(self.classical.generate_private_key(), self.pq.generate_private_key())

    def public_key(self, private_key: HybridPrivateKey) -> rsa.RSAPublicKey:
        return private_key.classical.public_key()

    def add_subject_key(self, builder: x509.CertificateBuilder, private_key: HybridPrivateKey) -> x509.CertificateBuilder:
        return builder.add_extension(hybrid.alt_public_key_extension(private_key.pq.public_key()), critical=False)

    def sign(self, builder: x509.CertificateBuilder, issuer_key: Any) -> x509.Certificate:
        if not isinstance(issuer_key, HybridPrivateKey):
            raise ValueError("hybrid certificates need a hybrid issuer (RSA + ML-DSA)")
        builder = builder.add_extension(
            hybrid.alt_signature_algorithm_extension(issuer_key.pq.public_key()), critical=False)
        # 1. ML-DSA signs the certificate as it stands (the "pre-TBS").
        pre = builder.sign(private_key=issuer_key.classical, algorithm=hashes.SHA256())
        pq_signature = issuer_key.pq.sign(pre.tbs_certificate_bytes)
        # 2. RSA signs the final certificate, which now includes the ML-DSA signature.
        builder = builder.add_extension(hybrid.alt_signature_value_extension(pq_signature), critical=False)
        return builder.sign(private_key=issuer_key.classical, algorithm=hashes.SHA256())


def signer_for(mode: CertMode, config: PKIConfig) -> CertificateSigner:
    if mode is CertMode.CLASSICAL:
        return RSASigner(config.rsa_key_size)
    if mode is CertMode.HYBRID:
        return HybridSigner(config.rsa_key_size, config.pq_algorithm)
    if mode is CertMode.PQ:
        return MLDSASigner(config.pq_algorithm)
    raise ValueError(f"unknown mode {mode!r}")


def get_signer(config: PKIConfig) -> CertificateSigner:
    return signer_for(config.mode, config)


def mode_of_key(private_key: Any) -> CertMode:
    if isinstance(private_key, HybridPrivateKey):
        return CertMode.HYBRID
    if isinstance(private_key, rsa.RSAPrivateKey):
        return CertMode.CLASSICAL
    if isinstance(private_key, hybrid.ML_DSA_PRIVATE_TYPES):
        return CertMode.PQ
    raise ValueError(f"unsupported key type {type(private_key).__name__}")

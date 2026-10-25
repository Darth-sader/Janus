"""Certificate-to-crypto interface contracts (Phase 3).

This is the agreed boundary between the cryptography layer (Poojita)
and the PKI layer (Ayanna).  The classes below are *working reference
implementations* of the contract - Ayanna can call them immediately, and
her PKI subsystem must interact with the crypto layer through exactly
these operations (or an evolution of them agreed in review).

Layer responsibility split (normative):

===========================  ==============================================
Cryptography layer (here)    PKI layer (Ayanna)
===========================  ==============================================
key generation               Root CA / Intermediate CA hierarchy
signing (components)         CA key management & trust anchors
signature verification       certificate issuance/parsing/lifecycle
serialization formats        chain construction & validation
algorithm identifiers        revocation, renewal, rotation
hybrid acceptance policy     validity-period and issuer checks
===========================  ==============================================
"""

from __future__ import annotations

from typing import Protocol

from crypto.errors import MalformedSignatureError, SigningError
from crypto.hybrid import HybridSigner, HybridVerifier
from crypto.keys import PublicKey
from crypto.verification import VerificationResult

from .model import (
    CertificateValidationRequest,
    CertificateVerificationOutcome,
    HybridCertificateModel,
)


class CertificateSigningContract(Protocol):
    """What the PKI layer may call when **issuing** a certificate."""

    def sign_certificate(
        self,
        certificate: HybridCertificateModel,
        ca_classical_private_key,
        ca_pq_private_key,
    ) -> HybridCertificateModel: ...


class CertificateVerificationContract(Protocol):
    """What the PKI layer may call when **validating** a certificate."""

    def verify_certificate_signature(
        self,
        certificate: HybridCertificateModel,
        issuer_classical_public_key: PublicKey,
        issuer_pq_public_key: PublicKey,
    ) -> VerificationResult: ...

    def extract_public_keys(self, certificate: HybridCertificateModel) -> dict[str, PublicKey]: ...


class CertificateSigningService:
    """Crypto-side of issuance: the PKI layer hands over a populated,
    unsigned certificate model plus the CA's two private keys; this
    service computes the TBS bytes, produces both component signatures
    over those bytes, and returns the signed certificate."""

    def __init__(self, signer: HybridSigner) -> None:
        self._signer = signer

    def sign_certificate(
        self,
        certificate: HybridCertificateModel,
        ca_classical_private_key,
        ca_pq_private_key,
    ) -> HybridCertificateModel:
        if certificate.is_signed():
            raise SigningError("certificate already carries a signature; refusing to double-sign")
        tbs = certificate.to_be_signed_bytes()
        signature = self._signer.sign(tbs, ca_classical_private_key, ca_pq_private_key)
        # keep the signature_algorithm identifier consistent with the signer
        if signature.algorithm != certificate.signature_algorithm:
            raise SigningError(
                f"signer produces {signature.algorithm!r} but certificate declares "
                f"{certificate.signature_algorithm!r}"
            )
        return certificate.with_signature(signature)


class CertificateVerificationService:
    """Crypto-side of validation: verifies ONLY the certificate's hybrid
    signature.  The PKI layer then continues with its own checks
    (validity window, issuer/chain policy, revocation) - those are not
    part of this result."""

    def __init__(self, verifier: HybridVerifier) -> None:
        self._verifier = verifier

    def verify_certificate_signature(
        self,
        certificate: HybridCertificateModel,
        issuer_classical_public_key: PublicKey,
        issuer_pq_public_key: PublicKey,
    ) -> VerificationResult:
        if not certificate.is_signed():
            return VerificationResult(
                accepted=False,
                subject=f"certificate:{certificate.serial_number}",
                policy=self._verifier.policy.value,
                reason="certificate has no signature",
            )
        return self._verifier.verify(
            certificate.to_be_signed_bytes(),
            certificate.signature,
            issuer_classical_public_key,
            issuer_pq_public_key,
        )

    def verify_request(self, request: CertificateValidationRequest) -> CertificateVerificationOutcome:
        """Alternative entry point taking the explicit handoff object."""
        result = self.verify_certificate_signature(
            request.certificate,
            request.issuer_classical_public_key,
            request.issuer_pq_public_key,
        )
        return CertificateVerificationOutcome(
            signature_accepted=result.accepted,
            signature_algorithm=request.certificate.signature_algorithm,
            detail=result.to_dict(),
        )

    def extract_public_keys(self, certificate: HybridCertificateModel) -> dict[str, PublicKey]:
        """Interface for pulling the component public keys out of a
        certificate (used for chain building and for verifying
        end-entity signatures made under the certificate)."""
        return {
            "classical": certificate.classical_public_key,
            "pq": certificate.pq_public_key,
        }


__all__ = [
    "CertificateSigningContract",
    "CertificateVerificationContract",
    "CertificateSigningService",
    "CertificateVerificationService",
    "CertificateValidationRequest",
    "CertificateVerificationOutcome",
    "HybridCertificateModel",
    "MalformedSignatureError",
]

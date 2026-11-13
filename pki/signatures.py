"""Checking a certificate's signature(s) against its issuer, for every mode.

ML-DSA signatures are verified through the crypto layer's CryptoProvider
(see crypto_bridge.py); RSA signatures through X.509's own verification.
"""
from cryptography import x509
from cryptography.exceptions import InvalidSignature

from pki import crypto_bridge, hybrid
from pki.models import ValidationReason


class SignatureError(Exception):
    def __init__(self, reason: ValidationReason, message: str):
        super().__init__(message)
        self.reason = reason


def _verify_main_signature(cert: x509.Certificate, issuer: x509.Certificate) -> str:
    """Verify the certificate's ordinary X.509 signature; return the algorithm name."""
    pq_name = hybrid.ML_DSA_SIGNATURE_OIDS.get(cert.signature_algorithm_oid.dotted_string)
    if pq_name:
        # ML-DSA-signed: the issuer's ML-DSA key may be its main key or its alt key.
        issuer_key = hybrid.pq_public_key(issuer)
        if issuer_key is None:
            raise SignatureError(ValidationReason.BAD_SIGNATURE, "issuer has no ML-DSA key")
        if not crypto_bridge.verify_ml_dsa(issuer_key, cert.signature, cert.tbs_certificate_bytes):
            raise SignatureError(ValidationReason.BAD_SIGNATURE, f"{pq_name} signature does not verify")
        return pq_name
    try:
        cert.verify_directly_issued_by(issuer)
    except InvalidSignature:
        raise SignatureError(ValidationReason.BAD_SIGNATURE, "RSA signature does not verify") from None
    except (ValueError, TypeError) as e:
        raise SignatureError(ValidationReason.BAD_SIGNATURE, f"cannot verify signature: {e}") from None
    return "RSA"


def _verify_alt_signature(cert: x509.Certificate, issuer: x509.Certificate) -> str:
    issuer_key = hybrid.pq_public_key(issuer)
    if issuer_key is None:
        raise SignatureError(ValidationReason.BAD_PQ_SIGNATURE, "issuer has no ML-DSA key for the hybrid signature")
    expected_algorithm = hybrid.alt_signature_algorithm_extension(issuer_key).value
    if hybrid.alt_signature_algorithm(cert) != expected_algorithm:
        raise SignatureError(ValidationReason.BAD_PQ_SIGNATURE, "ML-DSA algorithm does not match the issuer's key")
    if not crypto_bridge.verify_ml_dsa(issuer_key, hybrid.alt_signature(cert), hybrid.pre_tbs_bytes(cert)):
        raise SignatureError(ValidationReason.BAD_PQ_SIGNATURE, "ML-DSA signature does not verify")
    return hybrid.ml_dsa_name(issuer_key)


def verify_signatures(cert: x509.Certificate, issuer: x509.Certificate) -> list[str]:
    """Verify every signature on `cert` (both halves of a hybrid one).

    Returns the algorithms that verified, e.g. ["RSA", "ML-DSA-65"].
    Raises SignatureError on the first failure: there is no fallback to the
    classical signature when the ML-DSA one fails (no downgrade).
    """
    verified = [_verify_main_signature(cert, issuer)]
    has_alt_signature = hybrid.alt_signature(cert) is not None
    if has_alt_signature:
        verified.append(_verify_alt_signature(cert, issuer))
    elif hybrid.alt_signature_algorithm(cert) is not None:
        raise SignatureError(ValidationReason.BAD_PQ_SIGNATURE, "hybrid signature value is missing")
    return verified


def has_pq_signature(cert: x509.Certificate) -> bool:
    oid = cert.signature_algorithm_oid.dotted_string
    return oid in hybrid.ML_DSA_SIGNATURE_OIDS or hybrid.alt_signature(cert) is not None

"""Cryptography layer of the hybrid PQ/T PKI framework (Poojita's workstream).

Subpackages
-----------
* :mod:`crypto.keys`         - algorithm-tagged key types + dev/test storage
* :mod:`crypto.rsa`          - RSA-4096 (RSASSA-PSS) classical provider
* :mod:`crypto.pq`           - ML-DSA (FIPS 204) and SLH-DSA (FIPS 205) providers
* :mod:`crypto.hybrid`       - parallel/composite hybrid signatures (RSA4096-MLDSA)
* :mod:`crypto.verification` - shared verification result types
* :mod:`crypto.certificates` - conceptual hybrid certificate model + PKI contracts

Every provider implements :class:`crypto_agility.interfaces.CryptoProvider`.
"""

from .errors import (
    ConfigurationError,
    CryptoError,
    InvalidKeyError,
    MalformedSignatureError,
    ProviderUnavailableError,
    SerializationError,
    SigningError,
    UnsupportedAlgorithmError,
)
from .keys import DevKeyStore, KeyPair, PrivateKey, PublicKey

# import concrete providers after keys/errors so submodule imports never see
# a partially initialized package
from .pq import MLDSAProvider, SLHDSAProvider
from .rsa import RSA4096Provider
from .verification import ComponentResult, VerificationResult, VerificationStatus

__all__ = [
    # errors
    "CryptoError",
    "UnsupportedAlgorithmError",
    "ProviderUnavailableError",
    "InvalidKeyError",
    "MalformedSignatureError",
    "SigningError",
    "SerializationError",
    "ConfigurationError",
    # keys
    "KeyPair",
    "PrivateKey",
    "PublicKey",
    "DevKeyStore",
    # providers
    "RSA4096Provider",
    "MLDSAProvider",
    "SLHDSAProvider",
    # verification
    "ComponentResult",
    "VerificationResult",
    "VerificationStatus",
]

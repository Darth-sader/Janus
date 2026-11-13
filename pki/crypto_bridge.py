"""Bridge between the PKI and the crypto-agility layer (crypto/, crypto_agility/).

The PKI keeps producing standard X.509 certificates with the `cryptography`
library (it needs native key objects to build and sign them). What it takes
from the crypto layer:

- Algorithm availability: a PQ algorithm is usable only if the crypto-agility
  registry says it is implemented (no silent fallback).
- ML-DSA verification: every ML-DSA signature the PKI checks (a PQ certificate's
  signature, or the alt signature of a hybrid one) is verified by the registry's
  CryptoProvider, so PKI and crypto layer agree on FIPS 204.

RSA signatures stay with X.509's own verification: certificates use
RSA PKCS#1 v1.5 + SHA-256, while the crypto layer's RSA provider is RSA-PSS.
"""
from functools import lru_cache
from typing import Any

from cryptography.hazmat.primitives import serialization

from crypto import PublicKey
from crypto.errors import CryptoError
from crypto_agility.policies import create_default_registry

# PKI parameter-set name -> crypto-agility algorithm id
PQ_ALGORITHM_IDS = {
    "ML-DSA-44": "mldsa44",
    "ML-DSA-65": "mldsa65",
    "ML-DSA-87": "mldsa87",
}


@lru_cache(maxsize=1)
def registry():
    return create_default_registry()


def algorithm_id(pq_algorithm: str) -> str:
    try:
        return PQ_ALGORITHM_IDS[pq_algorithm]
    except KeyError:
        raise ValueError(f"unknown PQ algorithm {pq_algorithm!r}") from None


def require_available(pq_algorithm: str) -> None:
    """Raise ValueError unless the crypto layer implements `pq_algorithm`."""
    availability = registry_check(pq_algorithm)
    if not availability["available"]:
        raise ValueError(f"{pq_algorithm} is not available in the crypto layer: {availability['reason']}")


def registry_check(pq_algorithm: str) -> dict:
    alg_id = algorithm_id(pq_algorithm)
    if not registry().is_available(alg_id):
        return {"algorithm_id": alg_id, "available": False, "reason": "not implemented in the registry"}
    return {"algorithm_id": alg_id, "available": True, "reason": registry().get_provider(alg_id).backend}


def verify_ml_dsa(public_key: Any, signature: bytes, message: bytes) -> bool:
    """Verify an ML-DSA signature with the crypto layer's provider for that parameter set."""
    from pki.hybrid import ml_dsa_name  # avoid an import cycle with pki.hybrid

    provider = registry().get_provider(algorithm_id(ml_dsa_name(public_key)))
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    try:
        return provider.verify(message, signature, PublicKey(provider.algorithm_id, raw))
    except CryptoError:
        return False

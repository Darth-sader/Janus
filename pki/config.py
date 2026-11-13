"""PKI configuration.

DEFAULTS (confirm with team):
- mode is CLASSICAL unless a CA or certificate asks for HYBRID or PQ.
- RSA key size is 4096 as per the spec; tests override it to 2048 because
  4096-bit key generation is slow.
- The PQ algorithm is ML-DSA-65 (open question: parameter set with Person 1).
- CRLs are valid for 7 days before a new one must be published.
"""
from dataclasses import dataclass

from pki.models import CertMode


@dataclass(frozen=True)
class PKIConfig:
    mode: CertMode = CertMode.CLASSICAL
    rsa_key_size: int = 4096
    pq_algorithm: str = "ML-DSA-65"      # ML-DSA-44, ML-DSA-65 or ML-DSA-87
    root_validity_days: int = 3650       # 10 years
    intermediate_validity_days: int = 1825  # 5 years
    leaf_validity_days: int = 365        # 1 year
    crl_validity_days: int = 7

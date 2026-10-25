"""File-based private key storage for the prototype.

DEFAULT (confirm with team, open question 7): keys are stored as PKCS#8 PEM
files encrypted with a passphrase. A hybrid key is one file holding two PEM
blocks, RSA first then ML-DSA. Not suitable for production -- no HSM.
"""
import re
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization

from pki.hybrid import HybridPrivateKey

_PEM_BLOCK = re.compile(rb"-----BEGIN [A-Z ]+-----.+?-----END [A-Z ]+-----\s*", re.DOTALL)


def _to_pem(key: Any, passphrase: bytes) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
    )


def save_private_key(key: Any, path: Path, passphrase: bytes) -> None:
    if isinstance(key, HybridPrivateKey):
        path.write_bytes(_to_pem(key.classical, passphrase) + _to_pem(key.pq, passphrase))
    else:
        path.write_bytes(_to_pem(key, passphrase))


def load_private_key(path: Path, passphrase: bytes) -> Any:
    blocks = _PEM_BLOCK.findall(path.read_bytes())
    keys = [serialization.load_pem_private_key(b, password=passphrase) for b in blocks]
    if len(keys) == 1:
        return keys[0]
    if len(keys) == 2:
        return HybridPrivateKey(classical=keys[0], pq=keys[1])
    raise ValueError(f"expected 1 or 2 keys in {path}, found {len(keys)}")

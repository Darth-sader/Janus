"""Algorithm-tagged key value types.

Every key carries the canonical algorithm id it belongs to (``rsa4096``,
``mldsa65``, ``RSA4096-MLDSA`` ...) next to its canonical encoding, so a
provider can refuse a key produced for another algorithm or parameter
set.  Keys are immutable values; equality compares algorithm and bytes.

Rendering hygiene: a :class:`PrivateKey` never renders its material
(``repr``/``str`` are redacted) and a :class:`PublicKey` renders only a
short SHA-256 fingerprint.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field


def _check(algorithm: str, data: bytes, kind: str) -> None:
    if not isinstance(algorithm, str) or not algorithm:
        raise ValueError(f"{kind} algorithm id must be a non-empty string")
    if not isinstance(data, (bytes, bytearray)) or len(data) == 0:
        raise ValueError(f"{kind} material must be non-empty bytes")


@dataclass(frozen=True)
class PublicKey:
    algorithm: str
    data: bytes = field(repr=False)

    def __post_init__(self) -> None:
        _check(self.algorithm, self.data, "public key")
        object.__setattr__(self, "data", bytes(self.data))

    def fingerprint(self) -> str:
        """First 16 hex chars of SHA-256 over the key bytes."""
        return hashlib.sha256(self.data).hexdigest()[:16]

    def __repr__(self) -> str:
        return f"PublicKey(algorithm={self.algorithm!r}, fingerprint={self.fingerprint()}, size={len(self.data)})"

    __str__ = __repr__


@dataclass(frozen=True)
class PrivateKey:
    algorithm: str
    data: bytes = field(repr=False)

    def __post_init__(self) -> None:
        _check(self.algorithm, self.data, "private key")
        object.__setattr__(self, "data", bytes(self.data))

    def __repr__(self) -> str:
        return f"PrivateKey(algorithm={self.algorithm!r}, <redacted>)"

    __str__ = __repr__


@dataclass(frozen=True)
class KeyPair:
    algorithm: str
    private_key: PrivateKey
    public_key: PublicKey

    def __post_init__(self) -> None:
        if self.private_key.algorithm != self.algorithm or self.public_key.algorithm != self.algorithm:
            raise ValueError(
                f"key pair algorithm mismatch: pair={self.algorithm!r}, "
                f"private={self.private_key.algorithm!r}, public={self.public_key.algorithm!r}"
            )

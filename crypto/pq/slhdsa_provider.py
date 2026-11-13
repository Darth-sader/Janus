"""SLH-DSA provider (additional post-quantum candidate) - FIPS 205.

The specification lists SLH-DSA as an additional candidate because it is
a *different* PQ signature family (stateless hash-based, FIPS 205) rather
than another lattice parameter set.  Decision recorded for this
workstream: **implement it** via the same ``pqcrypto`` backend so the
registry holds a working second PQ family, while keeping it secondary to
the primary RSA-4096 + ML-DSA construction.

Canonical encodings: raw FIPS 205 public/private key and signature bytes.
"""

from __future__ import annotations

from typing import ClassVar, Final

from pqcrypto import InvalidSignatureError
from pqcrypto.sign import (
    slh_dsa_sha2_128f,
    slh_dsa_sha2_128s,
    slh_dsa_sha2_192f,
    slh_dsa_sha2_192s,
    slh_dsa_sha2_256f,
    slh_dsa_sha2_256s,
    slh_dsa_shake_128f,
    slh_dsa_shake_128s,
    slh_dsa_shake_192f,
    slh_dsa_shake_192s,
    slh_dsa_shake_256f,
    slh_dsa_shake_256s,
)

from crypto.errors import (
    InvalidKeyError,
    MalformedSignatureError,
    ResourceLimitExceededError,
    SerializationError,
    SigningError,
)
from crypto.keys import KeyPair, PrivateKey, PublicKey

from crypto_agility.interfaces import CryptoProvider

#: canonical id -> (pqcrypto module, FIPS 205 parameter-set name, NIST category)
SLHDSA_PARAMETER_SETS: Final[dict[str, tuple]] = {
    "slhdsa-sha2-128s": (slh_dsa_sha2_128s, "SLH-DSA-SHA2-128s", "NIST category 1"),
    "slhdsa-sha2-128f": (slh_dsa_sha2_128f, "SLH-DSA-SHA2-128f", "NIST category 1"),
    "slhdsa-sha2-192s": (slh_dsa_sha2_192s, "SLH-DSA-SHA2-192s", "NIST category 3"),
    "slhdsa-sha2-192f": (slh_dsa_sha2_192f, "SLH-DSA-SHA2-192f", "NIST category 3"),
    "slhdsa-sha2-256s": (slh_dsa_sha2_256s, "SLH-DSA-SHA2-256s", "NIST category 5"),
    "slhdsa-sha2-256f": (slh_dsa_sha2_256f, "SLH-DSA-SHA2-256f", "NIST category 5"),
    "slhdsa-shake-128s": (slh_dsa_shake_128s, "SLH-DSA-SHAKE-128s", "NIST category 1"),
    "slhdsa-shake-128f": (slh_dsa_shake_128f, "SLH-DSA-SHAKE-128f", "NIST category 1"),
    "slhdsa-shake-192s": (slh_dsa_shake_192s, "SLH-DSA-SHAKE-192s", "NIST category 3"),
    "slhdsa-shake-192f": (slh_dsa_shake_192f, "SLH-DSA-SHAKE-192f", "NIST category 3"),
    "slhdsa-shake-256s": (slh_dsa_shake_256s, "SLH-DSA-SHAKE-256s", "NIST category 5"),
    "slhdsa-shake-256f": (slh_dsa_shake_256f, "SLH-DSA-SHAKE-256f", "NIST category 5"),
}


class SLHDSAProvider(CryptoProvider):
    """SLH-DSA (FIPS 205) provider, parameterized by parameter set."""

    family: ClassVar[str] = "pq"
    standard: ClassVar[str] = "FIPS 205 (SLH-DSA)"
    quantum_vulnerable: ClassVar[bool] = False
    backend: ClassVar[str] = "pqcrypto (Rust bindings)"

    def __init__(self, parameter_set: str = "slhdsa-sha2-128s") -> None:
        if parameter_set not in SLHDSA_PARAMETER_SETS:
            raise InvalidKeyError(
                f"unknown SLH-DSA parameter set {parameter_set!r}; "
                f"known sets: {sorted(SLHDSA_PARAMETER_SETS)}"
            )
        self._module, self._set_name, self._security_level = SLHDSA_PARAMETER_SETS[parameter_set]
        self.parameter_set = parameter_set

    @property
    def algorithm_id(self) -> str:  # type: ignore[override]
        return self.parameter_set

    @property
    def display_name(self) -> str:  # type: ignore[override]
        return self._set_name

    # -- key generation ----------------------------------------------------
    def generate_keypair(self) -> KeyPair:
        pk, sk = self._module.keygen()
        return KeyPair(
            algorithm=self.algorithm_id,
            private_key=PrivateKey(self.algorithm_id, sk),
            public_key=PublicKey(self.algorithm_id, pk),
        )

    # -- validation -----------------------------------------------------------
    def _validate_key(self, key: PrivateKey | PublicKey, kind: type) -> None:
        if not isinstance(key, kind):
            raise InvalidKeyError(f"key must be a crypto.keys {kind.__name__} object")
        if key.algorithm != self.algorithm_id:
            raise InvalidKeyError(
                f"key algorithm mismatch: provider is {self.algorithm_id!r}, key is {key.algorithm!r}"
            )
        expected = self._module.SECRET_KEY_SIZE if kind is PrivateKey else self._module.PUBLIC_KEY_SIZE
        if len(key.data) != expected:
            raise InvalidKeyError(
                f"malformed {self._set_name} {kind.__name__[:-4].lower()} key: "
                f"expected {expected} bytes, got {len(key.data)}"
            )

    # -- sign / verify ----------------------------------------------------------
    def sign(self, message: bytes, private_key: PrivateKey, context: bytes | None = None) -> bytes:
        self._validate_key(private_key, PrivateKey)
        if not isinstance(message, (bytes, bytearray)):
            raise SigningError("message must be bytes")
        from crypto.faults import check_message_size
        from crypto.encoding.contexts import validate_context

        message = check_message_size(bytes(message))
        context = validate_context(context)  # native FIPS 205 context string
        try:
            return self._module.sign(private_key.data, message, context=context)
        except ResourceLimitExceededError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise SigningError(f"SLH-DSA signing failed ({type(exc).__name__})") from None

    def verify(self, message: bytes, signature: bytes, public_key: PublicKey, context: bytes | None = None) -> bool:
        self._validate_key(public_key, PublicKey)
        if not isinstance(message, (bytes, bytearray)) or not isinstance(signature, (bytes, bytearray)):
            return False
        from crypto.faults import check_message_size
        from crypto.encoding.contexts import validate_context

        try:
            message = check_message_size(bytes(message))
        except ResourceLimitExceededError:
            return False
        context = validate_context(context)
        try:
            self._module.verify(public_key.data, message, bytes(signature), context=context)
            return True
        except InvalidSignatureError:
            return False
        except Exception:  # noqa: BLE001
            return False

    # -- serialization -------------------------------------------------------------
    def serialize_public_key(self, public_key: PublicKey) -> bytes:
        self._validate_key(public_key, PublicKey)
        if len(public_key.data) != self._module.PUBLIC_KEY_SIZE:
            raise InvalidKeyError(
                f"SLH-DSA public key must be {self._module.PUBLIC_KEY_SIZE} bytes, got {len(public_key.data)}"
            )
        return public_key.data

    def deserialize_public_key(self, data: bytes) -> PublicKey:
        if not isinstance(data, (bytes, bytearray)) or len(data) != self._module.PUBLIC_KEY_SIZE:
            raise SerializationError(
                f"SLH-DSA public key must be exactly {self._module.PUBLIC_KEY_SIZE} bytes"
            )
        return PublicKey(self.algorithm_id, bytes(data))

    def serialize_signature(self, signature: bytes) -> bytes:
        if not isinstance(signature, (bytes, bytearray)) or len(signature) != self._module.SIGNATURE_SIZE:
            raise MalformedSignatureError(
                f"SLH-DSA signature must be exactly {self._module.SIGNATURE_SIZE} bytes"
            )
        return bytes(signature)

    def deserialize_signature(self, data: bytes) -> bytes:
        return self.serialize_signature(data)

    # -- sizes / capabilities -----------------------------------------------------------
    def public_key_size(self) -> int:
        return self._module.PUBLIC_KEY_SIZE

    def signature_size(self) -> int:
        return self._module.SIGNATURE_SIZE

    def secret_key_size(self) -> int:
        return self._module.SECRET_KEY_SIZE

    def capabilities(self) -> "object":
        from crypto_agility.interfaces import ProviderCapabilities

        return ProviderCapabilities(
            algorithm_id=self.algorithm_id,
            display_name=self.display_name,
            family=self.family,
            standard=self.standard,
            parameter_set=self._set_name,
            backend=self.backend,
            quantum_vulnerable=self.quantum_vulnerable,
            implemented=True,
            public_key_size=self.public_key_size(),
            secret_key_size=self.secret_key_size(),
            signature_size=self.signature_size(),
            security_level=self._security_level,
        )

"""ML-DSA provider (primary post-quantum component) - FIPS 204.

Parameter sets are recorded explicitly in the provider configuration and
carried in the canonical algorithm id (``mldsa44`` / ``mldsa65`` /
``mldsa87``), so a key generated for one parameter set can never be used
with another: every operation validates ``key.algorithm ==
provider.algorithm_id``.

Canonical encodings:

* public key  - raw FIPS 204 public-key bytes (fixed length per set)
* private key - raw FIPS 204 private-key bytes
* signature   - raw FIPS 204 signature bytes (fixed length per set)

Backend: ``pqcrypto`` (compiled Rust bindings to a maintained FIPS 204
implementation).  No primitive is hand-written.
"""

from __future__ import annotations

from typing import ClassVar, Final

from pqcrypto import InvalidSignatureError
from pqcrypto.sign import ml_dsa_44, ml_dsa_65, ml_dsa_87

from crypto.errors import (
    InvalidKeyError,
    MalformedSignatureError,
    ResourceLimitExceededError,
    SerializationError,
    SigningError,
)
from crypto.keys import KeyPair, PrivateKey, PublicKey

from crypto_agility.interfaces import CryptoProvider

#: canonical id -> (pqcrypto module, FIPS 204 parameter-set name, NIST category)
MLDSA_PARAMETER_SETS: Final[dict[str, tuple]] = {
    "mldsa44": (ml_dsa_44, "ML-DSA-44", "NIST category 2"),
    "mldsa65": (ml_dsa_65, "ML-DSA-65", "NIST category 3"),
    "mldsa87": (ml_dsa_87, "ML-DSA-87", "NIST category 5"),
}


class MLDSAProvider(CryptoProvider):
    """ML-DSA (FIPS 204) provider, parameterized by parameter set."""

    family: ClassVar[str] = "pq"
    standard: ClassVar[str] = "FIPS 204 (ML-DSA)"
    quantum_vulnerable: ClassVar[bool] = False
    backend: ClassVar[str] = "pqcrypto (Rust bindings)"

    def __init__(self, parameter_set: str = "mldsa65") -> None:
        if parameter_set not in MLDSA_PARAMETER_SETS:
            raise InvalidKeyError(
                f"unknown ML-DSA parameter set {parameter_set!r}; "
                f"known sets: {sorted(MLDSA_PARAMETER_SETS)}"
            )
        self._module, self._set_name, self._security_level = MLDSA_PARAMETER_SETS[parameter_set]
        self.parameter_set = parameter_set

    # class-level defaults are overridden per instance for these three:
    @property
    def algorithm_id(self) -> str:  # type: ignore[override]
        return self.parameter_set

    @property
    def display_name(self) -> str:  # type: ignore[override]
        return self._set_name

    # -- key generation -----------------------------------------------------
    def generate_keypair(self) -> KeyPair:
        pk, sk = self._module.keygen()
        return KeyPair(
            algorithm=self.algorithm_id,
            private_key=PrivateKey(self.algorithm_id, sk),
            public_key=PublicKey(self.algorithm_id, pk),
        )

    # -- validation ----------------------------------------------------------
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

    # -- sign / verify ---------------------------------------------------------
    def sign(self, message: bytes, private_key: PrivateKey, context: bytes | None = None) -> bytes:
        self._validate_key(private_key, PrivateKey)
        if not isinstance(message, (bytes, bytearray)):
            raise SigningError("message must be bytes")
        from crypto.faults import check_message_size
        from crypto.encoding.contexts import validate_context

        message = check_message_size(bytes(message))
        context = validate_context(context)  # native FIPS 204 context string
        try:
            return self._module.sign(private_key.data, message, context=context)
        except ResourceLimitExceededError:
            raise
        except Exception as exc:  # noqa: BLE001 - sanitized; never includes key bytes
            raise SigningError(f"ML-DSA signing failed ({type(exc).__name__})") from None

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
        except Exception:  # noqa: BLE001 - wrong lengths etc. -> not verified
            return False

    # -- serialization -----------------------------------------------------------
    def serialize_public_key(self, public_key: PublicKey) -> bytes:
        self._validate_key(public_key, PublicKey)
        if len(public_key.data) != self._module.PUBLIC_KEY_SIZE:
            raise InvalidKeyError(
                f"ML-DSA public key must be {self._module.PUBLIC_KEY_SIZE} bytes, got {len(public_key.data)}"
            )
        return public_key.data

    def deserialize_public_key(self, data: bytes) -> PublicKey:
        if not isinstance(data, (bytes, bytearray)) or len(data) != self._module.PUBLIC_KEY_SIZE:
            raise SerializationError(
                f"ML-DSA public key must be exactly {self._module.PUBLIC_KEY_SIZE} bytes"
            )
        return PublicKey(self.algorithm_id, bytes(data))

    def serialize_signature(self, signature: bytes) -> bytes:
        if not isinstance(signature, (bytes, bytearray)) or len(signature) != self._module.SIGNATURE_SIZE:
            raise MalformedSignatureError(
                f"ML-DSA signature must be exactly {self._module.SIGNATURE_SIZE} bytes"
            )
        return bytes(signature)

    def deserialize_signature(self, data: bytes) -> bytes:
        return self.serialize_signature(data)

    # -- sizes / capabilities ---------------------------------------------------------
    def public_key_size(self) -> int:
        return self._module.PUBLIC_KEY_SIZE

    def signature_size(self) -> int:
        return self._module.SIGNATURE_SIZE

    def secret_key_size(self) -> int:
        return self._module.SECRET_KEY_SIZE

    def capabilities(self) -> "object":  # narrow to ProviderCapabilities
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

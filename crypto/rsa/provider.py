"""RSA-4096 provider (classical component of the hybrid construction).

Scheme (explicit, not implicit - per the specification's implementation
note): **RSASSA-PSS** with SHA-256, MGF1-SHA-256 and a salt length equal
to the digest size (32 bytes), public exponent 65537, key size fixed at
4096 bits.  Implemented with the maintained ``cryptography`` library;
no primitive is hand-written.

Canonical encodings:

* public key  - DER ``SubjectPublicKeyInfo``
* private key - PKCS#8 DER (unencrypted; encryption is a storage concern,
  see :mod:`crypto.keys.storage`)
* signature   - raw DER RSASSA-PSS signature bytes (already deterministic)
"""

from __future__ import annotations

from typing import ClassVar, Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_der_private_key,
    load_der_public_key,
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

ALGORITHM_ID: Final = "rsa4096"

_MAX_SIGNATURE_BYTES = 8192  # sanity bound for deserialize_signature


def _pss_padding() -> padding.PSS:
    # Salt length == SHA-256 digest length (32 bytes); documented scheme.
    return padding.PSS(mgf=padding.MGF1(algorithm=hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH)


def _with_context(message: bytes, context: bytes | None) -> bytes:
    """Bind an optional domain-separation context into the signed input.

    RSA-PSS has no native context string (unlike FIPS 204/205), so the
    context is length-prefixed in front of the message: the signed input
    is ``u16(len(context)) || context || message``.  Length-prefixing
    keeps the mapping injective (no concatenation ambiguity).
    """
    if context is None:
        return message
    from crypto.encoding.contexts import validate_context

    context = validate_context(context)
    return len(context).to_bytes(2, "big") + context + message


class RSA4096Provider(CryptoProvider):
    """RSA-4096 signing via RSASSA-PSS (SHA-256)."""

    algorithm_id: ClassVar[str] = ALGORITHM_ID
    display_name: ClassVar[str] = "RSA-4096"
    family: ClassVar[str] = "classical"
    standard: ClassVar[str] = "FIPS 186-5 / PKCS #1 v2.2 RSASSA-PSS"
    parameter_set: ClassVar[str] = "RSA-4096; RSASSA-PSS, SHA-256, MGF1-SHA-256, salt=32"
    quantum_vulnerable: ClassVar[bool] = True
    backend: ClassVar[str] = "cryptography (OpenSSL backend)"

    KEY_SIZE_BITS: ClassVar[int] = 4096
    PUBLIC_EXPONENT: ClassVar[int] = 65537

    # -- key generation ---------------------------------------------------
    def generate_keypair(self) -> KeyPair:
        private_key = rsa.generate_private_key(public_exponent=self.PUBLIC_EXPONENT, key_size=self.KEY_SIZE_BITS)
        private_der = private_key.private_bytes(
            encoding=Encoding.DER, format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption()
        )
        public_der = private_key.public_key().public_bytes(
            encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo
        )
        return KeyPair(
            algorithm=self.algorithm_id,
            private_key=PrivateKey(self.algorithm_id, private_der),
            public_key=PublicKey(self.algorithm_id, public_der),
        )

    # -- internal loading/validation ---------------------------------------
    def _load_private(self, private_key: PrivateKey) -> rsa.RSAPrivateKey:
        if not isinstance(private_key, PrivateKey):
            raise InvalidKeyError("private_key must be a crypto.keys PrivateKey object")
        if private_key.algorithm != self.algorithm_id:
            raise InvalidKeyError(
                f"key algorithm mismatch: provider is {self.algorithm_id!r}, key is {private_key.algorithm!r}"
            )
        try:
            key = load_der_private_key(private_key.data, password=None)
        except Exception as exc:  # noqa: BLE001 - normalized, no key material in message
            raise InvalidKeyError(f"malformed RSA private key ({type(exc).__name__})") from None
        if not isinstance(key, rsa.RSAPrivateKey) or key.key_size != self.KEY_SIZE_BITS:
            raise InvalidKeyError(f"RSA provider requires a {self.KEY_SIZE_BITS}-bit RSA private key")
        return key

    def _load_public(self, public_key: PublicKey) -> rsa.RSAPublicKey:
        if not isinstance(public_key, PublicKey):
            raise InvalidKeyError("public_key must be a crypto.keys PublicKey object")
        if public_key.algorithm != self.algorithm_id:
            raise InvalidKeyError(
                f"key algorithm mismatch: provider is {self.algorithm_id!r}, key is {public_key.algorithm!r}"
            )
        try:
            key = load_der_public_key(public_key.data)
        except Exception as exc:  # noqa: BLE001
            raise InvalidKeyError(f"malformed RSA public key ({type(exc).__name__})") from None
        if not isinstance(key, rsa.RSAPublicKey) or key.key_size != self.KEY_SIZE_BITS:
            raise InvalidKeyError(f"RSA provider requires a {self.KEY_SIZE_BITS}-bit RSA public key")
        return key

    # -- sign / verify ------------------------------------------------------
    def sign(self, message: bytes, private_key: PrivateKey, context: bytes | None = None) -> bytes:
        if not isinstance(message, (bytes, bytearray)):
            raise SigningError("message must be bytes")
        from crypto.faults import check_message_size

        message = check_message_size(bytes(message))
        key = self._load_private(private_key)
        try:
            return key.sign(_with_context(message, context), _pss_padding(), hashes.SHA256())
        except ResourceLimitExceededError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise SigningError(f"RSA signing failed ({type(exc).__name__})") from None

    def verify(self, message: bytes, signature: bytes, public_key: PublicKey, context: bytes | None = None) -> bool:
        if not isinstance(message, (bytes, bytearray)) or not isinstance(signature, (bytes, bytearray)):
            return False
        from crypto.faults import check_message_size

        try:
            message = check_message_size(bytes(message))
        except ResourceLimitExceededError:
            return False  # oversized input can never match a signature: fail closed
        key = self._load_public(public_key)  # malformed key -> InvalidKeyError
        try:
            key.verify(bytes(signature), _with_context(message, context), _pss_padding(), hashes.SHA256())
            return True
        except InvalidSignature:
            return False
        except Exception:  # noqa: BLE001 - structurally impossible signature -> not verified
            return False

    # -- serialization --------------------------------------------------------
    def serialize_public_key(self, public_key: PublicKey) -> bytes:
        key = self._load_public(public_key)
        return key.public_bytes(encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo)

    def deserialize_public_key(self, data: bytes) -> PublicKey:
        if not isinstance(data, (bytes, bytearray)) or not data:
            raise SerializationError("RSA public key data must be non-empty bytes")
        try:
            key = load_der_public_key(bytes(data))
        except Exception as exc:  # noqa: BLE001
            raise SerializationError(f"malformed RSA public key encoding ({type(exc).__name__})") from None
        if not isinstance(key, rsa.RSAPublicKey) or key.key_size != self.KEY_SIZE_BITS:
            raise InvalidKeyError(f"expected a {self.KEY_SIZE_BITS}-bit RSA public key")
        return PublicKey(self.algorithm_id, bytes(data))

    def serialize_signature(self, signature: bytes) -> bytes:
        if not isinstance(signature, (bytes, bytearray)) or not signature:
            raise MalformedSignatureError("RSA signature must be non-empty bytes")
        if len(signature) > _MAX_SIGNATURE_BYTES:
            raise MalformedSignatureError("RSA signature exceeds maximum plausible size")
        return bytes(signature)

    def deserialize_signature(self, data: bytes) -> bytes:
        return self.serialize_signature(data)

    # -- sizes -----------------------------------------------------------------
    def public_key_size(self) -> int:
        # DER SPKI for a 4096-bit modulus with a 3-byte exponent.
        return 550

    def signature_size(self) -> int:
        return 512  # 4096-bit modulus

    def secret_key_size(self) -> int:
        return 3275  # PKCS#8 DER, typical

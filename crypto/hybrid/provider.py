"""Adapter that exposes the hybrid construction through the common
CryptoProvider interface.

Why: the crypto-agility layer (phase 4) selects a provider per configured
mode - classical, PQ **or hybrid** - and the platform code should not
need algorithm-specific branches.  With this adapter, "the hybrid path"
is just another registered provider whose keys/signatures happen to be
composites.

Composite encodings (canonical JSON, fixed field order):

* public key  :: {"rsa": b64(SPKI DER), "mldsa": b64(raw FIPS 204 pk)}
* private key :: {"rsa": b64(PKCS#8 DER), "mldsa": b64(raw FIPS 204 sk)}
* signature   :: the canonical JSON hybrid signature (see
  :meth:`crypto.hybrid.signature.HybridSignature.to_json_bytes`)
"""

from __future__ import annotations

import base64
import binascii
import json
from typing import ClassVar

from crypto.errors import (
    InvalidKeyError,
    MalformedSignatureError,
    SerializationError,
    SigningError,
)
from crypto.keys import KeyPair, PrivateKey, PublicKey
from crypto_agility.interfaces import CryptoProvider

from .signature import HYBRID_ALGORITHM_ID, HybridSignature
from .signer import HybridSigner
from .verifier import HybridAcceptancePolicy, HybridVerifier

_COMPOSITE_FIELDS = ("rsa", "mldsa")


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(text: str) -> bytes:
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError, TypeError):
        raise SerializationError("composite key component is not valid base64") from None


def _parse_composite(data: bytes, kind: str) -> dict:
    try:
        obj = json.loads(bytes(data).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise SerializationError(f"composite {kind} is not valid JSON") from None
    if not isinstance(obj, dict) or any(k not in obj for k in _COMPOSITE_FIELDS):
        raise SerializationError(f"composite {kind} must be a JSON object with fields {_COMPOSITE_FIELDS}")
    return obj


class HybridCryptoProvider(CryptoProvider):
    """RSA4096-MLDSA hybrid as a single provider behind the common interface."""

    algorithm_id: ClassVar[str] = HYBRID_ALGORITHM_ID
    display_name: ClassVar[str] = "RSA-4096 + ML-DSA (hybrid)"
    family: ClassVar[str] = "hybrid"
    standard: ClassVar[str] = "RFC 9794 PQ/T terminology; parallel/composite construction"
    parameter_set: ClassVar[str] = "RSA-4096 (RSASSA-PSS SHA-256) + ML-DSA-65 (FIPS 204)"
    # The composite as a whole is not defeated by a quantum adversary on
    # its own: the ML-DSA component remains hard.  The classical half
    # *is* quantum-vulnerable, which the capability note spells out.
    quantum_vulnerable: ClassVar[bool] = False
    backend: ClassVar[str] = "cryptography + pqcrypto (composite)"

    def __init__(
        self,
        classical_provider: CryptoProvider,
        pq_provider: CryptoProvider,
        policy: HybridAcceptancePolicy = HybridAcceptancePolicy.STRICT_TWO_COMPONENT,
    ) -> None:
        self._signer = HybridSigner(classical_provider, pq_provider, HYBRID_ALGORITHM_ID)
        self._verifier = HybridVerifier(classical_provider, pq_provider, HYBRID_ALGORITHM_ID, policy)
        self._classical = classical_provider
        self._pq = pq_provider

    # -- composite key (de)serialization helpers ---------------------------- #
    def _pack_key(self, rsa_data: bytes, mldsa_data: bytes) -> bytes:
        return json.dumps(
            {"rsa": _b64(rsa_data), "mldsa": _b64(mldsa_data)}, separators=(",", ":")
        ).encode("utf-8")

    def _unpack_private(self, private_key: PrivateKey) -> tuple[PrivateKey, PrivateKey]:
        if not isinstance(private_key, PrivateKey) or private_key.algorithm != self.algorithm_id:
            raise InvalidKeyError(f"expected a composite {self.algorithm_id} PrivateKey")
        obj = _parse_composite(private_key.data, "private key")
        return (
            PrivateKey(self._classical.algorithm_id, _unb64(obj["rsa"])),
            PrivateKey(self._pq.algorithm_id, _unb64(obj["mldsa"])),
        )

    def _unpack_public(self, public_key: PublicKey) -> tuple[PublicKey, PublicKey]:
        if not isinstance(public_key, PublicKey) or public_key.algorithm != self.algorithm_id:
            raise InvalidKeyError(f"expected a composite {self.algorithm_id} PublicKey")
        obj = _parse_composite(public_key.data, "public key")
        return (
            PublicKey(self._classical.algorithm_id, _unb64(obj["rsa"])),
            PublicKey(self._pq.algorithm_id, _unb64(obj["mldsa"])),
        )

    # -- CryptoProvider implementation --------------------------------------- #
    def generate_keypair(self) -> KeyPair:
        classical_kp = self._classical.generate_keypair()
        pq_kp = self._pq.generate_keypair()
        return KeyPair(
            algorithm=self.algorithm_id,
            private_key=PrivateKey(
                self.algorithm_id,
                self._pack_key(classical_kp.private_key.data, pq_kp.private_key.data),
            ),
            public_key=PublicKey(
                self.algorithm_id,
                self._pack_key(classical_kp.public_key.data, pq_kp.public_key.data),
            ),
        )

    def sign(self, message: bytes, private_key: PrivateKey, context: bytes | None = None) -> bytes:
        if not isinstance(message, (bytes, bytearray)):
            raise SigningError("message must be bytes")
        classical_sk, pq_sk = self._unpack_private(private_key)
        hybrid_sig = self._signer.sign(bytes(message), classical_sk, pq_sk, context=context)
        return hybrid_sig.to_json_bytes()

    def verify(self, message: bytes, signature: bytes, public_key: PublicKey, context: bytes | None = None) -> bool:
        if not isinstance(message, (bytes, bytearray)) or not isinstance(signature, (bytes, bytearray)):
            return False
        classical_pk, pq_pk = self._unpack_public(public_key)
        result = self._verifier.verify(bytes(message), bytes(signature), classical_pk, pq_pk, context=context)
        return result.accepted

    def verify_detailed(
        self,
        message: bytes,
        signature: bytes,
        public_key: PublicKey,
        context: bytes | None = None,
        timeout_s: float | None = None,
    ):
        """Full :class:`VerificationResult` with component diagnostics
        (preferred API for the PKI layer after integration)."""
        classical_pk, pq_pk = self._unpack_public(public_key)
        return self._verifier.verify(
            bytes(message), bytes(signature), classical_pk, pq_pk, context=context, timeout_s=timeout_s
        )

    # -- serialization ---------------------------------------------------------- #
    def serialize_public_key(self, public_key: PublicKey) -> bytes:
        classical_pk, pq_pk = self._unpack_public(public_key)
        return self._pack_key(
            self._classical.serialize_public_key(classical_pk),
            self._pq.serialize_public_key(pq_pk),
        )

    def deserialize_public_key(self, data: bytes) -> PublicKey:
        obj = _parse_composite(data, "public key")
        classical_pk = self._classical.deserialize_public_key(_unb64(obj["rsa"]))
        pq_pk = self._pq.deserialize_public_key(_unb64(obj["mldsa"]))
        return PublicKey(self.algorithm_id, self._pack_key(classical_pk.data, pq_pk.data))

    def serialize_signature(self, signature: bytes) -> bytes:
        # validate by parsing; canonical form is already deterministic
        try:
            HybridSignature.from_json_bytes(bytes(signature))
        except MalformedSignatureError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise MalformedSignatureError(f"invalid hybrid signature ({type(exc).__name__})") from None
        return bytes(signature)

    def deserialize_signature(self, data: bytes) -> bytes:
        return self.serialize_signature(data)

    # -- sizes / capabilities ------------------------------------------------------ #
    def public_key_size(self) -> int:
        return self._classical.public_key_size() + self._pq.public_key_size()

    def signature_size(self) -> int:
        # JSON overhead: fields + base64 expansion (~4/3 * raw)
        raw = self._classical.signature_size() + self._pq.signature_size()
        return raw + (raw + 2) // 3 + 96

    def secret_key_size(self) -> int:
        return self._classical.secret_key_size() + self._pq.secret_key_size()

    def capabilities(self):
        from crypto_agility.interfaces import ProviderCapabilities

        return ProviderCapabilities(
            algorithm_id=self.algorithm_id,
            display_name=self.display_name,
            family=self.family,
            standard=self.standard,
            parameter_set=self.parameter_set,
            backend=self.backend,
            quantum_vulnerable=False,
            implemented=True,
            public_key_size=self.public_key_size(),
            secret_key_size=self.secret_key_size(),
            signature_size=self.signature_size(),
            security_level="max(classical 152-bit, PQ NIST category 3)",
            notes=(
                "Composite: classical RSA-4096 component is quantum-vulnerable; "
                "security against a cryptographically relevant quantum computer comes "
                "from the ML-DSA component (both must verify - strict two-component policy)."
            ),
        )

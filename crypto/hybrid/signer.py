"""Hybrid signing: one message, two independent component signatures."""

from __future__ import annotations

from crypto.errors import SigningError
from crypto.keys import PrivateKey
from crypto_agility.interfaces import CryptoProvider

from .signature import HYBRID_ALGORITHM_ID, SUPPORTED_HYBRID_ALGORITHMS, HybridSignature


class HybridSigner:
    """Generates the RSA and ML-DSA signatures over the same message and
    packages them into a :class:`HybridSignature`.

    Failure semantics: if *either* component signing operation fails, the
    exception propagates and **no** hybrid signature object is returned -
    a caller can never mistake a one-component result for a success.
    """

    def __init__(
        self,
        classical_provider: CryptoProvider,
        pq_provider: CryptoProvider,
        algorithm_id: str = HYBRID_ALGORITHM_ID,
    ) -> None:
        if algorithm_id not in SUPPORTED_HYBRID_ALGORITHMS:
            raise SigningError(
                f"unsupported hybrid algorithm identifier {algorithm_id!r}; "
                f"supported: {list(SUPPORTED_HYBRID_ALGORITHMS)}"
            )
        if classical_provider.family != "classical":
            raise SigningError(
                f"classical provider must have family 'classical', got {classical_provider.family!r}"
            )
        if pq_provider.family != "pq":
            raise SigningError(f"PQ provider must have family 'pq', got {pq_provider.family!r}")
        self._classical = classical_provider
        self._pq = pq_provider
        self.algorithm_id = algorithm_id

    @property
    def classical_provider(self) -> CryptoProvider:
        return self._classical

    @property
    def pq_provider(self) -> CryptoProvider:
        return self._pq

    def sign(
        self,
        message: bytes,
        classical_private_key: PrivateKey,
        pq_private_key: PrivateKey,
        context: bytes | None = None,
    ) -> HybridSignature:
        if not isinstance(message, (bytes, bytearray)):
            raise SigningError("message must be bytes")
        # fail fast with a clear, key-material-free error before invoking
        # the component providers
        if not isinstance(classical_private_key, PrivateKey) or classical_private_key.algorithm != self._classical.algorithm_id:
            raise SigningError(
                f"classical slot requires a {self._classical.algorithm_id!r} private key "
                f"(got {getattr(classical_private_key, 'algorithm', type(classical_private_key).__name__)!r})"
            )
        if not isinstance(pq_private_key, PrivateKey) or pq_private_key.algorithm != self._pq.algorithm_id:
            raise SigningError(
                f"PQ slot requires a {self._pq.algorithm_id!r} private key "
                f"(got {getattr(pq_private_key, 'algorithm', type(pq_private_key).__name__)!r})"
            )
        message = bytes(message)

        rsa_sig = self._classical.sign(message, classical_private_key, context=context)
        mldsa_sig = self._pq.sign(message, pq_private_key, context=context)

        # Component providers raise on failure, so reaching this point
        # means both signatures exist; still, never package empties.
        if not rsa_sig or not mldsa_sig:
            raise SigningError("component signature was empty; refusing to build hybrid signature")

        return HybridSignature(
            algorithm=self.algorithm_id,
            rsa_signature=rsa_sig,
            mldsa_signature=mldsa_sig,
        )

    def sign_serialized(
        self,
        message: bytes,
        classical_private_key: PrivateKey,
        pq_private_key: PrivateKey,
        context: bytes | None = None,
    ) -> bytes:
        """Convenience: canonical JSON wire bytes of the hybrid signature."""
        return self.sign(message, classical_private_key, pq_private_key, context=context).to_json_bytes()

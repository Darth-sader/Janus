"""The CryptoProvider contract - the foundation of crypto-agility.

This is the single common interface named in the Technical Design
Specification (section 5.1).  Every algorithm provider - classical
(RSA-4096) and post-quantum (ML-DSA, SLH-DSA) - implements exactly this
interface, so the application can invoke cryptography without knowing
which algorithm is behind it.

Contract rules every provider must honor
========================================

1. ``verify()`` is a *predicate*: it returns ``True``/``False`` and never
   raises merely because a well-formed signature did not verify.
2. Malformed *inputs* (keys of the wrong type/size/parameter set,
   structurally invalid signatures) raise the package error types from
   :mod:`crypto.errors` - never a third-party exception.
3. Error messages never contain private-key material or raw key/signature
   bytes.
4. Keys and signatures passed between layers are the algorithm-tagged
   value types from :mod:`crypto.keys`, and every provider's
   serialization functions are deterministic (same input -> same bytes).
5. A provider must not silently accept keys produced by a different
   algorithm or parameter set (key.algorithm must match
   ``cls.algorithm_id``).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from crypto.keys import KeyPair, PrivateKey, PublicKey

from .capabilities import ProviderCapabilities


class CryptoProvider(ABC):
    """Abstract base class implemented by every algorithm provider."""

    #: Canonical algorithm identifier (see docs/algorithm_identifiers).
    algorithm_id: ClassVar[str]
    #: Human-readable name, e.g. ``"RSA-4096"``.
    display_name: ClassVar[str]
    #: ``"classical"`` or ``"pq"`` (hybrid uses ``"hybrid"``).
    family: ClassVar[str]
    #: Standard(s) the implementation conforms to.
    standard: ClassVar[str]
    #: Parameter set / scheme identifier recorded in provider config.
    parameter_set: ClassVar[str]
    #: Whether the algorithm is broken by a cryptographically relevant
    #: quantum computer (classical public-key algorithms: yes).
    quantum_vulnerable: ClassVar[bool]
    #: Backend/library actually performing the primitive operations.
    backend: ClassVar[str]

    # -- core operations ------------------------------------------------
    @abstractmethod
    def generate_keypair(self) -> KeyPair:
        """Generate a new key pair for this algorithm."""

    @abstractmethod
    def sign(self, message: bytes, private_key: PrivateKey, context: bytes | None = None) -> bytes:
        """Sign ``message`` with ``private_key``; returns the signature bytes.

        ``context`` (optional) is a registered domain-separation label
        (:mod:`crypto.encoding.contexts`) that becomes part of the exact
        signed input - a signature made under one context does not verify
        under another.  Implementations either bind the context natively
        (FIPS 204/205 context strings) or by length-prefixing it into the
        signed input (RSA-PSS).

        Raises InvalidKeyError if the key does not belong to this
        algorithm, SigningError if the signing operation itself fails,
        ResourceLimitExceededError for oversized messages.
        """

    @abstractmethod
    def verify(self, message: bytes, signature: bytes, public_key: PublicKey, context: bytes | None = None) -> bool:
        """Return ``True`` iff ``signature`` verifies over ``message`` under
        ``public_key`` (and ``context``, if given).

        Raises InvalidKeyError for malformed/mismatched keys; returns
        ``False`` for any well-formed-but-incorrect signature.
        """

    # -- serialization ---------------------------------------------------
    @abstractmethod
    def serialize_public_key(self, public_key: PublicKey) -> bytes:
        """Deterministic wire bytes for ``public_key``."""

    @abstractmethod
    def deserialize_public_key(self, data: bytes) -> PublicKey:
        """Parse wire bytes back into a :class:`PublicKey`.

        Raises SerializationError/InvalidKeyError on malformed input.
        """

    @abstractmethod
    def serialize_signature(self, signature: bytes) -> bytes:
        """Deterministic wire bytes for a signature of this algorithm."""

    @abstractmethod
    def deserialize_signature(self, data: bytes) -> bytes:
        """Parse wire bytes back into raw signature bytes accepted by
        :meth:`verify`.  Raises MalformedSignatureError on bad input."""

    # -- capabilities ----------------------------------------------------
    @abstractmethod
    def public_key_size(self) -> int:
        """Expected public-key size in bytes (typical value)."""

    @abstractmethod
    def signature_size(self) -> int:
        """Expected signature size in bytes (typical value)."""

    @abstractmethod
    def secret_key_size(self) -> int:
        """Expected private-key size in bytes (typical value)."""

    def capabilities(self) -> ProviderCapabilities:
        """Describe this provider's capabilities for the registry and the
        migration platform (see crypto_agility.migration_logic)."""
        return ProviderCapabilities(
            algorithm_id=self.algorithm_id,
            display_name=self.display_name,
            family=self.family,
            standard=self.standard,
            parameter_set=self.parameter_set,
            backend=self.backend,
            quantum_vulnerable=self.quantum_vulnerable,
            implemented=True,
            public_key_size=self.public_key_size(),
            secret_key_size=self.secret_key_size(),
            signature_size=self.signature_size(),
        )

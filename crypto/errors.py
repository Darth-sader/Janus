"""Exception hierarchy for the cryptography layer.

Rules that apply to every error raised from this package:

1. Error messages never contain private-key material, raw key bytes or
   signature bytes.  Only algorithm identifiers, lengths and reasons.
2. A *failed verification* is not an exception: ``verify()`` returns
   ``False``.  Exceptions are reserved for malformed inputs, unsupported
   operations and configuration problems, so callers can distinguish
   "the signature is wrong" from "the request itself is invalid".
3. Underlying library exceptions are caught and re-raised as one of the
   types below so the rest of the application never sees third-party
   exception classes (crypto-agility: swapping a provider must not
   change the application's error handling).
"""


class CryptoError(Exception):
    """Base class for every error raised by the cryptography layer."""


class UnsupportedAlgorithmError(CryptoError):
    """An algorithm identifier is unknown to the registry/provider.

    Raised instead of silently falling back to a different algorithm.
    """


class ProviderUnavailableError(CryptoError):
    """The algorithm is known (registered as a candidate) but has no
    usable implementation in this deployment."""


class InvalidKeyError(CryptoError):
    """A key is malformed, of the wrong type, or of the wrong size/parameter set."""


class MalformedSignatureError(CryptoError):
    """A signature blob is structurally invalid (wrong length, bad
    encoding, missing hybrid component, ...).

    Note: this is *not* raised when a well-formed signature simply does
    not verify - that path returns ``False`` from ``verify()``.
    """


class SigningError(CryptoError):
    """A signing operation failed (the reason is sanitized)."""


class SerializationError(CryptoError):
    """Serializing or deserializing an internal object failed."""


class ConfigurationError(CryptoError):
    """A crypto-agility configuration is invalid or inconsistent
    (unknown mode, unavailable algorithm for the requested mode, ...)."""


class ResourceLimitExceededError(CryptoError):
    """An input exceeds a configured resource limit (message size,
    serialized object size, nesting depth, field count, ...).

    Fail-closed: oversized input is rejected before any cryptographic
    operation sees it."""


class PolicyViolationError(CryptoError):
    """A cryptographic operation was blocked by the algorithm/parameter-set
    policy engine.  Carries a machine-readable decision record."""

    def __init__(self, message: str, decision: dict | None = None) -> None:
        super().__init__(message)
        self.decision: dict = decision or {}


class NegotiationError(CryptoError):
    """A hybrid negotiation was rejected.

    ``category`` distinguishes security-relevant rejection classes, in
    particular an explicit DOWNGRADE_ATTEMPT from an authorized-legacy
    request."""

    def __init__(self, message: str, category: str = "REJECTED") -> None:
        super().__init__(message)
        self.category = category


class KeyStateError(CryptoError):
    """A key-lifecycle operation is not permitted in the key's current
    state (e.g. signing with a retired key)."""


class KeyCompromisedError(KeyStateError):
    """The referenced key is marked COMPROMISED."""

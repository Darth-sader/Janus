"""Reusable verification result types and helpers.

Both the hybrid signature verifier and (after integration) Ayanna's
certificate validation report through these types, so callers always see
the same shape: an overall accept/reject plus per-component diagnostics.
Diagnostics strings are sanitized by construction - providers never put
key material into exceptions, and these helpers only carry statuses and
short reasons.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from crypto.errors import CryptoError, InvalidKeyError
from crypto.keys import PublicKey
from crypto_agility.interfaces import CryptoProvider


class VerificationStatus(str, Enum):
    """Per-component outcome of a verification."""

    VERIFIED = "VERIFIED"
    INVALID = "INVALID"                        # well-formed but did not verify
    MISSING = "MISSING"                        # component absent
    MALFORMED = "MALFORMED"                    # structurally broken input
    UNSUPPORTED_ALGORITHM = "UNSUPPORTED_ALGORITHM"
    KEY_MISMATCH = "KEY_MISMATCH"              # key does not belong to this component
    ERROR = "ERROR"                            # unexpected internal failure (sanitized)


@dataclass(frozen=True)
class ComponentResult:
    """Diagnostic result for one signature component."""

    component: str                # e.g. "rsa_signature" or "mldsa_signature"
    status: VerificationStatus
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.status is VerificationStatus.VERIFIED

    def to_dict(self) -> dict:
        return {"component": self.component, "status": self.status.value, "detail": self.detail}


@dataclass(frozen=True)
class VerificationResult:
    """Overall verification outcome plus component-level diagnostics."""

    accepted: bool
    subject: str                  # what was verified, e.g. "hybrid-signature:RSA4096-MLDSA"
    policy: str                   # acceptance policy id that was applied
    components: tuple[ComponentResult, ...] = ()
    reason: str = ""

    def to_dict(self) -> dict:
        return {
            "accepted": self.accepted,
            "subject": self.subject,
            "policy": self.policy,
            "reason": self.reason,
            "components": [c.to_dict() for c in self.components],
        }


def check_with_provider(
    provider: CryptoProvider,
    message: bytes,
    signature: bytes,
    public_key: PublicKey,
    component: str,
    context: bytes | None = None,
    timeout_s: float | None = None,
) -> ComponentResult:
    """Run one provider verification and translate every failure mode
    into a :class:`ComponentResult`.

    Contract: only ``VERIFIED`` counts as success; everything else is a
    diagnostic.  Key-material-free detail strings only.  Exceptions,
    timeouts and provider crashes are fail-closed: they become ERROR
    results, never acceptance.
    """
    if public_key.algorithm != provider.algorithm_id:
        return ComponentResult(
            component,
            VerificationStatus.KEY_MISMATCH,
            detail=f"public key algorithm {public_key.algorithm!r} does not match "
            f"component algorithm {provider.algorithm_id!r}",
        )

    from crypto.faults import verify_fail_closed

    result, diagnostic = verify_fail_closed(
        lambda: provider.verify(message, signature, public_key, context=context), timeout_s
    )
    if result is None:
        return ComponentResult(component, VerificationStatus.ERROR, detail=diagnostic or "verification failed")
    if result is True:
        return ComponentResult(component, VerificationStatus.VERIFIED)
    if result is False:
        return ComponentResult(component, VerificationStatus.INVALID, detail="signature did not verify")
    # provider returned something other than a bool - treat as failure
    return ComponentResult(component, VerificationStatus.ERROR, detail="provider returned invalid result type")

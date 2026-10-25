"""Hybrid verification with an explicit, documented acceptance policy."""

from __future__ import annotations

from enum import Enum

from crypto.errors import MalformedSignatureError
from crypto.keys import PublicKey
from crypto.verification import ComponentResult, VerificationResult, VerificationStatus, check_with_provider
from crypto_agility.interfaces import CryptoProvider

from .signature import HYBRID_ALGORITHM_ID, SUPPORTED_HYBRID_ALGORITHMS, HybridSignature


class HybridAcceptancePolicy(str, Enum):
    """How component results combine into an overall decision.

    ``STRICT_TWO_COMPONENT`` (the project's documented policy): the hybrid
    signature is accepted **only if both** the classical and the PQ
    component verify.  A single valid component is never sufficient.
    The enum is intentionally the only place this rule lives - if a
    future policy is added, it is added here and in the tests, not
    scattered through the code.
    """

    STRICT_TWO_COMPONENT = "strict-two-component"


class HybridVerifier:
    """Verifies hybrid signatures and returns component-level diagnostics."""

    def __init__(
        self,
        classical_provider: CryptoProvider,
        pq_provider: CryptoProvider,
        algorithm_id: str = HYBRID_ALGORITHM_ID,
        policy: HybridAcceptancePolicy = HybridAcceptancePolicy.STRICT_TWO_COMPONENT,
    ) -> None:
        if algorithm_id not in SUPPORTED_HYBRID_ALGORITHMS:
            raise ValueError(
                f"unsupported hybrid algorithm identifier {algorithm_id!r}; "
                f"supported: {list(SUPPORTED_HYBRID_ALGORITHMS)}"
            )
        self._classical = classical_provider
        self._pq = pq_provider
        self.algorithm_id = algorithm_id
        self.policy = policy

    # ------------------------------------------------------------------ #
    def verify(
        self,
        message: bytes,
        signature: HybridSignature | bytes,
        classical_public_key: PublicKey,
        pq_public_key: PublicKey,
        context: bytes | None = None,
        timeout_s: float | None = None,
    ) -> VerificationResult:
        """Verify ``message`` against a hybrid signature.

        Accepts a :class:`HybridSignature` object or its canonical JSON
        byte serialization.  Returns a :class:`VerificationResult` whose
        ``accepted`` flag follows the configured policy and whose
        ``components`` carry the per-component diagnostics.

        ``context`` binds the verification to a domain-separation label;
        ``timeout_s`` applies fail-closed component timeouts (a timed-out
        component is reported as ERROR, never accepted).
        """
        from crypto.faults import check_message_size

        subject = f"hybrid-signature:{self.algorithm_id}"
        try:
            message = check_message_size(bytes(message))
        except Exception as exc:  # noqa: BLE001 - fail-closed on oversized input
            return VerificationResult(
                accepted=False,
                subject=subject,
                policy=self.policy.value,
                reason=f"message rejected before verification: {exc}",
            )
        if isinstance(signature, (bytes, bytearray)):
            try:
                signature = HybridSignature.from_json_bytes(bytes(signature))
            except MalformedSignatureError as exc:
                return VerificationResult(
                    accepted=False,
                    subject=subject,
                    policy=self.policy.value,
                    components=(
                        ComponentResult("rsa_signature", VerificationStatus.MALFORMED, "deserialization failed"),
                        ComponentResult("mldsa_signature", VerificationStatus.MALFORMED, "deserialization failed"),
                    ),
                    reason=f"malformed serialized hybrid signature: {exc}",
                )
        elif not isinstance(signature, HybridSignature):
            return VerificationResult(
                accepted=False,
                subject=subject,
                policy=self.policy.value,
                reason="signature must be a HybridSignature or its canonical JSON bytes",
            )

        # Algorithm identifier must match what this verifier is configured
        # for; a mismatch means the components cannot be trusted to be the
        # expected algorithms at all.
        if signature.algorithm != self.algorithm_id:
            unsupported = (
                ComponentResult(
                    "rsa_signature",
                    VerificationStatus.UNSUPPORTED_ALGORITHM,
                    detail=f"hybrid algorithm {signature.algorithm!r} is not supported here",
                ),
                ComponentResult(
                    "mldsa_signature",
                    VerificationStatus.UNSUPPORTED_ALGORITHM,
                    detail=f"hybrid algorithm {signature.algorithm!r} is not supported here",
                ),
            )
            return VerificationResult(
                accepted=False,
                subject=subject,
                policy=self.policy.value,
                components=unsupported,
                reason=f"unsupported hybrid algorithm identifier {signature.algorithm!r}",
            )

        rsa_result = (
            ComponentResult("rsa_signature", VerificationStatus.MISSING, detail="component absent/empty")
            if not signature.rsa_signature
            else self._check_component(
                self._classical, message, signature.rsa_signature, classical_public_key, "rsa_signature", context, timeout_s
            )
        )
        mldsa_result = (
            ComponentResult("mldsa_signature", VerificationStatus.MISSING, detail="component absent/empty")
            if not signature.mldsa_signature
            else self._check_component(
                self._pq, message, signature.mldsa_signature, pq_public_key, "mldsa_signature", context, timeout_s
            )
        )

        accepted = self._decide(rsa_result, mldsa_result)
        reason = (
            "accepted: both components verified under strict two-component policy"
            if accepted
            else "rejected: " + "; ".join(
                f"{c.component}={c.status.value}" for c in (rsa_result, mldsa_result) if not c.ok
            )
            + " (policy requires both components to verify)"
        )
        return VerificationResult(
            accepted=accepted,
            subject=subject,
            policy=self.policy.value,
            components=(rsa_result, mldsa_result),
            reason=reason,
        )

    # ------------------------------------------------------------------ #
    def _check_component(
        self,
        provider: CryptoProvider,
        message: bytes,
        signature_bytes: bytes,
        public_key: PublicKey,
        component: str,
        context: bytes | None,
        timeout_s: float | None,
    ) -> ComponentResult:
        # oversize components are rejected before any provider call
        from crypto.faults import check_signature_size
        from crypto.errors import ResourceLimitExceededError

        try:
            signature_bytes = check_signature_size(bytes(signature_bytes))
        except ResourceLimitExceededError as exc:
            return ComponentResult(component, VerificationStatus.MALFORMED, detail=str(exc))
        return check_with_provider(
            provider, message, signature_bytes, public_key, component, context=context, timeout_s=timeout_s
        )

    # ------------------------------------------------------------------ #
    def _decide(self, rsa_result: ComponentResult, mldsa_result: ComponentResult) -> bool:
        if self.policy is HybridAcceptancePolicy.STRICT_TWO_COMPONENT:
            return rsa_result.ok and mldsa_result.ok
        raise ValueError(f"unknown acceptance policy {self.policy!r}")

    # ------------------------------------------------------------------ #
    def verify_components(self, signature: HybridSignature) -> dict:
        """Raw component presence check (missing components, etc.) used by
        tests and diagnostics; not a verification."""
        return {
            "rsa_signature": len(signature.rsa_signature),
            "mldsa_signature": len(signature.mldsa_signature),
        }

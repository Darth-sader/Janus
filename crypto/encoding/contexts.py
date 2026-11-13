"""Domain-separation context labels (Tier 1.3).

Every signature this layer produces is bound to an explicit, versioned
purpose label.  A signature made under one context can never verify
under another, because the context label is part of the exact signed
byte input (see :mod:`crypto.encoding.canonical` and the ``context``
parameter on provider sign/verify).

Rules:

* a context label is non-empty ASCII bytes, at most 255 bytes long
  (the FIPS 204/205 context-string limit), with the form
  ``"<base-label>"`` or ``"<base-label>:<qualifier>"``;
* the base label must be registered here - arbitrary ad-hoc labels are
  rejected, so a caller cannot invent a context that aliases another
  purpose;
* adding a new purpose = adding a registered base label + tests, never
  reusing an existing label.
"""

from __future__ import annotations

#: Policy document signing (the signed cryptographic policy object).
CONTEXT_POLICY_SIGNING = "policy-signing:v1"
#: Hybrid negotiation transcript binding.
CONTEXT_NEGOTIATION = "negotiation-transcript:v1"
#: Explicit authorization of a legacy (classical-only) session.
CONTEXT_LEGACY_AUTHORIZATION = "legacy-authorization:v1"
#: Ordinary application-message signatures.
CONTEXT_MESSAGE = "message-signing:v1"
#: Signatures bound to a negotiated session (qualifier = transcript digest).
CONTEXT_SESSION_BINDING = "session-binding:v1"
#: Migration-plan / migration-artifact approval signatures.
CONTEXT_MIGRATION_APPROVAL = "migration-approval:v1"
#: Tamper-evident audit trail checkpoint signatures.
CONTEXT_AUDIT_CHECKPOINT = "audit-checkpoint:v1"
#: Key-lifecycle confirmations (rotation receipts, compromise notices).
CONTEXT_KEY_CONFIRMATION = "key-confirmation:v1"

#: Base labels any signature context must start with.
BASE_LABELS: frozenset[str] = frozenset(
    {
        CONTEXT_POLICY_SIGNING,
        CONTEXT_NEGOTIATION,
        CONTEXT_LEGACY_AUTHORIZATION,
        CONTEXT_MESSAGE,
        CONTEXT_SESSION_BINDING,
        CONTEXT_MIGRATION_APPROVAL,
        CONTEXT_AUDIT_CHECKPOINT,
        CONTEXT_KEY_CONFIRMATION,
    }
)

_MAX_CONTEXT_BYTES = 255


def validate_context(context: bytes | None) -> bytes | None:
    """Validate an optional signature context; returns normalized bytes.

    A valid context is exactly a registered base label or starts with
    ``"<base-label>:"`` plus a qualifier (e.g. a session digest).
    Raises ValueError on invalid contexts so misuse fails loudly instead
    of silently widening a signature's scope.
    """
    if context is None:
        return None
    if isinstance(context, str):
        context = context.encode("ascii")
    if not isinstance(context, (bytes, bytearray)) or not context:
        raise ValueError("context must be non-empty bytes (or None)")
    context = bytes(context)
    if len(context) > _MAX_CONTEXT_BYTES:
        raise ValueError(f"context exceeds {_MAX_CONTEXT_BYTES} bytes")
    try:
        text = context.decode("ascii")
    except UnicodeDecodeError:
        raise ValueError("context must be ASCII") from None
    for label in BASE_LABELS:
        if text == label or text.startswith(label + ":"):
            return context
    raise ValueError(
        f"unregistered context {text.split(':')[0]!r}; registered bases: "
        f"{sorted(l.split(':v')[0] for l in BASE_LABELS)}"
    )


def session_context(transcript_digest: bytes) -> bytes:
    """Build the session-binding context for a negotiated transcript."""
    if not isinstance(transcript_digest, (bytes, bytearray)) or not transcript_digest:
        raise ValueError("transcript_digest must be non-empty bytes")
    return validate_context(f"{CONTEXT_SESSION_BINDING}:{bytes(transcript_digest).hex()}")

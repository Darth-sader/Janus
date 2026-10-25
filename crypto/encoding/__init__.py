"""Canonical cryptographic encoding + domain separation (Tier 1.3).

See the module docstrings for the full wire specification of
``HPKI-CANON-1`` and the registered purpose labels.
"""

from .canonical import (
    DEFAULT_LIMITS,
    EncodingLimits,
    decode_struct,
    encode_struct,
    strict_json_loads,
    validate_schema,
)
from .contexts import (
    BASE_LABELS,
    CONTEXT_AUDIT_CHECKPOINT,
    CONTEXT_KEY_CONFIRMATION,
    CONTEXT_LEGACY_AUTHORIZATION,
    CONTEXT_MESSAGE,
    CONTEXT_MIGRATION_APPROVAL,
    CONTEXT_NEGOTIATION,
    CONTEXT_POLICY_SIGNING,
    CONTEXT_SESSION_BINDING,
    session_context,
    validate_context,
)

__all__ = [
    "EncodingLimits",
    "DEFAULT_LIMITS",
    "encode_struct",
    "decode_struct",
    "strict_json_loads",
    "validate_schema",
    "BASE_LABELS",
    "CONTEXT_POLICY_SIGNING",
    "CONTEXT_NEGOTIATION",
    "CONTEXT_LEGACY_AUTHORIZATION",
    "CONTEXT_MESSAGE",
    "CONTEXT_SESSION_BINDING",
    "CONTEXT_MIGRATION_APPROVAL",
    "CONTEXT_AUDIT_CHECKPOINT",
    "CONTEXT_KEY_CONFIRMATION",
    "validate_context",
    "session_context",
]

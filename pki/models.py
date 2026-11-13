"""Data models shared across the PKI module.

Field names are a first draft -- confirm against the shared spec's
Certificate model before Person 3 relies on them.
"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class CertMode(str, Enum):
    CLASSICAL = "classical"  # RSA only
    HYBRID = "hybrid"        # RSA + ML-DSA (both signatures must verify)
    PQ = "pq"                # ML-DSA only


class LifecycleState(str, Enum):
    GENERATE = "GENERATE"
    ISSUE = "ISSUE"
    ACTIVE = "ACTIVE"
    RENEW = "RENEW"
    REVOKE = "REVOKE"
    REVOKED = "REVOKED"


class CertRole(str, Enum):
    ROOT_CA = "root_ca"
    INTERMEDIATE_CA = "intermediate_ca"
    LEAF = "leaf"


class ValidationReason(str, Enum):
    OK = "OK"
    EXPIRED = "EXPIRED"
    NOT_YET_VALID = "NOT_YET_VALID"
    BAD_SIGNATURE = "BAD_SIGNATURE"            # classical (or sole ML-DSA) signature
    BAD_PQ_SIGNATURE = "BAD_PQ_SIGNATURE"      # ML-DSA half of a hybrid signature
    BAD_CHAIN = "BAD_CHAIN"                    # missing issuer, issuer not a CA, path too long
    UNTRUSTED_ROOT = "UNTRUSTED_ROOT"
    REVOKED = "REVOKED"
    REVOCATION_UNKNOWN = "REVOCATION_UNKNOWN"  # no usable CRL when one is required
    POLICY_VIOLATION = "POLICY_VIOLATION"      # e.g. PQ required but certificate is classical


@dataclass
class CertificateRecord:
    """Plain-data view of a certificate, safe to serialise to JSON for Person 3."""
    serial_number: str          # hex string
    subject: str
    issuer: str
    not_before: datetime
    not_after: datetime
    role: CertRole
    is_ca: bool
    public_key_algorithm: str   # e.g. "RSA-4096" or "RSA-4096 + ML-DSA-65"
    signature_algorithm: str    # e.g. "sha256WithRSAEncryption + ML-DSA-65"
    mode: CertMode
    fingerprint_sha256: str
    san_dns_names: list[str] = field(default_factory=list)
    state: LifecycleState = LifecycleState.ACTIVE

    def to_dict(self) -> dict:
        return {
            "serial_number": self.serial_number,
            "subject": self.subject,
            "issuer": self.issuer,
            "not_before": self.not_before.isoformat(),
            "not_after": self.not_after.isoformat(),
            "role": self.role.value,
            "is_ca": self.is_ca,
            "public_key_algorithm": self.public_key_algorithm,
            "signature_algorithm": self.signature_algorithm,
            "mode": self.mode.value,
            "fingerprint_sha256": self.fingerprint_sha256,
            "san_dns_names": self.san_dns_names,
            "state": self.state.value,
        }


@dataclass
class ValidationIssue:
    reason: ValidationReason
    subject: str     # certificate the problem was found on
    message: str

    def to_dict(self) -> dict:
        return {"reason": self.reason.value, "subject": self.subject, "message": self.message}


@dataclass
class ValidationResult:
    """Detailed outcome of a chain validation, for the dashboard rather than pass/fail."""
    valid: bool
    reason: ValidationReason              # first issue found, or OK
    issues: list[ValidationIssue]
    chain: list[str]                      # subjects, leaf first
    mode: CertMode                        # mode of the certificate being validated
    checked_at: datetime

    def to_dict(self) -> dict:
        return {
            "valid": self.valid,
            "reason": self.reason.value,
            "issues": [i.to_dict() for i in self.issues],
            "chain": self.chain,
            "mode": self.mode.value,
            "checked_at": self.checked_at.isoformat(),
        }

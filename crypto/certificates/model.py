"""Conceptual hybrid certificate data model (Phase 3).

This module is the **architecture** deliverable of Poojita's workstream:
it defines what a hybrid certificate contains and which bytes the CA
signs.  It is deliberately **not** an X.509 implementation and not a
finalized interoperable encoding - per the specification (section 7) and
RFC 9794 terminology, the applicable certificate profile/encoding is
agreed with the PKI workstream (Ayanna) before implementation.  See
``docs/hybrid_certificate_architecture.md`` for the full contract.

What is normative here:

* the field set of the conceptual model (subject, both public keys,
  issuer, serial, validity, extensions, signature info);
* the exact bytes that both CA signature components cover
  (:meth:`HybridCertificateModel.to_be_signed_bytes`) - a deterministic
  canonical JSON serialization of every field *except* the signature;
* which component signs what: **both** the RSA-4096 and the ML-DSA
  component sign the identical TBS bytes, under the composite algorithm
  id ``RSA4096-MLDSA``.
"""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Mapping

from crypto.errors import SerializationError
from crypto.hybrid import SUPPORTED_HYBRID_ALGORITHMS, HybridSignature
from crypto.keys import PublicKey

#: Conceptual profile tag; intentionally not claimed as an X.509 standard.
CERTIFICATE_PROFILE = "conceptual-hybrid-certificate-v1 (NOT an X.509 encoding)"

#: Classical component algorithm expected in this project's configuration.
CLASSICAL_COMPONENT_ALGORITHM = "rsa4096"
#: PQ component family expected (any ML-DSA parameter set).
PQ_COMPONENT_ALGORITHM_PREFIX = "mldsa"


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(text: str) -> bytes:
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError, TypeError):
        raise SerializationError("certificate field is not valid base64") from None


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


@dataclass
class HybridCertificateModel:
    """Conceptual hybrid certificate (RFC 9794 "hybrid certificate": one
    certificate carrying public keys for a traditional and a PQ
    algorithm, plus the composite signature over it)."""

    subject: str
    issuer: str
    serial_number: int
    not_before: datetime
    not_after: datetime
    #: RSA-4096 component public key (algorithm ``rsa4096``)
    classical_public_key: PublicKey
    #: ML-DSA component public key (algorithm ``mldsa44/65/87``)
    pq_public_key: PublicKey
    #: Opaque extension bag (name -> value bytes); semantics agreed with
    #: the PKI layer.  Iteration/serialization is key-sorted so the TBS
    #: bytes stay deterministic.
    extensions: Mapping[str, bytes] = field(default_factory=dict)
    #: Composite signature algorithm identifier
    signature_algorithm: str = "RSA4096-MLDSA"
    #: Populated by the CA when the certificate is issued
    signature: HybridSignature | None = None

    # ------------------------------------------------------------------ #
    def __post_init__(self) -> None:
        if not self.subject or not isinstance(self.subject, str):
            raise SerializationError("subject must be a non-empty string")
        if not self.issuer or not isinstance(self.issuer, str):
            raise SerializationError("issuer must be a non-empty string")
        if not isinstance(self.serial_number, int) or self.serial_number <= 0:
            raise SerializationError("serial_number must be a positive integer")
        for name in ("not_before", "not_after"):
            dt = getattr(self, name)
            if not isinstance(dt, datetime):
                raise SerializationError(f"{name} must be a datetime")
            if dt.tzinfo is None:
                raise SerializationError(f"{name} must be timezone-aware")
        if self.not_before >= self.not_after:
            raise SerializationError("not_before must be earlier than not_after")
        if not isinstance(self.classical_public_key, PublicKey) or not self.classical_public_key.algorithm.startswith(
            "rsa"
        ):
            raise SerializationError("classical_public_key must be an rsa* PublicKey")
        if not isinstance(self.pq_public_key, PublicKey) or not self.pq_public_key.algorithm.startswith(
            PQ_COMPONENT_ALGORITHM_PREFIX
        ):
            raise SerializationError("pq_public_key must be an mldsa* PublicKey")
        if self.signature_algorithm not in SUPPORTED_HYBRID_ALGORITHMS:
            raise SerializationError(
                f"unsupported signature_algorithm {self.signature_algorithm!r}; "
                f"supported: {list(SUPPORTED_HYBRID_ALGORITHMS)}"
            )
        if self.signature is not None and not isinstance(self.signature, HybridSignature):
            raise SerializationError("signature must be a HybridSignature or None")

    # ------------------------------------------------------------------ #
    def to_be_signed_bytes(self) -> bytes:
        """The exact bytes both CA signature components cover.

        Deterministic canonical JSON (sorted keys, compact separators,
        UTC ISO-8601 timestamps, base64 key/extension values) over every
        field except ``signature``.  Any change to any field - even
        key-order games - changes these bytes and fails verification.
        """
        tbs = {
            "profile": CERTIFICATE_PROFILE,
            "subject": self.subject,
            "issuer": self.issuer,
            "serial_number": self.serial_number,
            "not_before": _iso(self.not_before),
            "not_after": _iso(self.not_after),
            "classical_public_key": {
                "algorithm": self.classical_public_key.algorithm,
                "data": _b64(self.classical_public_key.data),
            },
            "pq_public_key": {
                "algorithm": self.pq_public_key.algorithm,
                "data": _b64(self.pq_public_key.data),
            },
            "extensions": {k: _b64(v) for k, v in sorted(self.extensions.items())},
            "signature_algorithm": self.signature_algorithm,
        }
        return json.dumps(tbs, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")

    # -- demo/internal serialization (NOT a wire format) ---------------- #
    def to_dict(self) -> dict:
        obj = {
            "profile": CERTIFICATE_PROFILE,
            "subject": self.subject,
            "issuer": self.issuer,
            "serial_number": self.serial_number,
            "not_before": _iso(self.not_before),
            "not_after": _iso(self.not_after),
            "classical_public_key": {
                "algorithm": self.classical_public_key.algorithm,
                "data": _b64(self.classical_public_key.data),
            },
            "pq_public_key": {
                "algorithm": self.pq_public_key.algorithm,
                "data": _b64(self.pq_public_key.data),
            },
            "extensions": {k: _b64(v) for k, v in sorted(self.extensions.items())},
            "signature_algorithm": self.signature_algorithm,
            "signature": self.signature.to_dict() if self.signature is not None else None,
        }
        return obj

    @classmethod
    def from_dict(cls, obj: dict) -> "HybridCertificateModel":
        if not isinstance(obj, dict):
            raise SerializationError("certificate must be a JSON object")
        try:
            signature = HybridSignature.from_dict(obj["signature"]) if obj.get("signature") is not None else None
            return cls(
                subject=obj["subject"],
                issuer=obj["issuer"],
                serial_number=int(obj["serial_number"]),
                not_before=datetime.fromisoformat(obj["not_before"]),
                not_after=datetime.fromisoformat(obj["not_after"]),
                classical_public_key=PublicKey(obj["classical_public_key"]["algorithm"], _unb64(obj["classical_public_key"]["data"])),
                pq_public_key=PublicKey(obj["pq_public_key"]["algorithm"], _unb64(obj["pq_public_key"]["data"])),
                extensions={k: _unb64(v) for k, v in obj.get("extensions", {}).items()},
                signature_algorithm=obj.get("signature_algorithm", "RSA4096-MLDSA"),
                signature=signature,
            )
        except KeyError as exc:
            raise SerializationError(f"certificate object missing field {exc}") from None

    # -- convenience ------------------------------------------------------- #
    def is_signed(self) -> bool:
        return self.signature is not None

    def with_signature(self, signature: HybridSignature) -> "HybridCertificateModel":
        return replace(self, signature=signature)


@dataclass(frozen=True)
class CertificateValidationRequest:
    """Handoff object: what the PKI layer passes down to the crypto layer
    when it wants a certificate's signature verified (see contracts.py)."""

    certificate: HybridCertificateModel
    #: The issuer's *component* public keys (from the issuer certificate
    #: or trust anchor) that the signature components verify against.
    issuer_classical_public_key: PublicKey
    issuer_pq_public_key: PublicKey


@dataclass(frozen=True)
class CertificateVerificationOutcome:
    """Handoff object returned to the PKI layer.

    ``signature_accepted`` covers ONLY the cryptographic signature check.
    Validity dates, issuer/chain checks and revocation are PKI-layer
    responsibilities and are deliberately absent here - signature
    verification never replaces those checks (spec, section 8).
    """

    signature_accepted: bool
    signature_algorithm: str
    detail: dict = field(default_factory=dict)

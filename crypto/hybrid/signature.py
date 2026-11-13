"""Hybrid signature representation.

A parallel/composite-style PQ/T hybrid per RFC 9794 terminology: both
component algorithms sign the *same* message independently, and the two
signatures travel together.  This is an internal representation - it is
deliberately NOT a finalized certificate/interoperability wire format
(see docs/hybrid_certificate_architecture.md).

Wire format (deterministic canonical JSON, UTF-8, fixed key order)::

    {"algorithm": "RSA4096-MLDSA",
     "rsa_signature": "<base64>",
     "mldsa_signature": "<base64>"}

matching the representation given in the Technical Design Specification.
"""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass

from crypto.errors import MalformedSignatureError

#: Canonical identifier of the primary hybrid construction (per spec).
HYBRID_ALGORITHM_ID = "RSA4096-MLDSA"

#: Hybrid constructions this layer understands.  Extensible: adding a new
#: combination means adding its id here and wiring its providers - the
#: rest of the application is untouched.
SUPPORTED_HYBRID_ALGORITHMS: tuple[str, ...] = (HYBRID_ALGORITHM_ID,)

#: Ordered component fields in the serialized object.
COMPONENT_FIELDS: tuple[str, ...] = ("rsa_signature", "mldsa_signature")


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(text: str) -> bytes:
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError, TypeError):
        raise MalformedSignatureError("hybrid signature component is not valid base64") from None


@dataclass(frozen=True)
class HybridSignature:
    """Both component signatures over one message.

    ``algorithm`` identifies the combination (which also tells the
    verifier which component algorithms and parameter sets to expect).
    Empty component bytes mean "component missing" and are rejected by
    the verifier - a hybrid signature with only one component is never
    accepted.
    """

    algorithm: str = HYBRID_ALGORITHM_ID
    rsa_signature: bytes = b""
    mldsa_signature: bytes = b""

    def __post_init__(self) -> None:
        if self.algorithm not in SUPPORTED_HYBRID_ALGORITHMS:
            raise MalformedSignatureError(
                f"unsupported hybrid algorithm identifier {self.algorithm!r}; "
                f"supported: {list(SUPPORTED_HYBRID_ALGORITHMS)}"
            )
        for name in ("rsa_signature", "mldsa_signature"):
            value = getattr(self, name)
            if not isinstance(value, (bytes, bytearray)):
                raise MalformedSignatureError(f"{name} must be bytes")

    # -- dict / JSON -----------------------------------------------------
    def to_dict(self) -> dict:
        return {
            "algorithm": self.algorithm,
            "rsa_signature": _b64(bytes(self.rsa_signature)),
            "mldsa_signature": _b64(bytes(self.mldsa_signature)),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "HybridSignature":
        if not isinstance(data, dict):
            raise MalformedSignatureError("hybrid signature must be a JSON object")
        missing = [k for k in ("algorithm", *COMPONENT_FIELDS) if k not in data]
        if missing:
            raise MalformedSignatureError(f"hybrid signature missing fields: {missing}")
        algorithm = data["algorithm"]
        if algorithm not in SUPPORTED_HYBRID_ALGORITHMS:
            raise MalformedSignatureError(
                f"unsupported hybrid algorithm identifier {algorithm!r}; "
                f"supported: {list(SUPPORTED_HYBRID_ALGORITHMS)}"
            )
        rsa_sig = _unb64(data["rsa_signature"])
        mldsa_sig = _unb64(data["mldsa_signature"])
        if not rsa_sig:
            raise MalformedSignatureError("rsa_signature component is missing/empty")
        if not mldsa_sig:
            raise MalformedSignatureError("mldsa_signature component is missing/empty")
        return cls(algorithm=algorithm, rsa_signature=rsa_sig, mldsa_signature=mldsa_sig)

    def to_json_bytes(self) -> bytes:
        """Deterministic serialization: fixed key order, compact separators,
        UTF-8 (ASCII in practice)."""
        obj = self.to_dict()
        ordered = {k: obj[k] for k in ("algorithm", *COMPONENT_FIELDS)}
        return json.dumps(ordered, separators=(",", ":"), ensure_ascii=True).encode("utf-8")

    @classmethod
    def from_json_bytes(cls, data: bytes) -> "HybridSignature":
        if not isinstance(data, (bytes, bytearray)):
            raise MalformedSignatureError("serialized hybrid signature must be bytes")
        from crypto.faults import check_serialized_size

        data = check_serialized_size(bytes(data))  # fail-closed before parsing
        from crypto.encoding import strict_json_loads

        try:
            obj = strict_json_loads(data)  # rejects duplicate fields
        except Exception as exc:  # noqa: BLE001 - normalized below
            raise MalformedSignatureError(f"serialized hybrid signature rejected ({type(exc).__name__})") from None
        return cls.from_dict(obj)

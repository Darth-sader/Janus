"""Capability records describing an algorithm/provider.

The :class:`ProviderCapabilities` fields deliberately mirror the
``PQCAlgorithm`` entity defined in the Technical Design Specification's
data model (section 21: name, family, standard, security_level, key_size,
signature_size, implementation) so the migration platform (Pranshita's
workstream) can seed its algorithm database directly from a provider.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass(frozen=True)
class ProviderCapabilities:
    """Machine-readable description of one algorithm/provider pair."""

    algorithm_id: str
    display_name: str
    family: str                    # "classical" | "pq" | "hybrid"
    standard: str                  # e.g. "FIPS 204"
    parameter_set: str             # e.g. "ML-DSA-65"
    backend: str                   # maintained library performing the primitives
    quantum_vulnerable: bool
    implemented: bool = True       # False -> registered candidate without implementation
    public_key_size: int | None = None
    secret_key_size: int | None = None
    signature_size: int | None = None
    security_level: str = ""       # e.g. "NIST category 3"
    supported_operations: tuple[str, ...] = ("keygen", "sign", "verify")
    notes: str = ""
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["supported_operations"] = list(self.supported_operations)
        return data

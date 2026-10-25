"""Crypto capability catalog - the query surface for the migration platform.

This is the handoff API to Pranshita's workstream: everything the asset
inventory, assessment engine and recommendation engine need from the
crypto layer, exposed as plain JSON-able dicts.

Boundary (normative): this module reports what the CRYPTO LAYER can do.
It does not assess assets, score algorithms, or recommend migrations -
that is the platform's rule-based engine.  The catalog only supplies the
facts (algorithms, parameter sets, standards, sizes, availability) the
engine consumes.
"""

from __future__ import annotations

from datetime import datetime, timezone

from crypto.errors import UnsupportedAlgorithmError

from ..policies.registry import AlgorithmRegistry


class CryptoCapabilityCatalog:
    """Read-only view over an :class:`AlgorithmRegistry`, shaped for the
    migration platform."""

    def __init__(self, registry: AlgorithmRegistry) -> None:
        self._registry = registry

    # ------------------------------------------------------------------ #
    def available_algorithms(self) -> list[dict]:
        """All algorithms with working implementations, aligned with the
        spec's ``PQCAlgorithm`` entity (name, family, standard,
        security_level, key_size, signature_size, implementation)."""
        out = []
        for entry in self._registry.implemented_algorithms():
            caps = self._registry.capabilities(entry.algorithm_id)
            out.append(self._algorithm_record(entry.algorithm_id, caps))
        return out

    def algorithm_details(self, algorithm_id: str) -> dict:
        """Details for one algorithm; works for candidates too.  Unknown
        ids raise :class:`UnsupportedAlgorithmError` (no guessing)."""
        self._registry.get(algorithm_id)  # exact lookup, raises on unknown
        caps = self._registry.capabilities(algorithm_id)
        return self._algorithm_record(algorithm_id, caps)

    def is_available(self, algorithm_id: str) -> bool:
        """True iff the algorithm has a working implementation here."""
        return self._registry.is_available(algorithm_id)

    def check_availability(self, algorithm_id: str) -> dict:
        """Explainable availability check for the recommendation engine:
        ``{"algorithm_id", "available", "reason"}``."""
        entry = None
        try:
            entry = self._registry.get(algorithm_id)
        except UnsupportedAlgorithmError:
            return {
                "algorithm_id": algorithm_id,
                "available": False,
                "reason": f"unknown algorithm {algorithm_id!r}; it is not in the registry",
            }
        if entry.implemented:
            return {
                "algorithm_id": algorithm_id,
                "available": True,
                "reason": f"implemented via {entry.provider.backend if entry.provider else 'n/a'}",
            }
        return {
            "algorithm_id": algorithm_id,
            "available": False,
            "reason": entry.notes or "registered as an evaluated candidate only; no implementation",
        }

    def unavailable_candidates(self) -> list[dict]:
        """PQ candidates that are declared but NOT implemented - the
        explicit answer to 'how is an unsupported PQ candidate reported'."""
        return [
            {
                **entry.to_dict(),
                "availability_reason": entry.notes or "no provider implemented",
            }
            for entry in self._registry.candidate_algorithms()
        ]

    def capability_report(self) -> dict:
        """Complete, JSON-serializable snapshot for the platform (DB seed,
        /api/algorithms, /api/pqc/candidates backing data)."""
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "implemented": self.available_algorithms(),
            "candidates": self.unavailable_candidates(),
            "mode_support": {
                "classical": True,
                "pq": True,
                "hybrid": True,
            },
        }

    # ------------------------------------------------------------------ #
    @staticmethod
    def _algorithm_record(algorithm_id: str, caps) -> dict:
        return {
            # PQCAlgorithm fields from the spec's data model:
            "name": caps.display_name,
            "family": caps.family,
            "standard": caps.standard,
            "security_level": caps.security_level,
            "key_size": caps.public_key_size,
            "signature_size": caps.signature_size,
            "implementation": caps.backend,
            # additional crypto-layer facts:
            "algorithm_id": caps.algorithm_id,
            "parameter_set": caps.parameter_set,
            "secret_key_size": caps.secret_key_size,
            "quantum_vulnerable": caps.quantum_vulnerable,
            "implemented": caps.implemented,
            "supported_operations": list(caps.supported_operations),
            "notes": caps.notes,
        }

"""Transition-mode logic owned by the crypto workstream.

Answers, deterministically and explainably, the crypto-layer half of the
migration question: *which signature modes (classical / hybrid / PQ) can
this crypto layer support right now, and what does each mode require?*

It does NOT decide that any particular asset should migrate - asset
assessment and recommendations belong to the platform (Pranshita's
rule-based engine).  The engine calls this module to know which target
modes are feasible with the registered algorithms, and gets structured,
auditable answers back.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from ..policies.registry import AlgorithmRegistry
from ..policies.selection import CryptoMode


class MigrationMode(str, Enum):
    """Target signature modes the crypto layer can serve."""

    CLASSICAL = "classical"
    HYBRID = "hybrid"
    PQ = "pq"


@dataclass(frozen=True)
class TransitionFeasibility:
    """Structured, auditable answer for one requested mode."""

    requested_mode: str
    supported: bool
    blockers: tuple[str, ...]
    explanation: str
    requirements: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "requested_mode": self.requested_mode,
            "supported": self.supported,
            "blockers": list(self.blockers),
            "explanation": self.explanation,
            "requirements": dict(self.requirements),
        }


class TransitionOptions:
    """Mode feasibility checks against a registry (deterministic rules)."""

    def __init__(self, registry: AlgorithmRegistry) -> None:
        self._registry = registry

    # ------------------------------------------------------------------ #
    def mode_requirements(self, mode: MigrationMode | str) -> dict:
        """What a mode needs, expressed in algorithm ids and families."""
        mode = MigrationMode(mode)
        if mode is MigrationMode.CLASSICAL:
            return {
                "required_families": ["classical"],
                "default_algorithm_ids": ["rsa4096"],
                "description": "classical-only signatures (pre-migration baseline)",
            }
        if mode is MigrationMode.HYBRID:
            return {
                "required_families": ["classical", "pq", "hybrid"],
                "default_algorithm_ids": ["rsa4096", "mldsa65", "RSA4096-MLDSA"],
                "description": "PQ/T composite: classical + PQ components over the same bytes",
            }
        return {
            "required_families": ["pq"],
            "default_algorithm_ids": ["mldsa65"],
            "description": "pure post-quantum signatures (post-migration end state)",
        }

    # ------------------------------------------------------------------ #
    def check_mode(self, mode: MigrationMode | str) -> TransitionFeasibility:
        """Check whether ``mode`` is supportable with registered,
        implemented providers.  Pure function of the registry state."""
        mode = MigrationMode(mode)
        requirements = self.mode_requirements(mode)
        blockers: list[str] = []

        family_to_slot = {"classical": "classical_algorithm", "pq": "pq_algorithm", "hybrid": "hybrid_algorithm"}
        for algorithm_id in requirements["default_algorithm_ids"]:
            entry = None
            try:
                entry = self._registry.get(algorithm_id)
            except Exception:
                blockers.append(f"required algorithm {algorithm_id!r} is not registered")
                continue
            if not entry.implemented:
                blockers.append(f"required algorithm {algorithm_id!r} has no implementation (candidate only)")

        if blockers:
            return TransitionFeasibility(
                requested_mode=mode.value,
                supported=False,
                blockers=tuple(blockers),
                explanation=(
                    f"mode {mode.value!r} cannot be served: "
                    + "; ".join(blockers)
                ),
                requirements=requirements,
            )
        return TransitionFeasibility(
            requested_mode=mode.value,
            supported=True,
            blockers=(),
            explanation=(
                f"mode {mode.value!r} is fully supported by the registered providers "
                f"({', '.join(requirements['default_algorithm_ids'])})"
            ),
            requirements=requirements,
        )

    # ------------------------------------------------------------------ #
    def supported_modes(self) -> list[str]:
        """Modes that currently pass :meth:`check_mode`, in migration order
        (classical -> hybrid -> pq)."""
        return [
            mode.value
            for mode in (MigrationMode.CLASSICAL, MigrationMode.HYBRID, MigrationMode.PQ)
            if self.check_mode(mode).supported
        ]

    def check_algorithm_for_mode(self, mode: MigrationMode | str, algorithm_id: str) -> TransitionFeasibility:
        """Would ``algorithm_id`` be usable as the algorithm of ``mode``?

        Deterministic check: family must match the mode's slot and the
        algorithm must be implemented.  Used by the platform to validate
        a candidate target before recommending it.
        """
        mode = MigrationMode(mode)
        expected_family = {
            MigrationMode.CLASSICAL: "classical",
            MigrationMode.HYBRID: "hybrid",
            MigrationMode.PQ: "pq",
        }[mode]
        try:
            entry = self._registry.get(algorithm_id)
        except Exception:
            return TransitionFeasibility(
                requested_mode=mode.value,
                supported=False,
                blockers=(f"algorithm {algorithm_id!r} is not registered",),
                explanation=f"cannot use {algorithm_id!r} for mode {mode.value!r}: unknown algorithm",
                requirements=self.mode_requirements(mode),
            )
        if entry.family != expected_family:
            return TransitionFeasibility(
                requested_mode=mode.value,
                supported=False,
                blockers=(
                    f"algorithm {algorithm_id!r} has family {entry.family!r}; "
                    f"mode {mode.value!r} requires family {expected_family!r}",
                ),
                explanation=f"family mismatch between {algorithm_id!r} and mode {mode.value!r}",
                requirements=self.mode_requirements(mode),
            )
        if not entry.implemented:
            return TransitionFeasibility(
                requested_mode=mode.value,
                supported=False,
                blockers=(f"algorithm {algorithm_id!r} is a candidate without implementation",),
                explanation=f"cannot select {algorithm_id!r} for mode {mode.value!r}",
                requirements=self.mode_requirements(mode),
            )
        return TransitionFeasibility(
            requested_mode=mode.value,
            supported=True,
            blockers=(),
            explanation=f"{algorithm_id!r} can serve mode {mode.value!r}",
            requirements=self.mode_requirements(mode),
        )

"""Provider selection from explicit configuration (Phase 4).

The selector turns a declarative :class:`CryptoConfiguration` (mode +
algorithm ids) into concrete providers, validating everything up front.
Design rules (normative):

* selection is deterministic and explainable (``describe()``);
* every algorithm in the configuration must be registered *and*
  implemented - a candidate-only algorithm is a configuration error;
* there is no silent fallback: a bad configuration raises
  :class:`ConfigurationError` before any cryptographic operation runs;
* selection logic lives here, never inside the providers themselves.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from crypto.errors import ConfigurationError
from crypto_agility.interfaces import CryptoProvider

from .registry import AlgorithmRegistry


class CryptoMode(str, Enum):
    """Deployment signature mode: classical, PQ, or hybrid."""

    CLASSICAL = "classical"
    PQ = "pq"
    HYBRID = "hybrid"


#: which algorithm slot each mode needs, and what family that slot expects
_MODE_REQUIREMENTS: dict[CryptoMode, tuple[tuple[str, str], ...]] = {
    CryptoMode.CLASSICAL: (("classical_algorithm", "classical"),),
    CryptoMode.PQ: (("pq_algorithm", "pq"),),
    CryptoMode.HYBRID: (("hybrid_algorithm", "hybrid"),),
}


@dataclass(frozen=True)
class CryptoConfiguration:
    """Explicit crypto-agility configuration (validated by the selector).

    Defaults match the project's primary configuration from the
    specification: RSA-4096 classical, ML-DSA-65 PQ, RSA4096-MLDSA hybrid.
    """

    mode: CryptoMode
    classical_algorithm: str = "rsa4096"
    pq_algorithm: str = "mldsa65"
    hybrid_algorithm: str = "RSA4096-MLDSA"

    def __post_init__(self) -> None:
        if not isinstance(self.mode, CryptoMode):
            try:
                object.__setattr__(self, "mode", CryptoMode(self.mode))
            except ValueError:
                raise ConfigurationError(
                    f"unknown crypto mode {self.mode!r}; known modes: {[m.value for m in CryptoMode]}"
                ) from None


@dataclass(frozen=True)
class SelectionDecision:
    """Explainable record of what the selector resolved and why."""

    mode: str
    algorithm_id: str
    provider_display_name: str
    family: str
    requirements_met: tuple[str, ...]
    configuration: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "mode": self.mode,
            "algorithm_id": self.algorithm_id,
            "provider_display_name": self.provider_display_name,
            "family": self.family,
            "requirements_met": list(self.requirements_met),
            "configuration": dict(self.configuration),
        }


class ProviderSelector:
    """Resolves and validates a :class:`CryptoConfiguration` against a
    registry, once, at construction time (fail fast)."""

    def __init__(self, registry: AlgorithmRegistry, configuration: CryptoConfiguration) -> None:
        self._registry = registry
        self._configuration = configuration
        self._decision: SelectionDecision = self._resolve(configuration)

    # ------------------------------------------------------------------ #
    def _resolve(self, configuration: CryptoConfiguration) -> SelectionDecision:
        requirements_met: list[str] = []
        for attr_name, expected_family in _MODE_REQUIREMENTS[configuration.mode]:
            algorithm_id = getattr(configuration, attr_name)
            try:
                entry = self._registry.get(algorithm_id)
            except Exception as exc:  # unknown id
                raise ConfigurationError(
                    f"mode {configuration.mode.value!r} requires algorithm {algorithm_id!r} "
                    f"for slot {attr_name!r}, which is not registered"
                ) from exc
            if entry.family != expected_family:
                raise ConfigurationError(
                    f"slot {attr_name!r} requires a {expected_family!r} algorithm; "
                    f"{algorithm_id!r} has family {entry.family!r}"
                )
            if not entry.implemented:
                raise ConfigurationError(
                    f"algorithm {algorithm_id!r} is registered as a candidate only and cannot "
                    f"be selected for mode {configuration.mode.value!r}"
                )
            requirements_met.append(f"{attr_name}={algorithm_id}")

        primary_attr = {
            CryptoMode.CLASSICAL: "classical_algorithm",
            CryptoMode.PQ: "pq_algorithm",
            CryptoMode.HYBRID: "hybrid_algorithm",
        }[configuration.mode]
        algorithm_id = getattr(configuration, primary_attr)
        provider = self._registry.get_provider(algorithm_id)  # no fallback by construction
        return SelectionDecision(
            mode=configuration.mode.value,
            algorithm_id=algorithm_id,
            provider_display_name=provider.display_name,
            family=provider.family,
            requirements_met=tuple(requirements_met),
            configuration={
                "classical_algorithm": configuration.classical_algorithm,
                "pq_algorithm": configuration.pq_algorithm,
                "hybrid_algorithm": configuration.hybrid_algorithm,
            },
        )

    # ------------------------------------------------------------------ #
    @property
    def configuration(self) -> CryptoConfiguration:
        return self._configuration

    def provider(self) -> CryptoProvider:
        """The provider implementing the configured mode.  For the hybrid
        mode this is the composite adapter - callers use the same
        generate_keypair/sign/verify interface as for any other mode."""
        return self._registry.get_provider(self._decision.algorithm_id)

    def signing_algorithm_id(self) -> str:
        """Canonical id the platform should record alongside signatures
        produced through :meth:`provider`."""
        return self._decision.algorithm_id

    def verification_provider_for(self, algorithm_id: str) -> CryptoProvider:
        """Provider able to verify artifacts created with ``algorithm_id``.

        Exact lookup, no fallback: verifying a hybrid signature with the
        RSA provider (or vice versa) is impossible through this API.
        """
        return self._registry.get_provider(algorithm_id)

    def is_compatible_with(self, algorithm_id: str) -> bool:
        """True iff ``algorithm_id`` is exactly what this selector signs with."""
        return algorithm_id == self._decision.algorithm_id

    def describe(self) -> SelectionDecision:
        """Deterministic, explainable selection summary (for logs, UIs,
        and the migration platform's evidence records)."""
        return self._decision

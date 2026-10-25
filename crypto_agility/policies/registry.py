"""Algorithm/provider registry (Phase 4).

The registry is the single source of truth for "which algorithms does
this deployment have and who implements them".  It distinguishes:

* **implemented** - a working :class:`CryptoProvider` is registered;
* **candidate** - the algorithm is known and described (e.g. an
  evaluated PQ candidate) but has no implementation here; querying its
  provider raises :class:`ProviderUnavailableError`.

Agility rule (normative): lookups are exact.  If the requested algorithm
is not available, the registry raises - it NEVER silently falls back to
a different algorithm.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

from crypto.errors import (
    ConfigurationError,
    ProviderUnavailableError,
    UnsupportedAlgorithmError,
)
from crypto.hybrid import HybridCryptoProvider
from crypto.pq import MLDSAProvider, SLHDSAProvider
from crypto.rsa import RSA4096Provider
from crypto_agility.interfaces import CryptoProvider, ProviderCapabilities


@dataclass(frozen=True)
class AlgorithmEntry:
    """One registry row: an algorithm and who (if anyone) implements it."""

    algorithm_id: str
    display_name: str
    family: str                 # "classical" | "pq" | "hybrid"
    standard: str
    parameter_set: str
    security_level: str
    quantum_vulnerable: bool
    implemented: bool
    provider: CryptoProvider | None
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "algorithm_id": self.algorithm_id,
            "display_name": self.display_name,
            "family": self.family,
            "standard": self.standard,
            "parameter_set": self.parameter_set,
            "security_level": self.security_level,
            "quantum_vulnerable": self.quantum_vulnerable,
            "implemented": self.implemented,
            "notes": self.notes,
        }


class AlgorithmRegistry:
    """Thread-safe registry mapping canonical algorithm ids to providers."""

    def __init__(self) -> None:
        self._entries: dict[str, AlgorithmEntry] = {}
        self._aliases: dict[str, str] = {}
        self._lock = threading.RLock()

    # ------------------------------------------------------------------ #
    # registration
    # ------------------------------------------------------------------ #
    def register_provider(self, provider: CryptoProvider, *, aliases: tuple[str, ...] = (), notes: str = "") -> None:
        """Register a working provider (derived entry from its capabilities)."""
        if not isinstance(provider, CryptoProvider):
            raise ConfigurationError("register_provider expects a CryptoProvider instance")
        caps = provider.capabilities()
        with self._lock:
            if caps.algorithm_id in self._entries:
                raise ConfigurationError(f"algorithm {caps.algorithm_id!r} is already registered")
            entry = AlgorithmEntry(
                algorithm_id=caps.algorithm_id,
                display_name=caps.display_name,
                family=caps.family,
                standard=caps.standard,
                parameter_set=caps.parameter_set,
                security_level=caps.security_level,
                quantum_vulnerable=caps.quantum_vulnerable,
                implemented=True,
                provider=provider,
                notes=notes or caps.notes,
            )
            self._entries[caps.algorithm_id] = entry
            for alias in aliases:
                if alias in self._aliases:
                    raise ConfigurationError(f"alias {alias!r} is already registered")
                self._aliases[alias] = caps.algorithm_id

    def register_candidate(
        self,
        *,
        algorithm_id: str,
        display_name: str,
        family: str,
        standard: str,
        parameter_set: str,
        security_level: str = "",
        quantum_vulnerable: bool = False,
        notes: str = "",
        aliases: tuple[str, ...] = (),
    ) -> None:
        """Register an algorithm as an evaluated candidate WITHOUT an
        implementation (e.g. a PQ family kept visible to the platform)."""
        if family not in ("classical", "pq", "hybrid"):
            raise ConfigurationError(f"invalid family {family!r}")
        with self._lock:
            if algorithm_id in self._entries:
                raise ConfigurationError(f"algorithm {algorithm_id!r} is already registered")
            self._entries[algorithm_id] = AlgorithmEntry(
                algorithm_id=algorithm_id,
                display_name=display_name,
                family=family,
                standard=standard,
                parameter_set=parameter_set,
                security_level=security_level,
                quantum_vulnerable=quantum_vulnerable,
                implemented=False,
                provider=None,
                notes=notes,
            )
            for alias in aliases:
                self._aliases[alias] = algorithm_id

    # ------------------------------------------------------------------ #
    # lookup (exact, no fallback)
    # ------------------------------------------------------------------ #
    def _resolve(self, algorithm_id: str) -> AlgorithmEntry:
        with self._lock:
            target = self._aliases.get(algorithm_id, algorithm_id)
            entry = self._entries.get(target)
            if entry is None:
                raise UnsupportedAlgorithmError(
                    f"unknown algorithm {algorithm_id!r}; available: {sorted(self._entries)}"
                )
            return entry

    def get(self, algorithm_id: str) -> AlgorithmEntry:
        return self._resolve(algorithm_id)

    def get_provider(self, algorithm_id: str) -> CryptoProvider:
        entry = self._resolve(algorithm_id)
        if not entry.implemented or entry.provider is None:
            raise ProviderUnavailableError(
                f"algorithm {algorithm_id!r} is registered as a candidate only "
                f"(no implementation in this deployment)"
            )
        return entry.provider

    def has(self, algorithm_id: str) -> bool:
        try:
            self._resolve(algorithm_id)
            return True
        except UnsupportedAlgorithmError:
            return False

    def is_available(self, algorithm_id: str) -> bool:
        """True iff the algorithm is registered AND has a working provider."""
        try:
            entry = self._resolve(algorithm_id)
        except UnsupportedAlgorithmError:
            return False
        return entry.implemented

    # ------------------------------------------------------------------ #
    # listing / capabilities
    # ------------------------------------------------------------------ #
    def list_algorithms(self) -> tuple[AlgorithmEntry, ...]:
        with self._lock:
            return tuple(sorted(self._entries.values(), key=lambda e: (e.family, e.algorithm_id)))

    def implemented_algorithms(self) -> tuple[AlgorithmEntry, ...]:
        return tuple(e for e in self.list_algorithms() if e.implemented)

    def candidate_algorithms(self) -> tuple[AlgorithmEntry, ...]:
        return tuple(e for e in self.list_algorithms() if not e.implemented)

    def capabilities(self, algorithm_id: str) -> ProviderCapabilities:
        """Capabilities of one algorithm; candidates get a synthesized
        record with ``implemented=False`` and no sizes."""
        entry = self._resolve(algorithm_id)
        if entry.implemented and entry.provider is not None:
            return entry.provider.capabilities()
        return ProviderCapabilities(
            algorithm_id=entry.algorithm_id,
            display_name=entry.display_name,
            family=entry.family,
            standard=entry.standard,
            parameter_set=entry.parameter_set,
            backend="not implemented",
            quantum_vulnerable=entry.quantum_vulnerable,
            implemented=False,
            security_level=entry.security_level,
            notes=entry.notes,
        )


def create_default_registry() -> AlgorithmRegistry:
    """Registry with this project's full built-in configuration:

    * classical: RSA-4096 (RSASSA-PSS)
    * PQ:        ML-DSA-44/65/87 (FIPS 204), SLH-DSA-SHA2-128s (FIPS 205)
    * hybrid:    RSA4096-MLDSA (composite adapter, strict policy)

    ``mldsa65`` is the project's primary PQ parameter set; the others are
    registered to demonstrate crypto-agility (the platform can query and
    select them without code changes).
    """
    registry = AlgorithmRegistry()
    registry.register_provider(RSA4096Provider())
    registry.register_provider(MLDSAProvider("mldsa44"))
    registry.register_provider(MLDSAProvider("mldsa65"))
    registry.register_provider(MLDSAProvider("mldsa87"))
    registry.register_provider(SLHDSAProvider("slhdsa-sha2-128s"), aliases=("slhdsa",))
    registry.register_provider(
        HybridCryptoProvider(RSA4096Provider(), MLDSAProvider("mldsa65")),
        aliases=("hybrid",),
    )
    # Example of a declared-but-not-implemented candidate kept visible to
    # the migration platform:
    registry.register_candidate(
        algorithm_id="picnic",
        display_name="Picnic",
        family="pq",
        standard="research candidate (NIST round-1 signature alternate)",
        parameter_set="picnic3l1",
        security_level="NIST category 1",
        quantum_vulnerable=False,
        notes="registered as evaluated candidate only; no provider implemented",
    )
    return registry

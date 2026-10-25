"""Measured crypto performance profiles (spec sections 10.5 and 27).

The assessment engine's *performance* dimension and the benchmark report
need real numbers, not claims: key-generation / signing / verification
times plus key and signature sizes per algorithm.  This module measures
them through the same CryptoProvider interface the platform will use in
production, so the numbers reflect the actual selected implementation.

Sizes come from the provider capability records; timings are medians of
``iterations`` runs (medians are robust against scheduler noise).
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from crypto.errors import UnsupportedAlgorithmError
from crypto_agility.interfaces import CryptoProvider

DEFAULT_MESSAGE = b"A" * 1024  # 1 KiB representative payload


@dataclass(frozen=True)
class PerformanceProfile:
    """One algorithm's measured crypto-layer performance."""

    algorithm_id: str
    parameter_set: str
    backend: str
    keygen_ms: float
    sign_ms: float
    verify_ms: float
    public_key_bytes: int
    secret_key_bytes: int
    signature_bytes: int
    iterations: int
    message_bytes: int
    measured_at: str
    notes: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def measure_provider(
    provider: CryptoProvider,
    *,
    iterations: int = 5,
    message: bytes = DEFAULT_MESSAGE,
    include_keygen: bool = True,
) -> PerformanceProfile:
    """Benchmark one provider.

    RSA-4096 key generation is intentionally expensive; pass
    ``iterations=1`` (and ``include_keygen=True`` once) when benchmarking
    it, or ``include_keygen=False`` to reuse an existing capability
    number for keygen and time only sign/verify.
    """
    if iterations < 1:
        raise ValueError("iterations must be >= 1")

    # ---- key generation -------------------------------------------------
    keypair = provider.generate_keypair()
    if include_keygen:
        samples = []
        for _ in range(iterations):
            start = time.perf_counter()
            provider.generate_keypair()
            samples.append((time.perf_counter() - start) * 1000.0)
        keygen_ms = _median(samples)
    else:
        keygen_ms = -1.0  # not measured

    # ---- signing / verification (same key pair) ---------------------------
    signature = provider.sign(message, keypair.private_key)
    sign_samples, verify_samples = [], []
    for _ in range(iterations):
        start = time.perf_counter()
        provider.sign(message, keypair.private_key)
        sign_samples.append((time.perf_counter() - start) * 1000.0)
    for _ in range(iterations):
        start = time.perf_counter()
        provider.verify(message, signature, keypair.public_key)
        verify_samples.append((time.perf_counter() - start) * 1000.0)

    caps = provider.capabilities()
    notes = ""
    if keygen_ms < 0:
        notes = "keygen not measured (include_keygen=False)"
    return PerformanceProfile(
        algorithm_id=caps.algorithm_id,
        parameter_set=caps.parameter_set,
        backend=caps.backend,
        keygen_ms=round(keygen_ms, 3),
        sign_ms=round(_median(sign_samples), 3),
        verify_ms=round(_median(verify_samples), 3),
        public_key_bytes=len(keypair.public_key.data),
        secret_key_bytes=len(keypair.private_key.data),
        signature_bytes=len(signature),
        iterations=iterations,
        message_bytes=len(message),
        measured_at=datetime.now(timezone.utc).isoformat(),
        notes=notes,
    )


def measure_algorithms(registry, algorithm_ids: list[str], **kwargs) -> dict[str, dict]:
    """Benchmark several registered algorithms; returns id -> profile dict.
    Unknown or unimplemented algorithms raise UnsupportedAlgorithmError -
    the platform decides how to present that, we don't hide it."""
    profiles: dict[str, dict] = {}
    for algorithm_id in algorithm_ids:
        try:
            provider = registry.get_provider(algorithm_id)
        except Exception as exc:
            raise UnsupportedAlgorithmError(f"cannot benchmark {algorithm_id!r}: {exc}") from None
        profiles[algorithm_id] = measure_provider(provider, **kwargs).to_dict()
    return profiles


def _median(values: list[float]) -> float:
    ordered = sorted(values)
    n = len(ordered)
    mid = n // 2
    if n % 2:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2.0

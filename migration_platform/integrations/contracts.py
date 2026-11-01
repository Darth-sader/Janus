from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass
class AlgorithmCapability:
    """Normalized algorithm information received from Person 1."""
    algorithm_id: str
    name: str
    family: str
    standard: str
    security_level: str
    key_size: int | None = None
    signature_size: int | None = None
    implementation: str | None = None
    quantum_vulnerable: bool = False
    implemented: bool = False
    supported_operations: list[str] = field(default_factory=list)
    notes: str = ""


@dataclass
class AlgorithmAvailability:
    """Availability result from the crypto capability catalog."""
    algorithm_id: str
    available: bool
    reason: str


@dataclass
class ModeFeasibility:
    """Whether the crypto layer supports a requested migration mode."""
    requested_mode: str
    supported: bool
    blockers: list[str] = field(default_factory=list)
    explanation: str = ""
    requirements: dict[str, Any] = field(default_factory=dict)


@dataclass
class PerformanceProfile:
    """Measured crypto performance; missing values remain unknown."""
    algorithm_id: str
    keygen_ms: float | None = None
    sign_ms: float | None = None
    verify_ms: float | None = None
    public_key_bytes: int | None = None
    secret_key_bytes: int | None = None
    signature_bytes: int | None = None
    iterations: int | None = None
    measured_at: str | None = None
    backend: str | None = None


@dataclass
class CertificateInfo:
    """Normalized certificate information received from Person 2."""
    cert_id: str
    asset_id: str | None = None
    serial_number: str | None = None
    subject: str | None = None
    issuer: str | None = None
    mode: str | None = None
    public_key_algorithm: str | None = None
    signature_algorithm: str | None = None
    state: str | None = None
    expired: bool | None = None
    not_before: str | None = None
    not_after: str | None = None
    previous_serials: list[str] = field(default_factory=list)
    history: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class CertificateValidation:
    """Normalized certificate validation result from Person 2."""
    valid: bool
    reason: str
    issues: list[dict[str, Any]] = field(default_factory=list)


class CryptoIntegration(Protocol):
    """Contract for connecting Person 1's crypto-agility module."""

    def available_algorithms(self) -> list[dict[str, Any]]:
        ...

    def algorithm_details(self, algorithm_id: str) -> dict[str, Any]:
        ...

    def check_availability(self, algorithm_id: str) -> dict[str, Any]:
        ...

    def check_mode(self, mode: str) -> dict[str, Any]:
        ...

    def check_algorithm_for_mode(
        self, mode: str, algorithm_id: str
    ) -> dict[str, Any]:
        ...

    def measure_algorithms(
        self, algorithm_ids: list[str]
    ) -> dict[str, dict[str, Any]]:
        ...


class PKIIntegration(Protocol):
    """Contract for connecting Person 2's PKI module."""

    def get_certificate(self, cert_id: str) -> dict[str, Any]:
        ...

    def list_certificates(self) -> list[dict[str, Any]]:
        ...

    def validate_certificate(self, cert_id: str) -> dict[str, Any]:
        ...

    def migrate_certificate(
        self, cert_id: str, target_mode: str
    ) -> dict[str, Any]:
        ...

from typing import Any
from dataclasses import asdict, is_dataclass
from migration_platform.integrations.contracts import (
    AlgorithmCapability,
    CryptoIntegration,
)


class CryptoAdapter:
    """
    Adapter connecting Person 3's migration platform
    with Person 1's crypto-agility module.
    """

    def __init__(
        self,
        capability_catalog: Any,
        transition_options: Any,
        performance_measure_function: Any = None,
    ):
        self.catalog = capability_catalog
        self.transitions = transition_options
        self.measure_function = performance_measure_function

    def available_algorithms(self) -> list[dict[str, Any]]:
        return self.catalog.available_algorithms()

    def algorithm_details(self, algorithm_id: str) -> dict[str, Any]:
        return self.catalog.algorithm_details(algorithm_id)

    def check_availability(self, algorithm_id: str) -> dict[str, Any]:
        return self.catalog.check_availability(algorithm_id)

    def check_mode(self, mode: str) -> dict[str, Any]:
        result = self.transitions.check_mode(mode)
        return result.to_dict()

    def check_algorithm_for_mode(
        self, mode: str, algorithm_id: str
    ) -> dict[str, Any]:
        result = self.transitions.check_algorithm_for_mode(
            mode, algorithm_id
        )
        return result.to_dict()

    def measure_algorithms(
        self, algorithm_ids: list[str]
    ) -> dict[str, dict[str, Any]]:

        if self.measure_function is None:
            return {}

        profiles = self.measure_function(algorithm_ids)

        return {
    algorithm_id: (
        asdict(profile)
        if is_dataclass(profile)
        else profile
    )
    for algorithm_id, profile in profiles.items()
}

    def get_normalized_algorithms(self) -> list[AlgorithmCapability]:
        normalized = []

        for algorithm in self.available_algorithms():
            algorithm_id = algorithm.get("algorithm_id")

            if not algorithm_id:
                continue

            normalized.append(
                AlgorithmCapability(
                    algorithm_id=algorithm_id,
                    name=algorithm.get("name", algorithm_id),
                    family=algorithm.get("family", "unknown"),
                    standard=algorithm.get("standard", "unknown"),
                    security_level=str(
                        algorithm.get("security_level", "unknown")
                    ),
                    key_size=algorithm.get("key_size"),
                    signature_size=algorithm.get("signature_size"),
                    implementation=algorithm.get("implementation"),
                    quantum_vulnerable=algorithm.get(
                        "quantum_vulnerable", False
                    ),
                    implemented=algorithm.get("implemented", False),
                    supported_operations=algorithm.get(
                        "supported_operations", []
                    ),
                    notes=algorithm.get("notes", ""),
                )
            )

        return normalized
from typing import Any


class RecommendationEngine:
    """
    Generates deterministic, explainable migration recommendations.

    Recommendations do not authorize or execute production migrations.
    """

    def recommend(
        self,
        assessment: dict,
        current_algorithm: str | None,
        algorithm_capabilities: list[Any],
        mode_feasibility: dict[str, dict] | None = None,
    ) -> dict:

        mode_feasibility = mode_feasibility or {}

        def get_value(obj, field, default=None):
            if isinstance(obj, dict):
                return obj.get(field, default)
            return getattr(obj, field, default)

        evidence = []
        outcome = "MONITOR"
        target_algorithm = None
        migration_mode = None
        priority = assessment.get(
            "migration_priority", "UNASSESSED"
        )

        # Find available and implemented algorithms.
        algorithms = {
            get_value(item, "algorithm_id"): item
            for item in algorithm_capabilities
            if get_value(item, "algorithm_id")
        }

        implemented_pq = [
            algorithm_id
            for algorithm_id, item in algorithms.items()
            if get_value(item, "family") in ("pq", "hybrid")
            and get_value(item, "implemented") is True
        ]

        hybrid_candidates = [
            algorithm_id
            for algorithm_id, item in algorithms.items()
            if get_value(item, "family") == "hybrid"
            and get_value(item, "implemented") is True
        ]

        # Check whether the asset can support migration.
        compatibility = assessment.get(
            "compatibility_status", "UNKNOWN"
        )

        security = assessment.get(
            "security_status", "UNKNOWN"
        )

        performance = assessment.get(
            "performance_status", "UNKNOWN"
        )

        if security == "UNKNOWN":
            evidence.append(
                "Current algorithm security information is unknown."
            )

        elif security == "HIGH_RISK":
            evidence.append(
                "The current cryptographic algorithm is quantum-vulnerable."
            )

        if compatibility == "RESTRICTED":
            outcome = "REPLACEMENT REQUIRED"
            evidence.append(
                "The asset does not support software or firmware updates."
            )

        elif security == "UNKNOWN":
            outcome = "MONITOR"

        elif security == "HIGH_RISK":

            if not implemented_pq and not hybrid_candidates:
                outcome = "MONITOR"
                evidence.append(
                    "No implemented PQ or hybrid target is available."
                )

            elif hybrid_candidates:
                feasible = mode_feasibility.get("hybrid", {})

                if feasible.get("supported") is True:
                    outcome = "HYBRID MIGRATION"
                    migration_mode = "hybrid"
                    target_algorithm = hybrid_candidates[0]

                    evidence.append(
                        "An implemented hybrid algorithm is available "
                        "and the crypto layer supports hybrid mode."
                    )
                else:
                    outcome = "MONITOR"
                    evidence.append(
                        "Hybrid migration feasibility has not been confirmed."
                    )

            elif implemented_pq:
                feasible = mode_feasibility.get("pq", {})

                if feasible.get("supported") is True:
                    outcome = "PQ MIGRATION"
                    migration_mode = "pq"
                    target_algorithm = implemented_pq[0]

                    evidence.append(
                        "An implemented PQ algorithm is available "
                        "and PQ migration mode is supported."
                    )
                else:
                    outcome = "MONITOR"
                    evidence.append(
                        "PQ migration feasibility has not been confirmed."
                    )

        elif security == "LOWER_QUANTUM_RISK":
            outcome = "MAINTAIN"
            evidence.append(
                "No quantum vulnerability was reported for the current algorithm."
            )

        if performance == "UNKNOWN":
            evidence.append(
                "Performance measurements are unavailable; "
                "performance suitability remains unverified."
            )

        return {
            "current_algorithm": current_algorithm,
            "target_algorithm": target_algorithm,
            "migration_mode": migration_mode,
            "outcome": outcome,
            "priority": priority,
            "reasoning": " ".join(evidence),
            "evidence": {
                "assessment": assessment,
                "decision_factors": evidence,
                "performance_verified": performance == "MEASURED",
            },
            "requires_human_approval": outcome in [
                "HYBRID MIGRATION",
                "PQ MIGRATION",
                "REPLACEMENT REQUIRED",
            ],
        }
from typing import Any


class AssessmentEngine:
    """
    Evaluates infrastructure assets across five dimensions.

    This engine produces explainable assessments.
    It does not execute migrations or authorize production changes.
    """

    def assess(
        self,
        asset: Any,
        crypto_configs: list[Any],
        algorithm_capabilities: list[Any],
        performance_profiles: dict[str, Any] | None = None,
    ) -> dict:

        performance_profiles = performance_profiles or {}
        evidence = {}

        # Convert SQLAlchemy objects or dataclasses into dictionaries.
        def get_value(obj, field, default=None):
            if isinstance(obj, dict):
                return obj.get(field, default)
            return getattr(obj, field, default)

        # 1. SECURITY ASSESSMENT
        security_status = "UNKNOWN"
        current_algorithm = None

        if crypto_configs:
            active_configs = [
                config for config in crypto_configs
                if get_value(config, "status", "ACTIVE") == "ACTIVE"
            ]

            if active_configs:
                current_algorithm = get_value(
                    active_configs[0], "algorithm"
                )

        capability = next(
            (
                algorithm for algorithm in algorithm_capabilities
                if get_value(algorithm, "algorithm_id")
                == current_algorithm
            ),
            None,
        )

        if capability is not None:
            vulnerable = get_value(
                capability, "quantum_vulnerable"
            )

            if vulnerable is True:
                security_status = "HIGH_RISK"
            elif vulnerable is False:
                security_status = "LOWER_QUANTUM_RISK"
            else:
                security_status = "UNKNOWN"

        evidence["security"] = {
            "current_algorithm": current_algorithm,
            "quantum_vulnerable": (
                get_value(capability, "quantum_vulnerable")
                if capability else None
            ),
            "status": security_status,
        }

        # 2. CRITICALITY ASSESSMENT
        criticality = get_value(asset, "criticality", "UNKNOWN")

        if criticality == "CRITICAL":
            criticality_status = "VERY_HIGH"
        elif criticality == "HIGH":
            criticality_status = "HIGH"
        elif criticality == "MEDIUM":
            criticality_status = "MEDIUM"
        elif criticality == "LOW":
            criticality_status = "LOW"
        else:
            criticality_status = "UNKNOWN"

        evidence["criticality"] = {
            "value": criticality,
            "status": criticality_status,
        }

        # 3. OPERATIONAL LIFECYCLE ASSESSMENT
        lifetime = get_value(asset, "operational_lifetime")

        if lifetime is None:
            lifecycle_status = "UNKNOWN"
        elif lifetime <= 2:
            lifecycle_status = "SHORT"
        elif lifetime <= 5:
            lifecycle_status = "MEDIUM"
        else:
            lifecycle_status = "LONG"

        evidence["lifecycle"] = {
            "remaining_years": lifetime,
            "status": lifecycle_status,
        }

        # 4. COMPATIBILITY ASSESSMENT
        update_capability = get_value(
            asset, "update_capability"
        )

        if update_capability is True:
            compatibility_status = "UPDATE_CAPABLE"
        elif update_capability is False:
            compatibility_status = "RESTRICTED"
        else:
            compatibility_status = "UNKNOWN"

        evidence["compatibility"] = {
            "firmware_version": get_value(
                asset, "firmware_version"
            ),
            "protocol": get_value(asset, "protocol"),
            "update_capability": update_capability,
            "status": compatibility_status,
        }

        # 5. PERFORMANCE ASSESSMENT
        performance_status = "UNKNOWN"

        if current_algorithm in performance_profiles:
            profile = performance_profiles[current_algorithm]

            measured = any(
                get_value(profile, field) is not None
                for field in [
                    "keygen_ms",
                    "sign_ms",
                    "verify_ms",
                    "public_key_bytes",
                    "signature_bytes",
                ]
            )

            if measured:
                performance_status = "MEASURED"

        evidence["performance"] = {
            "status": performance_status,
            "profile_available": (
                current_algorithm in performance_profiles
            ),
        }

        # OVERALL MIGRATION PRIORITY
        if (
            security_status == "HIGH_RISK"
            and criticality_status in ["VERY_HIGH", "HIGH"]
        ):
            priority = "CRITICAL"

        elif security_status == "HIGH_RISK":
            priority = "HIGH"

        elif security_status == "UNKNOWN":
            priority = "UNASSESSED"

        else:
            priority = "NORMAL"

        return {
            "security_status": security_status,
            "compatibility_status": compatibility_status,
            "performance_status": performance_status,
            "lifecycle_status": lifecycle_status,
            "migration_priority": priority,
            "evidence": evidence,
        }
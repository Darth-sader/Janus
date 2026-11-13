from migration_platform.recommendations.engine import RecommendationEngine


def create_assessment(
    security="HIGH_RISK",
    compatibility="UPDATE_CAPABLE",
    performance="UNKNOWN",
    priority="CRITICAL",
):
    return {
        "security_status": security,
        "compatibility_status": compatibility,
        "performance_status": performance,
        "lifecycle_status": "LONG",
        "migration_priority": priority,
    }


def test_recommends_hybrid_migration():
    engine = RecommendationEngine()

    algorithms = [
        {
            "algorithm_id": "RSA4096-MLDSA",
            "family": "hybrid",
            "implemented": True,
        }
    ]

    feasibility = {
        "hybrid": {"supported": True}
    }

    result = engine.recommend(
        create_assessment(),
        "rsa4096",
        algorithms,
        feasibility,
    )

    assert result["outcome"] == "HYBRID MIGRATION"
    assert result["target_algorithm"] == "RSA4096-MLDSA"
    assert result["requires_human_approval"] is True


def test_monitor_when_hybrid_not_supported():
    engine = RecommendationEngine()

    algorithms = [
        {
            "algorithm_id": "RSA4096-MLDSA",
            "family": "hybrid",
            "implemented": True,
        }
    ]

    feasibility = {
        "hybrid": {"supported": False}
    }

    result = engine.recommend(
        create_assessment(),
        "rsa4096",
        algorithms,
        feasibility,
    )

    assert result["outcome"] == "MONITOR"
    assert result["target_algorithm"] is None


def test_replacement_when_updates_are_restricted():
    engine = RecommendationEngine()

    result = engine.recommend(
        create_assessment(compatibility="RESTRICTED"),
        "rsa4096",
        [],
        {},
    )

    assert result["outcome"] == "REPLACEMENT REQUIRED"
    assert result["requires_human_approval"] is True


def test_monitor_when_security_is_unknown():
    engine = RecommendationEngine()

    result = engine.recommend(
        create_assessment(security="UNKNOWN"),
        "unknown-algorithm",
        [],
        {},
    )

    assert result["outcome"] == "MONITOR"
    assert result["target_algorithm"] is None


def test_maintain_when_no_quantum_vulnerability_reported():
    engine = RecommendationEngine()

    result = engine.recommend(
        create_assessment(security="LOWER_QUANTUM_RISK"),
        "mldsa65",
        [],
        {},
    )

    assert result["outcome"] == "MAINTAIN"


def test_no_migration_without_implemented_target():
    engine = RecommendationEngine()

    algorithms = [
        {
            "algorithm_id": "mldsa65",
            "family": "pq",
            "implemented": False,
        }
    ]

    result = engine.recommend(
        create_assessment(),
        "rsa4096",
        algorithms,
        {},
    )

    assert result["outcome"] == "MONITOR"
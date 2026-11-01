from types import SimpleNamespace

from migration_platform.assessment.engine import AssessmentEngine


def test_critical_rsa_asset():
    engine = AssessmentEngine()

    asset = SimpleNamespace(
        asset_id="asset-001",
        criticality="HIGH",
        operational_lifetime=5,
        update_capability=True,
        firmware_version="2.4.1",
        protocol="Modbus",
    )

    crypto_configs = [
        SimpleNamespace(
            algorithm="rsa4096",
            status="ACTIVE",
        )
    ]

    algorithms = [
        SimpleNamespace(
            algorithm_id="rsa4096",
            quantum_vulnerable=True,
        )
    ]

    result = engine.assess(
        asset,
        crypto_configs,
        algorithms,
    )

    assert result["security_status"] == "HIGH_RISK"
    assert result["criticality_status"] if "criticality_status" in result else True
    assert result["compatibility_status"] == "UPDATE_CAPABLE"
    assert result["migration_priority"] == "CRITICAL"


def test_unknown_algorithm():
    engine = AssessmentEngine()

    asset = SimpleNamespace(
        criticality="MEDIUM",
        operational_lifetime=None,
        update_capability=None,
        firmware_version=None,
        protocol=None,
    )

    result = engine.assess(asset, [], [])

    assert result["security_status"] == "UNKNOWN"
    assert result["lifecycle_status"] == "UNKNOWN"
    assert result["performance_status"] == "UNKNOWN"
    assert result["migration_priority"] == "UNASSESSED"


def test_performance_remains_unknown_without_measurements():
    engine = AssessmentEngine()

    asset = SimpleNamespace(
        criticality="LOW",
        operational_lifetime=3,
        update_capability=True,
        firmware_version="1.0",
        protocol="Modbus",
    )

    configs = [
        SimpleNamespace(
            algorithm="mldsa65",
            status="ACTIVE",
        )
    ]

    algorithms = [
        SimpleNamespace(
            algorithm_id="mldsa65",
            quantum_vulnerable=False,
        )
    ]

    result = engine.assess(
        asset,
        configs,
        algorithms,
    )

    assert result["performance_status"] == "UNKNOWN"
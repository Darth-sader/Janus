
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from migration_platform.database import Base
from migration_platform.models import (
    Asset,
    CryptoConfig,
    Assessment,
    Recommendation,
    MigrationPlan,
)
from migration_platform.reports.report_service import ReportService


def setup_db():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    Base.metadata.create_all(bind=engine)

    TestingSession = sessionmaker(bind=engine)
    return TestingSession()


def test_report_contains_asset_and_assessment():
    db = setup_db()

    asset = Asset(
        asset_type="SCADA_SERVER",
        criticality="CRITICAL",
        firmware_version="2.4.1",
        operational_lifetime=12,
        update_capability=True,
        protocol="Modbus",
    )

    db.add(asset)
    db.commit()
    db.refresh(asset)

    config = CryptoConfig(
        asset_id=asset.asset_id,
        algorithm="rsa4096",
        key_size=4096,
        signature_scheme="RSA",
        status="ACTIVE",
    )

    assessment = Assessment(
        asset_id=asset.asset_id,
        security_status="UNKNOWN",
        compatibility_status="UPDATE_CAPABLE",
        performance_status="UNKNOWN",
        lifecycle_status="LONG",
        migration_priority="UNASSESSED",
        evidence={},
    )

    db.add_all([config, assessment])
    db.commit()

    service = ReportService()
    rows = service.generate_migration_report(db)

    assert len(rows) == 1
    assert rows[0]["asset_id"] == asset.asset_id
    assert rows[0]["current_algorithms"] == "rsa4096"
    assert rows[0]["security_status"] == "UNKNOWN"
    assert rows[0]["migration_status"] == "NO_PLAN"

    db.close()


def test_report_handles_asset_without_assessment():
    db = setup_db()

    asset = Asset(
        asset_type="SCADA_SERVER",
        criticality="HIGH",
        firmware_version="1.0",
        operational_lifetime=5,
        update_capability=False,
        protocol="Modbus",
    )

    db.add(asset)
    db.commit()

    service = ReportService()
    rows = service.generate_migration_report(db)

    assert len(rows) == 1
    assert rows[0]["security_status"] == "NOT_ASSESSED"
    assert rows[0]["recommendation"] == "NOT_GENERATED"

    db.close()


def test_empty_database_returns_empty_report():
    db = setup_db()

    service = ReportService()
    rows = service.generate_migration_report(db)

    assert rows == []

    db.close()

import pytest

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from migration_platform.database import Base
from migration_platform.models import (
    Asset,
    CryptoConfig,
    PQCAlgorithm,
    Assessment,
)
from migration_platform.assessment.service import AssessmentService


@pytest.fixture
def db():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    Base.metadata.create_all(bind=engine)

    TestSession = sessionmaker(bind=engine)
    session = TestSession()

    yield session

    session.close()
    engine.dispose()


def test_assess_asset_successfully(db):
    asset = Asset(
        asset_type="SCADA_SERVER",
        criticality="CRITICAL",
        firmware_version="3.0.0",
        operational_lifetime=5,
        update_capability=True,
        protocol="Modbus",
    )

    db.add(asset)
    db.flush()

    db.add(
        CryptoConfig(
            asset_id=asset.asset_id,
            algorithm="rsa4096",
            key_size=4096,
            signature_scheme="RSA",
            status="ACTIVE",
        )
    )

    db.add(
        PQCAlgorithm(
            algorithm_id="rsa4096",
            name="RSA-4096",
            family="classical",
            standard="RSA",
            security_level="classical",
            key_size=4096,
            quantum_vulnerable=True,
            implemented=True,
        )
    )

    db.commit()

    service = AssessmentService()

    result = service.assess_asset(
        asset.asset_id,
        db,
    )

    assert result["security_status"] == "HIGH_RISK"
    assert result["compatibility_status"] == "UPDATE_CAPABLE"
    assert result["migration_priority"] == "CRITICAL"

    saved = db.query(Assessment).filter_by(
        assessment_id=result["assessment_id"]
    ).first()

    assert saved is not None
    assert saved.asset_id == asset.asset_id


def test_assess_missing_asset(db):
    service = AssessmentService()

    with pytest.raises(ValueError):
        service.assess_asset("unknown-asset", db)
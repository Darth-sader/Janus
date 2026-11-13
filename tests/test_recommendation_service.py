
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
from migration_platform.recommendations.service import RecommendationService


@pytest.fixture
def db():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    Base.metadata.create_all(bind=engine)

    TestingSession = sessionmaker(bind=engine)
    session = TestingSession()

    yield session

    session.close()
    Base.metadata.drop_all(bind=engine)


def test_generate_recommendation_for_asset(db):
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

    algorithm = PQCAlgorithm(
        algorithm_id="mldsa65",
        name="ML-DSA-65",
        family="pq",
        standard="FIPS 204",
        security_level="3",
        key_size=1952,
        signature_size=3309,
        implementation=True,
        quantum_vulnerable=False,
        implemented=True,
    )

    assessment = Assessment(
        asset_id=asset.asset_id,
        security_status="HIGH_RISK",
        compatibility_status="UPDATE_CAPABLE",
        performance_status="UNKNOWN",
        lifecycle_status="LONG",
        migration_priority="CRITICAL",
        evidence={},
    )

    db.add_all([config, algorithm, assessment])
    db.commit()

    service = RecommendationService()

    result = service.generate_for_asset(
        asset_id=asset.asset_id,
        db=db,
    )

    assert result["asset_id"] == asset.asset_id
    assert result["current_algorithm"] == "rsa4096"
    assert result["outcome"] in [
        "MONITOR",
        "HYBRID MIGRATION",
        "PQ MIGRATION",
    ]

    saved = db.query(Assessment).filter(
        Assessment.asset_id == asset.asset_id
    ).first()

    assert saved is not None

    from migration_platform.models import Recommendation

    recommendation = db.query(Recommendation).filter(
        Recommendation.asset_id == asset.asset_id
    ).first()

    assert recommendation is not None
    assert recommendation.outcome == result["outcome"]


def test_missing_asset_raises_error(db):
    service = RecommendationService()

    with pytest.raises(ValueError, match="Asset not found"):
        service.generate_for_asset(
            asset_id="non-existent-id",
            db=db,
        )


def test_missing_assessment_raises_error(db):
    asset = Asset(
        asset_type="SCADA_SERVER",
        criticality="HIGH",
        firmware_version="1.0",
        operational_lifetime=5,
        update_capability=True,
        protocol="Modbus",
    )

    db.add(asset)
    db.commit()
    db.refresh(asset)

    service = RecommendationService()

    with pytest.raises(ValueError, match="assess this asset"):
        service.generate_for_asset(
            asset_id=asset.asset_id,
            db=db,
        )

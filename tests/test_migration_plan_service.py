
import pytest

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from migration_platform.database import Base
from migration_platform.models import (
    Asset,
    Assessment,
    Recommendation,
    MigrationPlan,
)
from migration_platform.migrations.service import MigrationPlanService


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


def create_migration_recommendation(db, outcome="HYBRID MIGRATION"):
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

    assessment = Assessment(
        asset_id=asset.asset_id,
        security_status="HIGH_RISK",
        compatibility_status="UPDATE_CAPABLE",
        performance_status="UNKNOWN",
        lifecycle_status="LONG",
        migration_priority="CRITICAL",
        evidence={},
    )
    db.add(assessment)
    db.commit()
    db.refresh(assessment)

    recommendation = Recommendation(
        asset_id=asset.asset_id,
        assessment_id=assessment.assessment_id,
        current_algorithm="rsa4096",
        target_algorithm="RSA4096-MLDSA",
        migration_mode="hybrid",
        outcome=outcome,
        priority="CRITICAL",
        reasoning="Test recommendation",
        evidence={},
    )
    db.add(recommendation)
    db.commit()
    db.refresh(recommendation)

    return recommendation


def test_create_draft_plan(db):
    recommendation = create_migration_recommendation(db)
    service = MigrationPlanService()

    plan = service.create_draft(recommendation.recommendation_id, db)

    assert plan.asset_id == recommendation.asset_id
    assert plan.recommendation_id == recommendation.recommendation_id
    assert plan.status == "DRAFT"
    assert plan.approval_status == "PENDING"
    assert plan.approved_by is None


def test_reject_non_migration_recommendation(db):
    recommendation = create_migration_recommendation(
        db,
        outcome="MONITOR"
    )
    service = MigrationPlanService()

    with pytest.raises(ValueError, match="migration recommendation"):
        service.create_draft(recommendation.recommendation_id, db)


def test_reject_missing_recommendation(db):
    service = MigrationPlanService()

    with pytest.raises(ValueError, match="Recommendation not found"):
        service.create_draft("missing-id", db)


def test_approve_plan(db):
    recommendation = create_migration_recommendation(db)
    service = MigrationPlanService()

    plan = service.create_draft(recommendation.recommendation_id, db)

    approved = service.approve_plan(
        migration_id=plan.migration_id,
        approved_by="Project Administrator",
        db=db,
    )

    assert approved.approval_status == "APPROVED"
    assert approved.approved_by == "Project Administrator"
    assert approved.approved_at is not None


def test_reject_empty_approver(db):
    recommendation = create_migration_recommendation(db)
    service = MigrationPlanService()

    plan = service.create_draft(recommendation.recommendation_id, db)

    with pytest.raises(ValueError, match="Approver identity"):
        service.approve_plan(
            migration_id=plan.migration_id,
            approved_by=" ",
            db=db,
        )

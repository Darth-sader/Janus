
import pytest

from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from migration_platform.database import Base
from migration_platform.models import (
    Asset,
    Assessment,
    Recommendation,
    MigrationPlan,
    ChecklistItem,
)
from migration_platform.migrations.status_service import MigrationStatusService


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


def create_plan(db, approved=False):
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
        outcome="HYBRID MIGRATION",
        priority="CRITICAL",
        reasoning="Test recommendation",
        evidence={},
    )
    db.add(recommendation)
    db.commit()
    db.refresh(recommendation)

    plan = MigrationPlan(
        asset_id=asset.asset_id,
        recommendation_id=recommendation.recommendation_id,
        target_algorithm="RSA4096-MLDSA",
        target_mode="hybrid",
        status="DRAFT",
        approval_status="APPROVED" if approved else "PENDING",
        approved_by="Project Administrator" if approved else None,
    )

    db.add(plan)
    db.commit()
    db.refresh(plan)

    return plan


def test_reject_start_without_approval(db):
    plan = create_plan(db)
    service = MigrationStatusService()

    with pytest.raises(ValueError, match="Human approval"):
        service.start_migration(plan.migration_id, db)


def test_start_approved_migration(db):
    plan = create_plan(db, approved=True)
    service = MigrationStatusService()

    updated = service.start_migration(plan.migration_id, db)

    assert updated.status == "IN_PROGRESS"
    assert updated.started_at is not None


def test_reject_completion_with_incomplete_checklist(db):
    plan = create_plan(db, approved=True)
    service = MigrationStatusService()

    service.start_migration(plan.migration_id, db)

    item = ChecklistItem(
        migration_id=plan.migration_id,
        title="Verify asset inventory",
        description="Check asset details",
        status="PENDING",
        sort_order=1,
    )
    db.add(item)
    db.commit()

    with pytest.raises(ValueError, match="still incomplete"):
        service.complete_migration(plan.migration_id, db)


def test_complete_migration_when_checklist_is_finished(db):
    plan = create_plan(db, approved=True)
    service = MigrationStatusService()

    service.start_migration(plan.migration_id, db)

    for index in range(1, 4):
        item = ChecklistItem(
            migration_id=plan.migration_id,
            title=f"Task {index}",
            description=f"Test task {index}",
            status="COMPLETED",
            sort_order=index,
            completed_by="Project Administrator",
            completed_at=datetime.now(timezone.utc),
        )
        db.add(item)

    db.commit()

    updated = service.complete_migration(plan.migration_id, db)

    assert updated.status == "COMPLETED"
    assert updated.completed_at is not None


def test_reject_missing_migration_plan(db):
    service = MigrationStatusService()

    with pytest.raises(ValueError, match="Migration plan not found"):
        service.start_migration("missing-id", db)


def test_reject_starting_already_started_plan(db):
    plan = create_plan(db, approved=True)
    service = MigrationStatusService()

    service.start_migration(plan.migration_id, db)

    with pytest.raises(ValueError, match="DRAFT status"):
        service.start_migration(plan.migration_id, db)

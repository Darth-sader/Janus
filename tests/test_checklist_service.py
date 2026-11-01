
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
    ChecklistItem,
)
from migration_platform.migrations.checklist_service import ChecklistService


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


def create_plan(db):
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
        reasoning="Test migration recommendation",
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
        approval_status="PENDING",
    )
    db.add(plan)
    db.commit()
    db.refresh(plan)

    return plan


def test_create_checklist(db):
    plan = create_plan(db)
    service = ChecklistService()

    items = service.create_for_plan(plan.migration_id, db)

    assert len(items) == 9
    assert all(item.status == "PENDING" for item in items)

    saved_count = db.query(ChecklistItem).filter(
        ChecklistItem.migration_id == plan.migration_id
    ).count()

    assert saved_count == 9


def test_reject_duplicate_checklist(db):
    plan = create_plan(db)
    service = ChecklistService()

    service.create_for_plan(plan.migration_id, db)

    with pytest.raises(ValueError, match="already exists"):
        service.create_for_plan(plan.migration_id, db)


def test_reject_missing_plan(db):
    service = ChecklistService()

    with pytest.raises(ValueError, match="Migration plan not found"):
        service.create_for_plan("missing-id", db)


def test_list_checklist_in_order(db):
    plan = create_plan(db)
    service = ChecklistService()

    created = service.create_for_plan(plan.migration_id, db)
    listed = service.list_for_plan(plan.migration_id, db)

    assert len(listed) == 9
    assert [item.sort_order for item in listed] == list(range(1, 10))
    assert listed[0].title == created[0].title


def test_list_checklist_for_missing_plan(db):
    service = ChecklistService()

    with pytest.raises(ValueError, match="Migration plan not found"):
        service.list_for_plan("missing-id", db)


def test_complete_checklist_item(db):
    plan = create_plan(db)
    service = ChecklistService()

    service.create_for_plan(plan.migration_id, db)

    item = service.complete_item(
        migration_id=plan.migration_id,
        sort_order=1,
        completed_by="Project Administrator",
        db=db,
        evidence={"verification": "Asset inventory checked"},
    )

    assert item.status == "COMPLETED"
    assert item.completed_by == "Project Administrator"
    assert item.completed_at is not None
    assert item.evidence["verification"] == "Asset inventory checked"


def test_reject_missing_checklist_item(db):
    plan = create_plan(db)
    service = ChecklistService()

    service.create_for_plan(plan.migration_id, db)

    with pytest.raises(ValueError, match="Checklist item not found"):
        service.complete_item(
            migration_id=plan.migration_id,
            sort_order=100,
            completed_by="Project Administrator",
            db=db,
        )


def test_reject_empty_completed_by(db):
    plan = create_plan(db)
    service = ChecklistService()

    service.create_for_plan(plan.migration_id, db)

    with pytest.raises(ValueError, match="Completed-by identity"):
        service.complete_item(
            migration_id=plan.migration_id,
            sort_order=1,
            completed_by=" ",
            db=db,
        )


def test_reject_completing_item_twice(db):
    plan = create_plan(db)
    service = ChecklistService()

    service.create_for_plan(plan.migration_id, db)

    service.complete_item(
        migration_id=plan.migration_id,
        sort_order=1,
        completed_by="Project Administrator",
        db=db,
    )

    with pytest.raises(ValueError, match="already completed"):
        service.complete_item(
            migration_id=plan.migration_id,
            sort_order=1,
            completed_by="Project Administrator",
            db=db,
        )

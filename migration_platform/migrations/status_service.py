
from sqlalchemy.orm import Session

from migration_platform.models import MigrationPlan, ChecklistItem
from datetime import datetime, timezone

class MigrationStatusService:

    def start_migration(self, migration_id: str, db: Session):

        plan = db.query(MigrationPlan).filter(
            MigrationPlan.migration_id == migration_id
        ).first()

        if not plan:
            raise ValueError("Migration plan not found")

        if plan.approval_status != "APPROVED":
            raise ValueError("Human approval is required before starting migration")

        if plan.status != "DRAFT":
            raise ValueError("Migration plan must be in DRAFT status to start")

        try:
            plan.status = "IN_PROGRESS"
            plan.started_at = datetime.now(timezone.utc)
            db.commit()
            db.refresh(plan)
        except Exception:
            db.rollback()
            raise

        return plan

    def complete_migration(self, migration_id: str, db: Session):

        plan = db.query(MigrationPlan).filter(
            MigrationPlan.migration_id == migration_id
        ).first()

        if not plan:
            raise ValueError("Migration plan not found")

        if plan.status != "IN_PROGRESS":
            raise ValueError("Only an IN_PROGRESS migration can be completed")

        items = db.query(ChecklistItem).filter(
            ChecklistItem.migration_id == migration_id
        ).all()

        if not items:
            raise ValueError("Migration checklist does not exist")

        incomplete_items = [
            item for item in items
            if item.status != "COMPLETED"
        ]

        if incomplete_items:
            raise ValueError(
                f"{len(incomplete_items)} checklist items are still incomplete"
            )

        try:
            plan.status = "COMPLETED"
            plan.completed_at = datetime.now(timezone.utc)
            db.commit()
            db.refresh(plan)
        except Exception:
            db.rollback()
            raise

        return plan


from sqlalchemy.orm import Session

from migration_platform.models import MigrationPlan, ChecklistItem
from datetime import datetime, timezone


DEFAULT_CHECKLIST = [
    (
        "Verify asset inventory",
        "Confirm asset details, firmware, protocol and current cryptographic configuration."
    ),
    (
        "Verify algorithm availability",
        "Confirm the target algorithm is registered and implemented by the crypto provider."
    ),
    (
        "Verify transition feasibility",
        "Check whether the requested classical, hybrid or post-quantum mode is supported."
    ),
    (
        "Check device compatibility",
        "Review firmware support, hardware resources, protocol compatibility and update capability."
    ),
    (
        "Review performance measurements",
        "Check available key generation, signing, verification and size measurements."
    ),
    (
        "Coordinate certificate lifecycle",
        "Coordinate certificate issuance, renewal or migration requirements with the PKI module."
    ),
    (
        "Prepare backup and recovery",
        "Document configuration backup, recovery procedures and rollback arrangements."
    ),
    (
        "Schedule migration",
        "Confirm the maintenance window, responsible team and operational impact."
    ),
    (
        "Verify human approval",
        "Confirm that the migration plan has recorded approval before execution."
    ),
]


class ChecklistService:

    def create_for_plan(self, migration_id: str, db: Session):

        plan = db.query(MigrationPlan).filter(
            MigrationPlan.migration_id == migration_id
        ).first()

        if not plan:
            raise ValueError("Migration plan not found")

        existing = db.query(ChecklistItem).filter(
            ChecklistItem.migration_id == migration_id
        ).count()

        if existing:
            raise ValueError("Checklist already exists for this migration plan")

        items = []

        for index, (title, description) in enumerate(DEFAULT_CHECKLIST, start=1):
            item = ChecklistItem(
                migration_id=migration_id,
                title=title,
                description=description,
                status="PENDING",
                sort_order=index,
            )
            items.append(item)

        try:
            db.add_all(items)
            db.commit()

            for item in items:
                db.refresh(item)

        except Exception:
            db.rollback()
            raise

        return items

    def list_for_plan(self, migration_id: str, db: Session):

        plan = db.query(MigrationPlan).filter(
            MigrationPlan.migration_id == migration_id
        ).first()

        if not plan:
            raise ValueError("Migration plan not found")

        return (
            db.query(ChecklistItem)
            .filter(ChecklistItem.migration_id == migration_id)
            .order_by(ChecklistItem.sort_order)
            .all()
        )
    def complete_item(
        self,
        migration_id: str,
        sort_order: int,
        completed_by: str,
        db: Session,
        evidence: dict | None = None,
    ):

        if not completed_by or not completed_by.strip():
            raise ValueError("Completed-by identity is required")

        plan = db.query(MigrationPlan).filter(
            MigrationPlan.migration_id == migration_id
        ).first()

        if not plan:
            raise ValueError("Migration plan not found")

        item = db.query(ChecklistItem).filter(
            ChecklistItem.migration_id == migration_id,
            ChecklistItem.sort_order == sort_order
        ).first()

        if not item:
            raise ValueError("Checklist item not found")

        if item.status == "COMPLETED":
            raise ValueError("Checklist item is already completed")

        item.status = "COMPLETED"
        item.completed_by = completed_by.strip()
        item.completed_at = datetime.now(timezone.utc)
        item.evidence = evidence or {}

        try:
            db.commit()
            db.refresh(item)
        except Exception:
            db.rollback()
            raise

        return item

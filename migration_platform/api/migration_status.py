
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from migration_platform.database import get_db
from migration_platform.migrations.status_service import MigrationStatusService

router = APIRouter(
    prefix="/migration-plans",
    tags=["Migration Status"]
)

service = MigrationStatusService()


def status_to_dict(plan):
    return {
        "migration_id": plan.migration_id,
        "asset_id": plan.asset_id,
        "status": plan.status,
        "approval_status": plan.approval_status,
        "started_at": (
            plan.started_at.isoformat()
            if plan.started_at else None
        ),
        "completed_at": (
            plan.completed_at.isoformat()
            if plan.completed_at else None
        ),
    }


@router.post("/{migration_id}/start")
def start_migration(
    migration_id: str,
    db: Session = Depends(get_db)
):
    try:
        plan = service.start_migration(migration_id, db)
        return status_to_dict(plan)

    except ValueError as error:
        message = str(error)
        status_code = (
            404 if "not found" in message.lower() else 400
        )
        raise HTTPException(
            status_code=status_code,
            detail=message
        )


@router.post("/{migration_id}/complete")
def complete_migration(
    migration_id: str,
    db: Session = Depends(get_db)
):
    try:
        plan = service.complete_migration(migration_id, db)
        return status_to_dict(plan)

    except ValueError as error:
        message = str(error)
        status_code = (
            404 if "not found" in message.lower() else 400
        )
        raise HTTPException(
            status_code=status_code,
            detail=message
        )

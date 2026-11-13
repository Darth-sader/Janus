
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from migration_platform.database import get_db
from migration_platform.migrations.service import MigrationPlanService

router = APIRouter(
    prefix="/migration-plans",
    tags=["Migration Plans"]
)

service = MigrationPlanService()


class ApprovalRequest(BaseModel):
    approved_by: str


def plan_to_dict(plan):
    return {
        "migration_id": plan.migration_id,
        "asset_id": plan.asset_id,
        "recommendation_id": plan.recommendation_id,
        "target_algorithm": plan.target_algorithm,
        "target_mode": plan.target_mode,
        "status": plan.status,
        "approval_status": plan.approval_status,
        "approved_by": plan.approved_by,
        "approved_at": (
            plan.approved_at.isoformat()
            if plan.approved_at else None
        ),
        "created_at": (
            plan.created_at.isoformat()
            if plan.created_at else None
        ),
    }


@router.post("/recommendation/{recommendation_id}")
def create_migration_plan(
    recommendation_id: str,
    db: Session = Depends(get_db)
):
    try:
        plan = service.create_draft(recommendation_id, db)
        return plan_to_dict(plan)

    except ValueError as error:
        message = str(error)
        status_code = (
            404 if "not found" in message.lower() else 400
        )
        raise HTTPException(
            status_code=status_code,
            detail=message
        )


@router.post("/{migration_id}/approve")
def approve_migration_plan(
    migration_id: str,
    request: ApprovalRequest,
    db: Session = Depends(get_db)
):
    try:
        plan = service.approve_plan(
            migration_id=migration_id,
            approved_by=request.approved_by,
            db=db
        )
        return plan_to_dict(plan)

    except ValueError as error:
        message = str(error)
        status_code = (
            404 if "not found" in message.lower() else 400
        )
        raise HTTPException(
            status_code=status_code,
            detail=message
        )

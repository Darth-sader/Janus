
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from migration_platform.database import get_db
from migration_platform.migrations.checklist_service import ChecklistService
from pydantic import BaseModel, Field
from typing import Any

router = APIRouter(
    prefix="/migration-plans",
    tags=["Migration Checklists"]
)

service = ChecklistService()
class CompleteChecklistRequest(BaseModel):
    completed_by: str
    evidence: dict[str, Any] = Field(default_factory=dict)

def checklist_item_to_dict(item):
    return {
        "title": item.title,
        "description": item.description,
        "status": item.status,
        "completed_by": item.completed_by,
        "completed_at": (
            item.completed_at.isoformat()
            if item.completed_at else None
        ),
        "sort_order": item.sort_order,
        "evidence": item.evidence,
        "created_at": (
            item.created_at.isoformat()
            if item.created_at else None
        ),
    }


@router.post("/{migration_id}/checklist")
def create_checklist(
    migration_id: str,
    db: Session = Depends(get_db)
):
    try:
        items = service.create_for_plan(migration_id, db)
        return {
            "message": "Migration checklist created successfully",
            "total_items": len(items),
            "items": [checklist_item_to_dict(item) for item in items],
        }

    except ValueError as error:
        message = str(error)
        status_code = (
            404 if "not found" in message.lower() else 400
        )
        raise HTTPException(status_code=status_code, detail=message)


@router.get("/{migration_id}/checklist")
def get_checklist(
    migration_id: str,
    db: Session = Depends(get_db)
):
    try:
        items = service.list_for_plan(migration_id, db)
        return {
            "migration_id": migration_id,
            "total_items": len(items),
            "items": [checklist_item_to_dict(item) for item in items],
        }

    except ValueError as error:
        raise HTTPException(status_code=404, detail=str(error))

@router.post("/{migration_id}/checklist/{sort_order}/complete")
def complete_checklist_item(
    migration_id: str,
    sort_order: int,
    request: CompleteChecklistRequest,
    db: Session = Depends(get_db)
):
    try:
        item = service.complete_item(
            migration_id=migration_id,
            sort_order=sort_order,
            completed_by=request.completed_by,
            db=db,
            evidence=request.evidence,
        )

        return {
            "message": "Checklist item completed successfully",
            "item": checklist_item_to_dict(item)
        }

    except ValueError as error:
        message = str(error)
        status_code = (
            404 if "not found" in message.lower() else 400
        )
        raise HTTPException(
            status_code=status_code,
            detail=message
        )
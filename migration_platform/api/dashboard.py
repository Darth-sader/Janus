
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from migration_platform.database import get_db
from migration_platform.reports.dashboard_service import DashboardService

router = APIRouter(
    prefix="/dashboard",
    tags=["Migration Dashboard"]
)

service = DashboardService()


@router.get("/summary")
def get_dashboard_summary(
    db: Session = Depends(get_db)
):
    try:
        return service.get_summary(db)

    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Unable to generate dashboard summary"
        )

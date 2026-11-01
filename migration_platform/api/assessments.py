
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from migration_platform.database import get_db
from migration_platform.assessment.service import AssessmentService

router = APIRouter(
    prefix="/assessments",
    tags=["Assessments"]
)

service = AssessmentService()


@router.post("/asset/{asset_id}")
def assess_asset(
    asset_id: str,
    db: Session = Depends(get_db)
):
    try:
        return service.assess_asset(
            asset_id=asset_id,
            db=db
        )

    except ValueError as error:
        raise HTTPException(
            status_code=404,
            detail=str(error)
        )

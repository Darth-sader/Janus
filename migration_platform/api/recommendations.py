
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from migration_platform.api.algorithms import optional_crypto_adapter
from migration_platform.database import get_db
from migration_platform.recommendations.service import RecommendationService

router = APIRouter(
    prefix="/recommendations",
    tags=["Recommendations"]
)

service = RecommendationService()


@router.post("/asset/{asset_id}")
def generate_recommendation(
    asset_id: str,
    db: Session = Depends(get_db),
    crypto_adapter=Depends(optional_crypto_adapter)
):
    try:
        return service.generate_for_asset(
            asset_id=asset_id,
            db=db,
            crypto_adapter=crypto_adapter
        )

    except ValueError as error:
        raise HTTPException(
            status_code=404,
            detail=str(error)
        )

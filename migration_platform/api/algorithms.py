
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from migration_platform.database import get_db
from migration_platform.integrations.algorithm_sync import sync_algorithms

router = APIRouter(
    prefix="/algorithms",
    tags=["Algorithm Inventory"]
)

# Person 1's adapter will be registered here during integration.
_crypto_adapter = None


def configure_crypto_adapter(adapter):
    global _crypto_adapter
    _crypto_adapter = adapter


def get_crypto_adapter():
    if _crypto_adapter is None:
        raise HTTPException(
            status_code=503,
            detail="Crypto catalog is not connected yet. "
                   "Connect Person 1's CryptoAdapter first."
        )

    return _crypto_adapter


@router.post("/sync")
def synchronize_algorithms(
    db: Session = Depends(get_db),
    crypto_adapter=Depends(get_crypto_adapter)
):
    try:
        return sync_algorithms(
            db=db,
            crypto_adapter=crypto_adapter
        )

    except Exception as error:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail=f"Algorithm synchronization failed: {str(error)}"
        )

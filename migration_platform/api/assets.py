from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from migration_platform.database import get_db
from migration_platform.models import Asset

router = APIRouter(
    prefix="/assets",
    tags=["Asset Inventory"]
)


@router.post("/")
def create_asset(
    asset_data: dict,
    db: Session = Depends(get_db)
):
    required_fields = ["asset_type", "criticality"]

    for field in required_fields:
        if field not in asset_data:
            raise HTTPException(
                status_code=400,
                detail=f"Missing required field: {field}"
            )

    asset = Asset(
        asset_type=asset_data["asset_type"],
        criticality=asset_data["criticality"],
        firmware_version=asset_data.get("firmware_version"),
        operational_lifetime=asset_data.get("operational_lifetime"),
        update_capability=asset_data.get("update_capability"),
        protocol=asset_data.get("protocol"),
    )

    db.add(asset)
    db.commit()
    db.refresh(asset)

    return {
        "message": "Asset registered successfully",
        "asset_id": asset.asset_id,
        "asset_type": asset.asset_type,
        "criticality": asset.criticality,
    }
@router.get("/")
def get_all_assets(db: Session = Depends(get_db)):
    assets = db.query(Asset).all()

    return {
        "total_assets": len(assets),
        "assets": [
            {
                "asset_id": asset.asset_id,
                "asset_type": asset.asset_type,
                "criticality": asset.criticality,
                "firmware_version": asset.firmware_version,
                "operational_lifetime": asset.operational_lifetime,
                "update_capability": asset.update_capability,
                "protocol": asset.protocol,
            }
            for asset in assets
        ]
    }


@router.get("/{asset_id}")
def get_asset(asset_id: str, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(
        Asset.asset_id == asset_id
    ).first()

    if not asset:
        raise HTTPException(
            status_code=404,
            detail="Asset not found"
        )

    return {
        "asset_id": asset.asset_id,
        "asset_type": asset.asset_type,
        "criticality": asset.criticality,
        "firmware_version": asset.firmware_version,
        "operational_lifetime": asset.operational_lifetime,
        "update_capability": asset.update_capability,
        "protocol": asset.protocol,
    }
@router.put("/{asset_id}")
def update_asset(
    asset_id: str,
    asset_data: dict,
    db: Session = Depends(get_db)
):
    asset = db.query(Asset).filter(
        Asset.asset_id == asset_id
    ).first()

    if not asset:
        raise HTTPException(
            status_code=404,
            detail="Asset not found"
        )

    allowed_fields = [
        "asset_type",
        "criticality",
        "firmware_version",
        "operational_lifetime",
        "update_capability",
        "protocol",
    ]

    for field, value in asset_data.items():
        if field in allowed_fields:
            setattr(asset, field, value)

    db.commit()
    db.refresh(asset)

    return {
        "message": "Asset updated successfully",
        "asset_id": asset.asset_id,
    }
@router.delete("/{asset_id}")
def delete_asset(
    asset_id: str,
    db: Session = Depends(get_db)
):
    asset = db.query(Asset).filter(
        Asset.asset_id == asset_id
    ).first()

    if not asset:
        raise HTTPException(
            status_code=404,
            detail="Asset not found"
        )

    db.delete(asset)
    db.commit()

    return {
        "message": "Asset deleted successfully",
        "asset_id": asset_id,
    }
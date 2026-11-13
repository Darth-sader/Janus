from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from migration_platform.database import get_db
from migration_platform.models import Asset, CryptoConfig

router = APIRouter(
    prefix="/crypto-configs",
    tags=["Cryptographic Inventory"]
)


@router.post("/")
def create_crypto_config(
    config_data: dict,
    db: Session = Depends(get_db)
):
    required_fields = ["asset_id", "algorithm"]

    for field in required_fields:
        if field not in config_data:
            raise HTTPException(
                status_code=400,
                detail=f"Missing required field: {field}"
            )

    asset = db.query(Asset).filter(
        Asset.asset_id == config_data["asset_id"]
    ).first()

    if not asset:
        raise HTTPException(
            status_code=404,
            detail="Asset not found"
        )

    config = CryptoConfig(
        asset_id=config_data["asset_id"],
        algorithm=config_data["algorithm"],
        key_size=config_data.get("key_size"),
        signature_scheme=config_data.get("signature_scheme"),
        status=config_data.get("status", "ACTIVE"),
    )

    db.add(config)
    db.commit()
    db.refresh(config)

    return {
        "message": "Cryptographic configuration registered successfully",
        "config_id": config.config_id,
        "asset_id": config.asset_id,
        "algorithm": config.algorithm,
        "status": config.status,
    }
@router.get("/")
def get_all_crypto_configs(db: Session = Depends(get_db)):
    configs = db.query(CryptoConfig).all()

    return {
        "total_configs": len(configs),
        "configurations": [
            {
                "config_id": config.config_id,
                "asset_id": config.asset_id,
                "algorithm": config.algorithm,
                "key_size": config.key_size,
                "signature_scheme": config.signature_scheme,
                "status": config.status,
                "detected_at": config.detected_at,
            }
            for config in configs
        ]
    }


@router.get("/asset/{asset_id}")
def get_configs_by_asset(
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

    configs = db.query(CryptoConfig).filter(
        CryptoConfig.asset_id == asset_id
    ).all()

    return {
        "asset_id": asset_id,
        "total_configs": len(configs),
        "configurations": [
            {
                "config_id": config.config_id,
                "algorithm": config.algorithm,
                "key_size": config.key_size,
                "signature_scheme": config.signature_scheme,
                "status": config.status,
                "detected_at": config.detected_at,
            }
            for config in configs
        ]
    }
@router.put("/{config_id}")
def update_crypto_config(
    config_id: str,
    config_data: dict,
    db: Session = Depends(get_db)
):
    config = db.query(CryptoConfig).filter(
        CryptoConfig.config_id == config_id
    ).first()

    if not config:
        raise HTTPException(
            status_code=404,
            detail="Cryptographic configuration not found"
        )

    allowed_fields = [
        "algorithm",
        "key_size",
        "signature_scheme",
        "status",
    ]

    for field, value in config_data.items():
        if field in allowed_fields:
            setattr(config, field, value)

    db.commit()
    db.refresh(config)

    return {
        "message": "Cryptographic configuration updated successfully",
        "config_id": config.config_id,
        "algorithm": config.algorithm,
        "status": config.status,
    }
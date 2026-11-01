from sqlalchemy.orm import Session

from migration_platform.assessment.engine import AssessmentEngine
from migration_platform.models import (
    Asset,
    CryptoConfig,
    PQCAlgorithm,
    Assessment,
)


class AssessmentService:

    def __init__(self):
        self.engine = AssessmentEngine()

    def assess_asset(self, asset_id: str, db: Session) -> dict:
        # 1. Retrieve the asset
        asset = db.query(Asset).filter(
            Asset.asset_id == asset_id
        ).first()

        if not asset:
            raise ValueError(f"Asset not found: {asset_id}")

        # 2. Retrieve its cryptographic configurations
        crypto_configs = db.query(CryptoConfig).filter(
            CryptoConfig.asset_id == asset_id
        ).all()

        # 3. Retrieve synchronized algorithm capabilities
        algorithms = db.query(PQCAlgorithm).all()

        # 4. Run the assessment engine
        result = self.engine.assess(
            asset=asset,
            crypto_configs=crypto_configs,
            algorithm_capabilities=algorithms,
        )

        # 5. Save the assessment
        assessment = Assessment(
            asset_id=asset_id,
            security_status=result["security_status"],
            compatibility_status=result["compatibility_status"],
            performance_status=result["performance_status"],
            lifecycle_status=result["lifecycle_status"],
            migration_priority=result["migration_priority"],
            evidence=result["evidence"],
        )

        db.add(assessment)
        db.commit()
        db.refresh(assessment)

        # 6. Return the saved assessment
        return {
            "message": "Asset assessment completed successfully",
            "assessment_id": assessment.assessment_id,
            "asset_id": assessment.asset_id,
            "security_status": assessment.security_status,
            "compatibility_status": assessment.compatibility_status,
            "performance_status": assessment.performance_status,
            "lifecycle_status": assessment.lifecycle_status,
            "migration_priority": assessment.migration_priority,
            "evidence": assessment.evidence,
        }

from sqlalchemy.orm import Session

from migration_platform.models import (
    Asset,
    CryptoConfig,
    PQCAlgorithm,
    Assessment,
    Recommendation,
)
from migration_platform.recommendations.engine import RecommendationEngine


class RecommendationService:

    def __init__(self):
        self.engine = RecommendationEngine()

    def generate_for_asset(self, asset_id: str, db: Session, crypto_adapter=None):

        # 1. Check whether the asset exists
        asset = db.query(Asset).filter(
            Asset.asset_id == asset_id
        ).first()

        if not asset:
            raise ValueError("Asset not found")

        # 2. Retrieve the latest assessment
        assessment_record = (
            db.query(Assessment)
            .filter(Assessment.asset_id == asset_id)
            .order_by(Assessment.assessed_at.desc())
            .first()
        )

        if not assessment_record:
            raise ValueError("Please assess this asset before generating a recommendation")

        # 3. Retrieve the asset's cryptographic configurations
        crypto_configs = db.query(CryptoConfig).filter(
            CryptoConfig.asset_id == asset_id
        ).all()

        active_configs = [
            config for config in crypto_configs
            if config.status == "ACTIVE"
        ]

        current_algorithm = (
            active_configs[0].algorithm if active_configs else None
        )

        # 4. Retrieve available algorithm capabilities
        algorithms = db.query(PQCAlgorithm).all()

        algorithm_capabilities = [
            {
                "algorithm_id": item.algorithm_id,
                "name": item.name,
                "family": item.family,
                "implemented": item.implemented,
                "quantum_vulnerable": item.quantum_vulnerable,
                "security_level": item.security_level,
            }
            for item in algorithms
        ]

        # 5. Check migration mode feasibility when the adapter is available
        mode_feasibility = {}

        if crypto_adapter:
            for mode in ["hybrid", "pq"]:
                try:
                    mode_feasibility[mode] = crypto_adapter.check_mode(mode)
                except Exception as error:
                    mode_feasibility[mode] = {
                        "supported": False,
                        "reason": str(error),
                    }

        # 6. Prepare assessment data
        assessment_data = {
            "security_status": assessment_record.security_status,
            "compatibility_status": assessment_record.compatibility_status,
            "performance_status": assessment_record.performance_status,
            "lifecycle_status": assessment_record.lifecycle_status,
            "migration_priority": assessment_record.migration_priority,
        }

        # 7. Generate recommendation
        result = self.engine.recommend(
            assessment=assessment_data,
            current_algorithm=current_algorithm,
            algorithm_capabilities=algorithm_capabilities,
            mode_feasibility=mode_feasibility,
        )

        # 8. Save recommendation in the database
        recommendation = Recommendation(
            asset_id=asset_id,
            assessment_id=assessment_record.assessment_id,
            current_algorithm=result["current_algorithm"],
            target_algorithm=result["target_algorithm"],
            migration_mode=result["migration_mode"],
            outcome=result["outcome"],
            priority=result["priority"],
            reasoning=result["reasoning"],
            evidence=result["evidence"],
        )

        db.add(recommendation)
        db.commit()
        db.refresh(recommendation)

        return {
            "recommendation_id": recommendation.recommendation_id,
            "asset_id": asset_id,
            "current_algorithm": recommendation.current_algorithm,
            "target_algorithm": recommendation.target_algorithm,
            "migration_mode": recommendation.migration_mode,
            "outcome": recommendation.outcome,
            "priority": recommendation.priority,
            "reasoning": recommendation.reasoning,
            "evidence": recommendation.evidence,
            "requires_human_approval": result["requires_human_approval"],
        }

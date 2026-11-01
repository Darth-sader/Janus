
from sqlalchemy.orm import Session

from migration_platform.models import (
    Asset,
    CryptoConfig,
    Assessment,
    Recommendation,
    MigrationPlan,
)


class ReportService:

    def generate_migration_report(self, db: Session):

        assets = db.query(Asset).all()
        report_rows = []

        for asset in assets:

            configs = db.query(CryptoConfig).filter(
                CryptoConfig.asset_id == asset.asset_id
            ).all()

            latest_assessment = (
                db.query(Assessment)
                .filter(Assessment.asset_id == asset.asset_id)
                .order_by(Assessment.assessed_at.desc())
                .first()
            )

            latest_recommendation = (
                db.query(Recommendation)
                .filter(Recommendation.asset_id == asset.asset_id)
                .order_by(Recommendation.created_at.desc())
                .first()
            )

            latest_plan = (
                db.query(MigrationPlan)
                .filter(MigrationPlan.asset_id == asset.asset_id)
                .order_by(MigrationPlan.created_at.desc())
                .first()
            )

            report_rows.append({
                "asset_id": asset.asset_id,
                "asset_type": asset.asset_type,
                "criticality": asset.criticality,
                "firmware_version": asset.firmware_version,
                "operational_lifetime": asset.operational_lifetime,
                "update_capability": asset.update_capability,
                "protocol": asset.protocol,

                "current_algorithms": "; ".join(
                    config.algorithm for config in configs
                ),

                "security_status": (
                    latest_assessment.security_status
                    if latest_assessment else "NOT_ASSESSED"
                ),
                "compatibility_status": (
                    latest_assessment.compatibility_status
                    if latest_assessment else "NOT_ASSESSED"
                ),
                "performance_status": (
                    latest_assessment.performance_status
                    if latest_assessment else "NOT_ASSESSED"
                ),
                "lifecycle_status": (
                    latest_assessment.lifecycle_status
                    if latest_assessment else "NOT_ASSESSED"
                ),
                "migration_priority": (
                    latest_assessment.migration_priority
                    if latest_assessment else "NOT_ASSESSED"
                ),

                "recommendation": (
                    latest_recommendation.outcome
                    if latest_recommendation else "NOT_GENERATED"
                ),
                "target_algorithm": (
                    latest_recommendation.target_algorithm
                    if latest_recommendation else None
                ),

                "migration_status": (
                    latest_plan.status
                    if latest_plan else "NO_PLAN"
                ),
                "approval_status": (
                    latest_plan.approval_status
                    if latest_plan else "NOT_APPLICABLE"
                ),
            })

        return report_rows

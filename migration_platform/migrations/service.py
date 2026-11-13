
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from migration_platform.models import Recommendation, MigrationPlan


class MigrationPlanService:

    def create_draft(self, recommendation_id: str, db: Session):

        recommendation = (
            db.query(Recommendation)
            .filter(
                Recommendation.recommendation_id == recommendation_id
            )
            .first()
        )

        if not recommendation:
            raise ValueError("Recommendation not found")

        if recommendation.outcome not in [
            "HYBRID MIGRATION",
            "PQ MIGRATION",
        ]:
            raise ValueError(
                "A migration plan can only be created for a migration recommendation"
            )

        if not recommendation.target_algorithm or not recommendation.migration_mode:
            raise ValueError("Recommendation is missing migration target details")

        plan = MigrationPlan(
            asset_id=recommendation.asset_id,
            recommendation_id=recommendation.recommendation_id,
            target_algorithm=recommendation.target_algorithm,
            target_mode=recommendation.migration_mode,
            status="DRAFT",
            approval_status="PENDING",
        )

        db.add(plan)
        db.commit()
        db.refresh(plan)

        return plan

    def approve_plan(
        self,
        migration_id: str,
        approved_by: str,
        db: Session
    ):

        if not approved_by or not approved_by.strip():
            raise ValueError("Approver identity is required")

        plan = (
            db.query(MigrationPlan)
            .filter(MigrationPlan.migration_id == migration_id)
            .first()
        )

        if not plan:
            raise ValueError("Migration plan not found")

        if plan.approval_status != "PENDING":
            raise ValueError("Migration plan is not awaiting approval")

        plan.approval_status = "APPROVED"
        plan.approved_by = approved_by.strip()
        plan.approved_at = datetime.now(timezone.utc)

        db.commit()
        db.refresh(plan)

        return plan


from collections import Counter
from sqlalchemy.orm import Session

from migration_platform.models import (
    Asset,
    CryptoConfig,
    PQCAlgorithm,
    Certificate,
    Assessment,
    Recommendation,
    MigrationPlan,
    ChecklistItem,
)


class DashboardService:

    def get_summary(self, db: Session):

        # Retrieve records from the database
        assets = db.query(Asset).all()
        crypto_configs = db.query(CryptoConfig).all()
        algorithms = db.query(PQCAlgorithm).all()
        certificates = db.query(Certificate).all()
        assessments = db.query(Assessment).all()
        recommendations = db.query(Recommendation).all()
        migration_plans = db.query(MigrationPlan).all()
        checklist_items = db.query(ChecklistItem).all()

        # Helper function for grouping records
        def count_by(records, field):
            values = [
                getattr(record, field, None)
                for record in records
            ]
            return dict(Counter(
                str(value) for value in values if value is not None
            ))

        # Asset inventory summary
        asset_summary = {
            "total_assets": len(assets),
            "by_criticality": count_by(assets, "criticality"),
            "by_type": count_by(assets, "asset_type"),
        }

        # Cryptographic inventory summary
        crypto_summary = {
            "total_crypto_configs": len(crypto_configs),
            "total_algorithms": len(algorithms),
            "implemented_algorithms": sum(
                1 for item in algorithms if item.implemented
            ),
            "candidate_algorithms": sum(
                1 for item in algorithms if not item.implemented
            ),
            "total_certificates": len(certificates),
        }

        # Assessment summary
        assessment_summary = {
            "total_assessments": len(assessments),
            "by_security_status": count_by(
                assessments, "security_status"
            ),
            "by_migration_priority": count_by(
                assessments, "migration_priority"
            ),
        }

        # Recommendation summary
        recommendation_summary = {
            "total_recommendations": len(recommendations),
            "by_outcome": count_by(recommendations, "outcome"),
            "by_priority": count_by(recommendations, "priority"),
        }

        # Migration summary
        migration_summary = {
            "total_plans": len(migration_plans),
            "by_status": count_by(migration_plans, "status"),
            "by_approval_status": count_by(
                migration_plans, "approval_status"
            ),
        }

        # Checklist progress
        completed_items = sum(
            1 for item in checklist_items
            if item.status == "COMPLETED"
        )

        total_items = len(checklist_items)

        checklist_summary = {
            "total_items": total_items,
            "completed_items": completed_items,
            "pending_items": total_items - completed_items,
            "completion_percentage": (
                round(completed_items / total_items * 100, 2)
                if total_items else 0
            ),
        }

        return {
            "inventory": asset_summary,
            "cryptographic_inventory": crypto_summary,
            "assessments": assessment_summary,
            "recommendations": recommendation_summary,
            "migrations": migration_summary,
            "checklists": checklist_summary,
        }

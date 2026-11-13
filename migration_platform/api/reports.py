
import csv
import io

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from migration_platform.database import get_db
from migration_platform.reports.report_service import ReportService

router = APIRouter(
    prefix="/reports",
    tags=["Migration Reports"]
)

service = ReportService()


@router.get("/migration")
def download_migration_report(
    db: Session = Depends(get_db)
):
    try:
        rows = service.generate_migration_report(db)

        output = io.StringIO()

        fieldnames = [
            "asset_id",
            "asset_type",
            "criticality",
            "firmware_version",
            "operational_lifetime",
            "update_capability",
            "protocol",
            "current_algorithms",
            "security_status",
            "compatibility_status",
            "performance_status",
            "lifecycle_status",
            "migration_priority",
            "recommendation",
            "target_algorithm",
            "migration_status",
            "approval_status",
        ]

        writer = csv.DictWriter(
            output,
            fieldnames=fieldnames,
            extrasaction="ignore"
        )

        writer.writeheader()
        writer.writerows(rows)

        csv_content = "\ufeff" + output.getvalue()
        output.close()

        return StreamingResponse(
            iter([csv_content]),
            media_type="text/csv; charset=utf-8",
            headers={
                "Content-Disposition":
                    'attachment; filename="janus_migration_report.csv"'
            }
        )

    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Unable to generate migration report"
        )

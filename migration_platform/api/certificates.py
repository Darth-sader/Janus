from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from migration_platform.database import get_db
from migration_platform.models import Asset, Certificate, MigrationPlan

router = APIRouter(
    prefix="/certificates",
    tags=["Certificates (PKI)"]
)

# Person 2's PKI is registered here by integrations.bootstrap.connect().
_pki_context = None
_pki_adapter = None


def configure_pki(context, adapter):
    global _pki_context, _pki_adapter
    _pki_context = context
    _pki_adapter = adapter


def get_pki_adapter():
    if _pki_adapter is None:
        raise HTTPException(
            status_code=503,
            detail="PKI is not connected yet. Connect Person 2's PKIAdapter first."
        )

    return _pki_adapter


class IssueRequest(BaseModel):
    asset_id: str
    common_name: str
    mode: str = "classical"


class MigrateRequest(BaseModel):
    migration_id: str


def _parse_time(value):
    return datetime.fromisoformat(value) if value else None


def _sync_record(record: Certificate, info: dict):
    """Copy Person 2's certificate status record into the platform's table."""
    record.serial_number = info.get("serial_number")
    record.issuer = info.get("issuer")
    record.subject = info.get("subject")
    record.public_key_algorithm = info.get("public_key_algorithm")
    record.signature_algorithm = info.get("signature_algorithm")
    record.mode = info.get("mode")
    record.issued_at = _parse_time(info.get("not_before"))
    record.expires_at = _parse_time(info.get("not_after"))
    record.status = info.get("state", "ACTIVE")
    record.expired = info.get("expired")
    record.synced_at = datetime.now(timezone.utc)


def certificate_to_dict(record: Certificate):
    return {
        "certificate_id": record.certificate_id,
        "asset_id": record.asset_id,
        "external_cert_id": record.external_cert_id,
        "serial_number": record.serial_number,
        "subject": record.subject,
        "issuer": record.issuer,
        "mode": record.mode,
        "public_key_algorithm": record.public_key_algorithm,
        "signature_algorithm": record.signature_algorithm,
        "status": record.status,
        "expired": record.expired,
        "expires_at": record.expires_at.isoformat() if record.expires_at else None,
    }


def _get_record(certificate_id: str, db: Session) -> Certificate:
    record = db.query(Certificate).filter(
        Certificate.certificate_id == certificate_id
    ).first()

    if not record:
        raise HTTPException(status_code=404, detail="Certificate not found")

    return record


@router.post("/issue")
def issue_certificate(
    request: IssueRequest,
    db: Session = Depends(get_db),
    pki=Depends(get_pki_adapter)
):
    asset = db.query(Asset).filter(Asset.asset_id == request.asset_id).first()

    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    try:
        managed = _pki_context.manager.issue(
            _pki_context.intermediate,
            request.common_name,
            mode=request.mode,
        )
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))

    info = pki.get_certificate(managed.cert_id)
    record = Certificate(asset_id=asset.asset_id, external_cert_id=managed.cert_id)
    _sync_record(record, info)
    db.add(record)
    db.commit()
    db.refresh(record)
    return certificate_to_dict(record)


@router.get("/")
def list_certificates(db: Session = Depends(get_db)):
    return [certificate_to_dict(record) for record in db.query(Certificate).all()]


@router.get("/{certificate_id}")
def get_certificate(certificate_id: str, db: Session = Depends(get_db)):
    return certificate_to_dict(_get_record(certificate_id, db))


@router.get("/{certificate_id}/pki")
def get_pki_record(
    certificate_id: str,
    db: Session = Depends(get_db),
    pki=Depends(get_pki_adapter)
):
    """Person 2's full status record, including lifecycle history."""
    record = _get_record(certificate_id, db)
    return pki.get_certificate(record.external_cert_id)


@router.post("/{certificate_id}/validate")
def validate_certificate(
    certificate_id: str,
    db: Session = Depends(get_db),
    pki=Depends(get_pki_adapter)
):
    record = _get_record(certificate_id, db)
    return pki.validate_certificate(record.external_cert_id)


@router.post("/{certificate_id}/migrate")
def migrate_certificate(
    certificate_id: str,
    request: MigrateRequest,
    db: Session = Depends(get_db),
    pki=Depends(get_pki_adapter)
):
    """Reissue the certificate in the migration plan's target mode.

    Only runs for a plan a human has approved and started for this asset:
    human approval is the safety boundary.
    """
    record = _get_record(certificate_id, db)
    plan = db.query(MigrationPlan).filter(
        MigrationPlan.migration_id == request.migration_id
    ).first()

    if not plan:
        raise HTTPException(status_code=404, detail="Migration plan not found")

    if plan.asset_id != record.asset_id:
        raise HTTPException(status_code=400, detail="Migration plan belongs to a different asset")

    if plan.approval_status != "APPROVED" or plan.status != "IN_PROGRESS":
        raise HTTPException(
            status_code=403,
            detail="Certificate migration needs an APPROVED migration plan that has been started"
        )

    if not plan.target_mode:
        raise HTTPException(status_code=400, detail="Migration plan has no target mode")

    try:
        info = pki.migrate_certificate(record.external_cert_id, plan.target_mode, approved=True)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))

    _sync_record(record, info)
    db.commit()
    db.refresh(record)
    validation = pki.validate_certificate(record.external_cert_id)
    return {"certificate": certificate_to_dict(record), "validation": validation}

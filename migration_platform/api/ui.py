"""Read models and demo data for the web frontend (migration_platform/frontend).

These routes only combine what the other routers already store; every
action the UI takes (assess, recommend, approve, migrate ...) goes through
the regular endpoints.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from migration_platform.api import algorithms as algorithms_api
from migration_platform.api import certificates as certificates_api
from migration_platform.assessment.service import AssessmentService
from migration_platform.database import get_db
from migration_platform.models import (
    Assessment,
    Asset,
    Certificate,
    ChecklistItem,
    CryptoConfig,
    MigrationPlan,
    PQCAlgorithm,
    Recommendation,
)
from migration_platform.recommendations.service import RecommendationService
from migration_platform.reports.dashboard_service import DashboardService
from migration_platform.reports.report_service import ReportService

router = APIRouter(
    prefix="/ui",
    tags=["Web UI"]
)

NEEDS_MIGRATION = ("HYBRID MIGRATION", "PQ MIGRATION", "REPLACEMENT REQUIRED")


def _iso(value):
    return value.isoformat() if value else None


def _latest(db, model, asset_id, order_field):
    return (
        db.query(model)
        .filter(model.asset_id == asset_id)
        .order_by(order_field.desc())
        .first()
    )


def _asset_label(asset, certificates):
    if certificates:
        return certificates[0].subject.split("CN=")[-1].split(",")[0] if certificates[0].subject else asset.asset_type
    return f"{asset.asset_type} {asset.asset_id[:4]}"


@router.get("/overview")
def overview(db: Session = Depends(get_db)):
    rows = ReportService().generate_migration_report(db)
    certificates = db.query(Certificate).all()
    by_asset = {}
    for certificate in certificates:
        by_asset.setdefault(certificate.asset_id, []).append(certificate)

    assets = {asset.asset_id: asset for asset in db.query(Asset).all()}
    for row in rows:
        asset_certificates = by_asset.get(row["asset_id"], [])
        row["name"] = _asset_label(assets[row["asset_id"]], asset_certificates)
        row["certificate_mode"] = asset_certificates[0].mode if asset_certificates else None

    modes = [c.mode for c in certificates if c.status != "REVOKED"]
    return {
        "assets": rows,
        "summary": DashboardService().get_summary(db),
        "posture": {
            "total_assets": len(rows),
            "need_migration": sum(r["recommendation"] in NEEDS_MIGRATION for r in rows),
            "high_priority": sum(r["migration_priority"] in ("CRITICAL", "HIGH") for r in rows),
            "pq_protected": sum(m in ("hybrid", "pq") for m in modes),
            "certificates_by_mode": {
                mode: modes.count(mode) for mode in ("classical", "hybrid", "pq")
            },
        },
    }


@router.get("/assets/{asset_id}")
def asset_detail(asset_id: str, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(Asset.asset_id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    configs = db.query(CryptoConfig).filter(CryptoConfig.asset_id == asset_id).all()
    certificates = db.query(Certificate).filter(Certificate.asset_id == asset_id).all()
    assessment = _latest(db, Assessment, asset_id, Assessment.assessed_at)
    recommendation = _latest(db, Recommendation, asset_id, Recommendation.created_at)
    plan = _latest(db, MigrationPlan, asset_id, MigrationPlan.created_at)
    checklist = []
    if plan:
        checklist = (
            db.query(ChecklistItem)
            .filter(ChecklistItem.migration_id == plan.migration_id)
            .order_by(ChecklistItem.sort_order)
            .all()
        )

    return {
        "asset": {
            "asset_id": asset.asset_id,
            "name": _asset_label(asset, certificates),
            "asset_type": asset.asset_type,
            "criticality": asset.criticality,
            "firmware_version": asset.firmware_version,
            "operational_lifetime": asset.operational_lifetime,
            "update_capability": asset.update_capability,
            "protocol": asset.protocol,
        },
        "crypto_configs": [
            {
                "config_id": c.config_id,
                "algorithm": c.algorithm,
                "key_size": c.key_size,
                "signature_scheme": c.signature_scheme,
                "status": c.status,
            }
            for c in configs
        ],
        "certificates": [certificates_api.certificate_to_dict(c) for c in certificates],
        "assessment": assessment and {
            "assessment_id": assessment.assessment_id,
            "security_status": assessment.security_status,
            "compatibility_status": assessment.compatibility_status,
            "performance_status": assessment.performance_status,
            "lifecycle_status": assessment.lifecycle_status,
            "migration_priority": assessment.migration_priority,
            "evidence": assessment.evidence,
            "assessed_at": _iso(assessment.assessed_at),
        },
        "recommendation": recommendation and {
            "recommendation_id": recommendation.recommendation_id,
            "current_algorithm": recommendation.current_algorithm,
            "target_algorithm": recommendation.target_algorithm,
            "migration_mode": recommendation.migration_mode,
            "outcome": recommendation.outcome,
            "priority": recommendation.priority,
            "reasoning": recommendation.reasoning,
            "evidence": recommendation.evidence,
            "requires_human_approval": recommendation.outcome in NEEDS_MIGRATION,
            "created_at": _iso(recommendation.created_at),
        },
        "plan": plan and {
            "migration_id": plan.migration_id,
            "recommendation_id": plan.recommendation_id,
            "target_algorithm": plan.target_algorithm,
            "target_mode": plan.target_mode,
            "status": plan.status,
            "approval_status": plan.approval_status,
            "approved_by": plan.approved_by,
            "approved_at": _iso(plan.approved_at),
            "started_at": _iso(plan.started_at),
            "completed_at": _iso(plan.completed_at),
        },
        "checklist": [
            {
                "sort_order": item.sort_order,
                "title": item.title,
                "description": item.description,
                "status": item.status,
                "completed_by": item.completed_by,
                "completed_at": _iso(item.completed_at),
            }
            for item in checklist
        ],
    }


@router.get("/algorithms")
def list_algorithms(db: Session = Depends(get_db)):
    return [
        {
            "algorithm_id": a.algorithm_id,
            "name": a.name,
            "family": a.family,
            "standard": a.standard,
            "security_level": a.security_level,
            "key_size": a.key_size,
            "signature_size": a.signature_size,
            "implementation": a.implementation,
            "quantum_vulnerable": a.quantum_vulnerable,
            "implemented": a.implemented,
            "notes": a.notes,
        }
        for a in db.query(PQCAlgorithm).order_by(PQCAlgorithm.family, PQCAlgorithm.algorithm_id).all()
    ]


@router.post("/algorithms/measure")
def measure(algorithm_ids: list[str], crypto_adapter=Depends(algorithms_api.get_crypto_adapter)):
    """Benchmark keygen / sign / verify with the crypto layer (a few seconds for RSA-4096)."""
    try:
        return crypto_adapter.measure_algorithms(algorithm_ids)
    except Exception as error:
        raise HTTPException(status_code=400, detail=str(error))


# ---------------------------------------------------------------------------
# Demo data: a small grid operator estate, loosely following the proposal.
# ---------------------------------------------------------------------------

DEMO_ASSETS = [
    # name, type, criticality, lifetime, updatable, protocol, firmware, algorithm, key size, cert mode
    ("substation-017.grid.test", "Substation gateway", "HIGH", 15, True, "IEC 61850", "4.2.1", "rsa2048", 2048, "classical"),
    ("scada-master-01.grid.test", "SCADA master", "CRITICAL", 10, True, "DNP3 / TLS", "9.0", "rsa3072", 3072, "classical"),
    ("pmu-118.grid.test", "Phasor measurement unit", "HIGH", 15, True, "IEEE C37.118", "2.7", "ecdsa-p256", 256, "classical"),
    ("rtu-204.grid.test", "Remote terminal unit", "MEDIUM", 8, True, "Modbus / TLS", "3.1", "rsa2048", 2048, "classical"),
    ("historian-02.grid.test", "Historian server", "MEDIUM", 5, True, "HTTPS", "2024.2", "rsa4096", 4096, "classical"),
    ("relay-p44.grid.test", "Protection relay", "CRITICAL", 20, False, "IEC 61850 GOOSE", "1.0.9", "rsa2048", 2048, "classical"),
    ("meter-fleet-a.grid.test", "Smart meter fleet", "LOW", 12, False, "DLMS/COSEM", "0.8", "ecdsa-p256", 256, "classical"),
    ("eng-ws-07.grid.test", "Engineering workstation", "MEDIUM", 4, True, "HTTPS", "11.4", "RSA4096-MLDSA", None, "hybrid"),
    ("field-gw-31.grid.test", "Field gateway", "LOW", 6, True, "MQTT", "1.4", "vendor-proprietary", None, "classical"),
]


@router.post("/reset")
def reset_inventory(db: Session = Depends(get_db)):
    """Delete all assets and their records (the algorithm catalog is kept)."""
    for model in (ChecklistItem, MigrationPlan, Recommendation, Assessment, Certificate, CryptoConfig, Asset):
        db.query(model).delete()
    db.commit()
    return {"message": "Inventory cleared"}


@router.post("/seed-demo")
def seed_demo(db: Session = Depends(get_db)):
    if db.query(Asset).first() is not None:
        raise HTTPException(status_code=409, detail="Demo data can only be loaded into an empty inventory")

    pki_context = certificates_api._pki_context
    crypto_adapter = algorithms_api.optional_crypto_adapter()
    if pki_context is None or crypto_adapter is None:
        raise HTTPException(status_code=503, detail="Crypto layer and PKI must be connected first")

    created = []
    for name, asset_type, criticality, lifetime, updatable, protocol, firmware, algorithm, key_size, mode in DEMO_ASSETS:
        asset = Asset(
            asset_type=asset_type,
            criticality=criticality,
            operational_lifetime=lifetime,
            update_capability=updatable,
            protocol=protocol,
            firmware_version=firmware,
        )
        db.add(asset)
        db.flush()

        if algorithm:
            db.add(CryptoConfig(asset_id=asset.asset_id, algorithm=algorithm, key_size=key_size, status="ACTIVE"))

        if mode:
            managed = pki_context.manager.issue(pki_context.intermediate, name, mode=mode)
            record = Certificate(asset_id=asset.asset_id, external_cert_id=managed.cert_id)
            certificates_api._sync_record(record, managed.to_dict())
            db.add(record)

        db.commit()
        created.append(asset.asset_id)

    assessment_service = AssessmentService()
    recommendation_service = RecommendationService()
    for asset_id in created:
        assessment_service.assess_asset(asset_id, db)
        recommendation_service.generate_for_asset(asset_id, db, crypto_adapter=crypto_adapter)

    return {"message": "Demo inventory loaded", "assets_created": len(created)}

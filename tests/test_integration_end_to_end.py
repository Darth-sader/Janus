"""End-to-end: crypto layer + PKI + migration platform, through the HTTP API.

Follows the proposal's flow for a critical substation:
inventory -> assessment -> recommendation -> plan -> human approval ->
hybrid certificate from the PKI -> verification.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import migration_platform.models  # noqa: F401  (registers the tables)
from migration_platform.database import Base, get_db
from migration_platform.integrations.algorithm_sync import sync_algorithms
from migration_platform.integrations.bootstrap import build_pki_context, connect
from migration_platform.main import app
from pki.config import PKIConfig
from pki.models import CertMode


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    engine = create_engine(
        f"sqlite:///{tmp_path_factory.mktemp('db') / 'janus.db'}",
        connect_args={"check_same_thread": False},
    )
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = Session()
        try:
            yield db
        finally:
            db.close()

    # RSA-2048 keeps the test fast; the default hierarchy uses RSA-4096.
    pki_context = build_pki_context(PKIConfig(mode=CertMode.HYBRID, rsa_key_size=2048))
    crypto_adapter, _ = connect(pki_context=pki_context)
    db = Session()
    sync_algorithms(db, crypto_adapter)
    db.close()

    app.dependency_overrides[get_db] = override_get_db
    # No "with": the startup hook would connect a second, RSA-4096 PKI.
    yield TestClient(app)
    app.dependency_overrides.clear()


def test_algorithm_catalog_comes_from_crypto_layer(client):
    response = client.post("/algorithms/sync")
    assert response.status_code == 200, response.text
    # rsa4096, mldsa44/65/87, SLH-DSA sets, RSA4096-MLDSA, picnic candidates
    assert response.json()["total_received"] >= 6


def test_substation_classical_to_hybrid(client):
    asset = client.post("/assets/", json={
        "asset_type": "SUBSTATION-017",
        "criticality": "HIGH",
        "operational_lifetime": 15,
        "update_capability": True,
        "protocol": "IEC 61850",
    }).json()
    asset_id = asset["asset_id"]
    client.post("/crypto-configs/", json={"asset_id": asset_id, "algorithm": "rsa4096", "key_size": 4096})

    # The asset's current credential: a classical certificate from the PKI.
    cert = client.post("/certificates/issue", json={
        "asset_id": asset_id, "common_name": "substation-017.grid.test", "mode": "classical",
    })
    assert cert.status_code == 200, cert.text
    cert = cert.json()
    assert cert["mode"] == "classical"
    assert client.post(f"/certificates/{cert['certificate_id']}/validate").json()["valid"] is True

    # Assess and recommend, using capabilities and feasibility from the crypto layer.
    assert client.post(f"/assessments/asset/{asset_id}").status_code == 200
    recommendation = client.post(f"/recommendations/asset/{asset_id}").json()
    assert recommendation["outcome"] == "HYBRID MIGRATION", recommendation
    assert recommendation["migration_mode"] == "hybrid"

    plan = client.post(f"/migration-plans/recommendation/{recommendation['recommendation_id']}").json()
    migration_id = plan["migration_id"]

    # Without human approval the PKI must not touch the certificate.
    blocked = client.post(f"/certificates/{cert['certificate_id']}/migrate", json={"migration_id": migration_id})
    assert blocked.status_code == 403

    client.post(f"/migration-plans/{migration_id}/approve", json={"approved_by": "grid-admin"})
    assert client.post(f"/migration-plans/{migration_id}/start").status_code == 200

    migrated = client.post(f"/certificates/{cert['certificate_id']}/migrate", json={"migration_id": migration_id})
    assert migrated.status_code == 200, migrated.text
    body = migrated.json()
    assert body["certificate"]["mode"] == "hybrid"
    assert body["validation"]["valid"] is True
    assert body["validation"]["mode"] == "hybrid"

    record = client.get(f"/certificates/{cert['certificate_id']}/pki").json()
    assert len(record["previous_serials"]) == 1   # the classical certificate was superseded


def test_migrate_requires_matching_asset(client):
    other = client.post("/assets/", json={"asset_type": "RTU", "criticality": "LOW"}).json()
    cert = client.post("/certificates/issue", json={
        "asset_id": other["asset_id"], "common_name": "rtu.grid.test",
    }).json()
    response = client.post(f"/certificates/{cert['certificate_id']}/migrate", json={"migration_id": "nope"})
    assert response.status_code == 404

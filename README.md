# Janus

Bringing classical and post-quantum cryptography together through hybrid signatures, crypto-agile PKI,
and evidence-driven migration for critical infrastructure.

Janus is a **cryptographic migration advisor**: it inventories assets and their cryptography, assesses them
on five dimensions, recommends a deterministic, explainable migration (maintain / monitor / hybrid / PQ /
replacement), and, once a human approves, moves the asset's certificate **classical → hybrid → PQ-ready**.

Primary algorithms: **RSA-4096** (classical) · **ML-DSA-65, FIPS 204** (primary PQ) · **RSA-4096 + ML-DSA**
(hybrid, RFC 9794 terminology) · **SLH-DSA, FIPS 205** (PQ candidate).

## Architecture

```
 migration_platform/  (Pranshita)   inventory · assessment · recommendation · plans · approval · checklist · API
        │  CryptoAdapter                                   │  PKIAdapter
        ▼                                                  ▼
 crypto_agility/ + crypto/  (Poojita)   ◄── ML-DSA ──   pki/  (Ayanna)
 CryptoProvider: RSA-4096 · ML-DSA ·     verification    Root/Intermediate CA · X.509 classical/hybrid/PQ
 SLH-DSA · hybrid; registry; feasibility;                certificates · chain validation · CRLs · renew/rotate/migrate
 performance metrics
```

How the layers connect (`migration_platform/integrations/bootstrap.py` is the single wiring point):

| From → to | What flows |
|---|---|
| crypto → platform | Algorithm catalog (synced into the DB at startup), mode feasibility used by recommendations, measured performance |
| crypto → PKI | Which PQ algorithms are available (no silent fallback); every ML-DSA signature the PKI checks is verified by the crypto layer's `CryptoProvider` (`pki/crypto_bridge.py`) |
| PKI → platform | Certificate status records and validation results; `/certificates/{id}/migrate` reissues a certificate in the plan's target mode **only for an approved, started migration plan** |

## Layout

| Path | Owner | Docs |
|---|---|---|
| `crypto/`, `crypto_agility/` | Poojita: PQ crypto & architecture | [docs/crypto_layer.md](docs/crypto_layer.md), [docs/crypto_capabilities_interface.md](docs/crypto_capabilities_interface.md), [docs/hybrid_certificate_architecture.md](docs/hybrid_certificate_architecture.md) |
| `pki/`, `demo_pki.py` | Ayanna: PKI engineering | [pki/README.md](pki/README.md) |
| `migration_platform/` | Pranshita: migration platform | API docs at `/docs` when the server runs |
| `tests/test_integration_end_to_end.py` | all | the full SUBSTATION-017 flow through the HTTP API |

## Quick start

```bash
pip install -r requirements.txt

python -m pytest                                  # crypto, PKI, platform and end-to-end tests
python examples/demo.py                           # crypto layer: sign, verify, tamper, benchmark
python demo_pki.py --fast                         # PKI: classical -> hybrid migration, attacks rejected
uvicorn migration_platform.main:app --reload      # web app: http://127.0.0.1:8000  (API docs: /docs)
```

Run these from the `Janus` folder. On startup the platform builds a hybrid RSA-4096 + ML-DSA-65 CA hierarchy
(set `JANUS_RSA_KEY_SIZE=2048` for faster starts), syncs the algorithm catalog from the crypto layer, and
re-issues stored asset certificates. The PKI keeps its state in memory, so a restart starts it fresh.

## Web app

Open http://127.0.0.1:8000 and click **Load demo data** to get a nine-asset grid estate.

| Page | What it shows |
|---|---|
| Dashboard | Posture tiles, certificate migration state (classical / hybrid / PQ), recommendations, priorities, plans, checklist progress, assets needing action, CSV report |
| Asset inventory | Search and filter every asset; **Add asset** registers it, issues its certificate, assesses it and recommends a path |
| Asset detail | The Discover → Assess → Recommend → Approve → Migrate → Verify tracker, the five assessment dimensions, the explained recommendation, the certificate (verify chain, lifecycle history), the plan and its checklist. One "next step" button walks through the whole migration, and approval asks for the administrator's name |
| Algorithms | The crypto-agility catalog: implemented targets vs legacy/candidate algorithms, sizes, quantum vulnerability, and live keygen / sign / verify benchmarks |

The frontend is plain HTML, CSS and JavaScript in `migration_platform/frontend/`, with no build step. Its read
models live in `migration_platform/api/ui.py`.

### Typical API flow

1. `POST /assets/` and `POST /crypto-configs/` (algorithm ids from the catalog, e.g. `rsa4096`)
2. `POST /certificates/issue` with `{"asset_id", "common_name", "mode": "classical"}`
3. `POST /assessments/asset/{asset_id}` and then `POST /recommendations/asset/{asset_id}`
4. `POST /migration-plans/recommendation/{recommendation_id}`, then `/approve` and `/start`
5. `POST /certificates/{certificate_id}/migrate` with `{"migration_id"}`, which returns the hybrid certificate and its validation
6. Work through `/migration-plans/{id}/checklist`, then `/complete`

## Known limitations (prototype)

- The PKI's hybrid X.509 encoding is modelled on X.509 alternative-signature extensions. It is not a
  standard and has not been tested for interoperability (see `pki/README.md`).
- X.509 RSA signatures use PKCS#1 v1.5 and are verified by `cryptography`. The crypto layer's RSA
  provider (RSA-PSS) is used for its own hybrid signatures and benchmarks.
- The crypto layer's JSON `HybridCertificateModel` is a reference architecture. The PKI issues X.509.
- The PKI keeps certificates in memory. After a restart the platform re-issues stored certificates from the
  new CA hierarchy, so their lifecycle history starts again.
- Legacy algorithms (RSA-2048/3072, ECDSA, Ed25519) are in the catalog as inventory-only entries, so
  assets using them are assessed as quantum-vulnerable. They are never offered as migration targets.

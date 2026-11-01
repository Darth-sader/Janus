from fastapi import FastAPI
from migration_platform.api.assessments import router as assessments_router
from migration_platform.api.recommendations import router as recommendations_router
from migration_platform.database import create_tables
from migration_platform.api.assets import router as assets_router
from migration_platform.api.crypto_configs import router as crypto_configs_router
from migration_platform.api.algorithms import router as algorithms_router
from migration_platform.api.migration_plans import router as migration_plans_router
from migration_platform.api.checklists import router as checklists_router
from migration_platform.api.migration_status import router as migration_status_router
from migration_platform.api.dashboard import router as dashboard_router
from migration_platform.api.reports import router as reports_router
import migration_platform.models


app = FastAPI(
    title="Janus Migration Platform",
    description="Cryptographic inventory and post-quantum migration management for critical infrastructure.",
    version="1.0.0",
)


@app.on_event("startup")
def startup():
    create_tables()


app.include_router(assets_router)
app.include_router(crypto_configs_router)
app.include_router(recommendations_router)
app.include_router(assessments_router)
app.include_router(algorithms_router)
app.include_router(migration_plans_router)
app.include_router(checklists_router)
app.include_router(migration_status_router)
app.include_router(dashboard_router)
app.include_router(reports_router)

@app.get("/")
def home():
    return {
        "message": "Welcome to the Janus Migration Platform",
        "status": "running",
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "Janus Migration Platform",
    }
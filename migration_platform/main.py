from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from migration_platform.api.assessments import router as assessments_router
from migration_platform.api.recommendations import router as recommendations_router
from migration_platform.database import SessionLocal, create_tables
from migration_platform.integrations.algorithm_sync import sync_algorithms
from migration_platform.integrations.bootstrap import connect
from migration_platform.api.assets import router as assets_router
from migration_platform.api.crypto_configs import router as crypto_configs_router
from migration_platform.api.algorithms import router as algorithms_router
from migration_platform.api.migration_plans import router as migration_plans_router
from migration_platform.api.checklists import router as checklists_router
from migration_platform.api.migration_status import router as migration_status_router
from migration_platform.api.dashboard import router as dashboard_router
from migration_platform.api.reports import router as reports_router
from migration_platform.api.certificates import reissue_after_restart, router as certificates_router
from migration_platform.api.ui import router as ui_router
import migration_platform.models


app = FastAPI(
    title="Janus Migration Platform",
    description="Cryptographic inventory and post-quantum migration management for critical infrastructure.",
    version="1.0.0",
)


@app.on_event("startup")
def startup():
    create_tables()

    # Connect Person 1's crypto layer and Person 2's PKI, then load the
    # algorithm catalog so recommendations see the real capabilities.
    crypto_adapter, _ = connect()
    db = SessionLocal()
    try:
        sync_algorithms(db, crypto_adapter)
        # The PKI is in memory: re-issue certificates recorded before a restart.
        reissue_after_restart(db)
    finally:
        db.close()


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
app.include_router(certificates_router)
app.include_router(ui_router)

class FrontendFiles(StaticFiles):
    """Static files that browsers revalidate, so an updated UI is never stale."""

    async def get_response(self, path, scope):
        response = await super().get_response(path, scope)
        response.headers["Cache-Control"] = "no-cache"
        return response


# Web frontend: plain HTML/JS served by the API itself (no build step).
app.mount(
    "/app",
    FrontendFiles(directory=Path(__file__).parent / "frontend", html=True),
    name="frontend",
)

@app.get("/", include_in_schema=False)
def home():
    return RedirectResponse(url="/app/")


@app.get("/about")
def about():
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
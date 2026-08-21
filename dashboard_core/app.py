"""
The FastAPI application object and its wiring.

This module owns nothing but assembly: it creates the app, mounts the static
files, and includes one router per route family. The behaviour lives in the
modules it mounts (see docs/architecture/repository-map.md).
"""

import os
from dashboard_core.services.logs import log_action

from fastapi import FastAPI 
from fastapi.staticfiles import StaticFiles

from dashboard_core import config
from dashboard_core.auth import verify_session_token
from dashboard_core.auth import get_current_user
from dashboard_core.routes import agents as agents_routes
from dashboard_core.routes import alerting as alerting_routes
from dashboard_core.routes import auth as auth_routes
from dashboard_core.routes import dashboard as dashboard_routes
from dashboard_core.routes import manager as manager_routes
from dashboard_core.routes import pipeline as pipeline_routes
from dashboard_core.routes import rag as rag_routes
from dashboard_core.routes import settings as settings_routes

app = FastAPI(
    title="Wazuh Alert Dashboard",
    description="A lightweight test panel that captures and displays Wazuh alerts",
    version="4.0.0"
)

@app.middleware("http")
async def log_requests(request, call_next):
    response = await call_next(request)
    if request.method in ("POST", "PUT", "DELETE", "PATCH"):
        username = getattr(request.state, "log_user", None) or get_current_user(request) or "-"
        target = getattr(request.state, "log_target", "-")
        detail = getattr(request.state, "log_detail", "-")
        log_action(
            category=request.url.path.strip("/").split("/")[0] or "root",
            action=f"{request.method} {request.url.path}",
            result="failed" if response.status_code >= 400 else "success",
            user=username,
            target=target,
            detail=detail,
        )
    return response

app.mount("/static", StaticFiles(directory=os.path.join(config.BASE_DIR, "static")), name="static")

app.include_router(dashboard_routes.router)
app.include_router(auth_routes.router)
app.include_router(settings_routes.router)
app.include_router(alerting_routes.router)
app.include_router(pipeline_routes.router)
app.include_router(agents_routes.router)
app.include_router(manager_routes.router)
app.include_router(rag_routes.router)

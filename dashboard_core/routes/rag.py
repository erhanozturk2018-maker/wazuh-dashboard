"""
RAG ASSISTANT - a question box in front of a separate local service, not
the Wazuh manager. See services/rag_pipeline.py for the transport and why
every call is proxied through this backend rather than made from the
browser.

**Gated behind Console > Features, at the route level, not only in the
sidebar.** Hiding the nav link is not access control - a request that
knows the URL would still reach a service the operator never turned on.
Both endpoints here re-check the flag themselves and refuse with a plain
404 when it is off, so there is exactly one place ("is this feature on?")
that decides, not two that could disagree.

Document management (POST /ingest, DELETE /documents/{id}) is
deliberately NOT exposed here. This page is a question box for whoever is
already logged into the dashboard, not an admin panel for the assistant
service itself; those two endpoints stay reachable only through the RAG
service's own API for now. GET /documents is the one exception - read-only,
shown next to the question box so an operator can see what it actually
knows about.
"""

from fastapi import APIRouter, Form, Request
from fastapi.responses import JSONResponse, RedirectResponse

from dashboard_core import config
from dashboard_core.auth import get_current_user
from dashboard_core.services import rag_pipeline
from dashboard_core.storage import load_feature_flags

router = APIRouter()


def _enabled() -> bool:
    return bool(load_feature_flags().get("rag_assistant", False))


@router.get("/rag")
async def rag_page(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    if not _enabled():
        return JSONResponse({"error": "not found"}, status_code=404)

    # Both calls are cheap (a local service, not the Wazuh manager), so -
    # like Console's own tabs - this page prepares everything on render
    # rather than making the client fetch it separately.
    status_ok, status_result = rag_pipeline.status()
    docs_ok, docs_result = rag_pipeline.list_documents()

    return config.templates.TemplateResponse(request, "rag.html", {
        "request": request,
        "username": user,
        "status_ok": status_ok,
        "status": status_result if status_ok else None,
        "status_error": None if status_ok else str(status_result),
        "documents": (docs_result.get("documents") or {}) if docs_ok and isinstance(docs_result, dict) else {},
    })


@router.post("/rag/ask")
async def rag_ask(request: Request, query: str = Form(...)):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    if not _enabled():
        return JSONResponse({"error": "not found"}, status_code=404)

    query = query.strip()
    if not query:
        return JSONResponse({"error": "The question is empty."}, status_code=400)

    ok, result = rag_pipeline.ask(query, user=user)
    request.state.log_target = user
    request.state.log_detail = query if ok else str(result)
    if not ok:
        return JSONResponse({"error": str(result)}, status_code=502)
    return JSONResponse(result if isinstance(result, dict) else {"answer": str(result)})

"""
LOGIN / REGISTER / LOGOUT
"""

from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse

from dashboard_core import config
from dashboard_core.auth import authenticate, create_user, get_current_user, make_session_token

router = APIRouter()


@router.get("/login")
async def login_page(request: Request, error: str = None, message: str = None):
    if get_current_user(request):
        return RedirectResponse("/", status_code=303)
    return config.templates.TemplateResponse(request, "login.html", {"error": error, "message": message})


@router.post("/login")
async def login_submit(request: Request, username: str = Form(...), password: str = Form(...)):
    if authenticate(username, password):
        token = make_session_token(username)
        request.state.log_user = username 
        resp = RedirectResponse("/", status_code=303)
        resp.set_cookie(
            config.SESSION_COOKIE, token,
            max_age=config.SESSION_MAX_AGE, httponly=True, samesite="lax",
        )
        return resp
    return config.templates.TemplateResponse(
        request, "login.html",
        {"error": "Invalid username or password."},
        status_code=401,
    )


@router.get("/register")
async def register_page(request: Request, error: str = None):
    if get_current_user(request):
        return RedirectResponse("/", status_code=303)
    return config.templates.TemplateResponse(request, "register.html", {"error": error})


@router.post("/register")
async def register_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    password2: str = Form(...),
):
    if password != password2:
        return config.templates.TemplateResponse(
            request, "register.html",
            {"error": "Passwords do not match."}, status_code=400,
        )

    ok, msg = create_user(username, password)
    if not ok:
        return config.templates.TemplateResponse(
            request, "register.html", {"error": msg}, status_code=400,
        )
    return RedirectResponse(f"/login?message={msg}", status_code=303)


@router.post("/logout")
async def logout():
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(config.SESSION_COOKIE)
    return resp

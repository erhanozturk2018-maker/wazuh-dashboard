"""
PIPELINE - how logs reach the manager and how it makes sense of them.

Replaces the old "ISP" page, whose name said nothing about its contents.
The two sub-tabs follow the data's own path:

  Collect  ->  ossec.conf <localfile> entries, /etc/rsyslog.d/wazuh-*.conf,
               and per-group agent.conf collectors
  Parse    ->  /var/ossec/etc/decoders|rules/*.xml

**Only the active tab's data is loaded.** The older screens prepared every
sub-tab on every render so that switching was instant with no round trip.
That trade made sense when the data came from one fast SSH call; against
this manager's API, where individual calls have been measured taking tens
of seconds, it would mean paying for both tabs on every page open. The
inactive tab is fetched when the operator actually switches to it.

Group collectors are likewise not expanded on render: the group list is
cheap, but each group's agent.conf is another call, so those load on
demand through /api/pipeline/groups/{group}/config.
"""

from fastapi import APIRouter, File, Form, Request, UploadFile
from fastapi.responses import JSONResponse, RedirectResponse

from dashboard_core import config
from dashboard_core.auth import get_current_user
from dashboard_core.services import manager_control
from dashboard_core.services import agents as agents_service
from dashboard_core.services import custom_files, ossec_config, service_checks
from dashboard_core.services.rsyslog import (
    rsyslog_file_delete,
    rsyslog_file_save,
    rsyslog_files_list,
)
from dashboard_core.validation import (
    AGENT_ID_RE,
    CUSTOM_XML_FILE_RE,
    RSYSLOG_FILE_RE,
    xml_well_formed_error,
)

router = APIRouter()

TABS = ("collect", "parse")

def _saved_redirect(url: str, message: str) -> RedirectResponse:
    """Redirect after a successful save, flagging a failed restart.

    The write landed, so this is still the success path - but if the
    manager did not come back, the change is on disk and not live, and
    that fact would be lost across the redirect. The flag is what lets
    the page render the retry control instead of a bare "Changes saved".
    """
    if manager_control.needs_restart_retry(message):
        url += "&restart_failed=1"
    return RedirectResponse(url, status_code=303)



def _pipeline_context(request: Request, user: str, tab: str, saved: bool,
                      error: str | None = None,
                      restart_failed: bool = False) -> dict:
    tab = tab if tab in TABS else "collect"
    context = {
        "request": request,
        "username": user,
        "tab": tab,
        "saved": saved,
        "error": error,
        # Save succeeded, manager did not come back - see _saved_redirect.
        "restart_failed": restart_failed,
        "restart_failed_hint": manager_control.RESTART_FAILED_HINT,
        # Defaults so the template can render either tab's markup without
        # branching on which one was actually loaded.
        "localfiles_list": [],
        "localfiles_list_error": None,
        "rsyslog_files_list": [],
        "rsyslog_files_list_error": None,
        "groups_list": [],
        "groups_list_error": None,
        "agents_list": [],
        "agents_list_error": None,
        "decoder_files_list": [],
        "decoder_files_list_error": None,
        "rule_files_list": [],
        "rule_files_list_error": None,
    }

    if tab == "collect":
        ok, result = ossec_config.list_blocks("localfile")
        context["localfiles_list"] = result if ok else []
        context["localfiles_list_error"] = None if ok else str(result)

        rsyslog_list, rsyslog_error = rsyslog_files_list()
        context["rsyslog_files_list"] = rsyslog_list or []
        context["rsyslog_files_list_error"] = rsyslog_error

        ok, result = agents_service.list_groups()
        context["groups_list"] = result if ok else []
        context["groups_list_error"] = None if ok else str(result)

        # The service-check wizard needs somewhere to verify against. This
        # is the cheap list call (one request for all agents), not the
        # per-agent detail one.
        #
        # The failure is captured rather than swallowed: an empty agent
        # dropdown with no explanation is indistinguishable from "this
        # manager has no agents", and the operator cannot tell whether to
        # wait or to go looking for a problem.
        ok, result = agents_service.list_agents()
        context["agents_list"] = [a for a in result if a["id"] != "000"] if ok else []
        context["agents_list_error"] = None if ok else str(result)
    else:
        ok, result = custom_files.list_files("decoder")
        context["decoder_files_list"] = result if ok else []
        context["decoder_files_list_error"] = None if ok else str(result)

        ok, result = custom_files.list_files("rule")
        context["rule_files_list"] = result if ok else []
        context["rule_files_list_error"] = None if ok else str(result)

    return context


@router.get("/pipeline")
async def pipeline_page(request: Request, saved: str = None, tab: str = "collect",
                        restart_failed: str = None):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    return config.templates.TemplateResponse(
        request, "pipeline.html",
        _pipeline_context(request, user, tab, bool(saved),
                          restart_failed=bool(restart_failed)),
    )


@router.get("/isp")
async def isp_redirect(request: Request):
    """The page used to live here. Kept so existing bookmarks and any
    lingering links land somewhere sensible instead of 404ing."""
    return RedirectResponse("/pipeline", status_code=301)


def _render_error(request: Request, user: str, tab: str, message: str):
    return config.templates.TemplateResponse(
        request, "pipeline.html",
        _pipeline_context(request, user, tab, False, error=message),
        status_code=400,
    )


# ======================================================================
# PARSE - custom decoder/rule XML files
# ======================================================================

@router.get("/api/pipeline/files/{kind}/{name}")
async def api_file_content(request: Request, kind: str, name: str):
    """One file's XML, fetched when the operator opens it.

    The listing deliberately carries no content (services/custom_files.py),
    so this is what fills the editor.
    """
    if not get_current_user(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    if kind not in custom_files.KINDS:
        return JSONResponse({"error": f"Unknown kind: {kind}"}, status_code=400)
    if not CUSTOM_XML_FILE_RE.match(name):
        return JSONResponse({"error": "Invalid file name."}, status_code=400)

    ok, result = custom_files.read_file(kind, name)
    if not ok:
        return JSONResponse({"error": str(result)}, status_code=502)
    return JSONResponse({"name": name, "content": result})


@router.post("/pipeline/files")
async def pipeline_files_submit(
    request: Request,
    action: str = Form(...),
    kind: str = Form(""),
    name: str = Form(""),
    content: str = Form(""),
    xml_file: UploadFile | None = File(None),
):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)

    if kind not in custom_files.KINDS:
        return _render_error(request, user, "parse", f"Unknown kind: {kind}")

    name = name.strip()
    if not name or not CUSTOM_XML_FILE_RE.match(name):
        return _render_error(
            request, user, "parse",
            "File name must use letters/digits/dot/dash/underscore only and end with .xml.",
        )

    if action in ("add", "update"):
        # An uploaded file wins over the textarea when both are present.
        if xml_file is not None and xml_file.filename:
            raw = await xml_file.read()
            try:
                content = raw.decode("utf-8")
            except UnicodeDecodeError:
                return _render_error(
                    request, user, "parse", "The uploaded file is not UTF-8 text."
                )
        if not content.strip():
            return _render_error(request, user, "parse", "The XML content is required.")
        xml_error = xml_well_formed_error(content)
        if xml_error:
            return _render_error(
                request, user, "parse", f"The XML is not well-formed: {xml_error}"
            )
        ok, message = custom_files.save_file(
            kind, name, content, overwrite=(action == "update")
        )
    elif action == "delete":
        ok, message = custom_files.delete_file(kind, name)
    else:
        return _render_error(request, user, "parse", f"Unknown action: {action}")

    request.state.log_target = f"{kind}:{name}"
    request.state.log_detail = str(message)
    if not ok:
        return _render_error(request, user, "parse", str(message))
    return _saved_redirect("/pipeline?saved=1&tab=parse", message)


# ======================================================================
# COLLECT - ossec.conf <localfile> entries
# ======================================================================

@router.post("/pipeline/localfiles")
async def pipeline_localfiles_submit(
    request: Request,
    action: str = Form(...),
    entry_id: str = Form(""),
    location: str = Form(""),
    log_format: str = Form(""),
    command: str = Form(""),
    alias: str = Form(""),
    frequency: str = Form(""),
):
    """A log source is either a file to read or a command to run.

    The previous version of this route only understood the file shape and
    demanded a location, which is why the three command entries already in
    this manager's ossec.conf were unreachable from the UI.
    """
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)

    log_format = log_format.strip()

    if action == "add":
        data = {"log_format": log_format}
        if log_format in ossec_config.COMMAND_LOG_FORMATS:
            data.update({
                "command": command.strip(),
                "alias": alias.strip(),
                "frequency": frequency.strip(),
            })
        else:
            data["location"] = location.strip()
        ok, message = ossec_config.add_block("localfile", data)

    elif action == "delete":
        entry_id = entry_id.strip()
        if not entry_id:
            return _render_error(
                request, user, "collect", "Which log source to remove was not given."
            )
        ok, message = ossec_config.delete_block("localfile", entry_id)

    else:
        return _render_error(request, user, "collect", f"Unknown action: {action}")

    request.state.log_target = entry_id or location.strip() or alias.strip()
    request.state.log_detail = str(message)
    if not ok:
        return _render_error(request, user, "collect", str(message))
    return _saved_redirect("/pipeline?saved=1&tab=collect", message)


# ======================================================================
# COLLECT - per-group agent.conf
# ======================================================================

@router.get("/api/pipeline/groups/{group}/config")
async def api_group_config(request: Request, group: str):
    """A group's agent.conf, loaded when its row is expanded."""
    if not get_current_user(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    ok, result = agents_service.read_group_config(group)
    if not ok:
        return JSONResponse({"error": str(result)}, status_code=502)
    return JSONResponse({"group": group, "content": result})


@router.post("/pipeline/groups/{group}/config")
async def pipeline_group_config_submit(
    request: Request, group: str, content: str = Form("")
):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)

    xml_error = xml_well_formed_error(content)
    if xml_error:
        return _render_error(
            request, user, "collect",
            f"The agent configuration is not well-formed XML: {xml_error}",
        )

    ok, message = agents_service.write_group_config(group, content)
    request.state.log_target = f"group:{group}"
    request.state.log_detail = str(message)
    if not ok:
        return _render_error(request, user, "collect", str(message))
    return RedirectResponse("/pipeline?saved=1&tab=collect", status_code=303)


# ======================================================================
# COLLECT - service checks
#
# A check is three coupled pieces (collector + decoder + rule); the
# service layer writes them together and rolls back a partial failure.
# These routes only carry the operator's intent to it.
#
# Everything here is loaded on demand rather than during the page render:
# listing what is watched costs one call per group, and the wizard's
# verification step hits syscollector, which is the slowest endpoint this
# manager has.
# ======================================================================

@router.get("/api/pipeline/service-checks")
async def api_service_checks(request: Request):
    if not get_current_user(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    ok, result = service_checks.list_watched()
    if not ok:
        return JSONResponse({"error": str(result)}, status_code=502)
    return JSONResponse({"checks": result})


@router.get("/api/pipeline/service-checks/verify")
async def api_verify_service(request: Request, agent_id: str = "", service: str = ""):
    """Is this service actually present on this agent, and what command
    would check it?

    Answering honestly matters more than answering conveniently: a check
    configured against a service the host never runs is the documented way
    this feature manufactures false alerts. So an exact match is reported
    as such, near-misses are offered only as suggestions, and the scan time
    is always returned because the inventory is a snapshot, not live state.
    """
    if not get_current_user(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)

    agent_id, service = agent_id.strip(), service.strip()
    if not AGENT_ID_RE.match(agent_id):
        return JSONResponse({"error": "Invalid agent id."}, status_code=400)
    if not service:
        return JSONResponse({"error": "A service name is required."}, status_code=400)

    ok, agent = agents_service.get_agent(agent_id)
    if not ok:
        return JSONResponse({"error": str(agent)}, status_code=502)
    platform = service_checks.platform_for((agent.get("os") or {}).get("platform"))

    ok, found = agents_service.find_service(agent_id, service)
    if not ok:
        return JSONResponse({"error": str(found)}, status_code=502)

    exact = found["exact"]
    return JSONResponse({
        "platform": platform,
        "platform_label": service_checks.PLATFORMS[platform]["label"],
        "exact": exact,
        "candidates": [c["name"] for c in found["candidates"]][:8],
        "suggested_command": service_checks.suggest_command(
            platform, exact["name"] if exact else service),
        "suggested_alias": _suggest_alias(exact["name"] if exact else service),
        "groups": agent.get("group") or [],
    })


def _suggest_alias(service: str) -> str:
    """A safe default the operator can override. Must satisfy ALIAS_RE."""
    cleaned = "".join(c if c.isalnum() else "_" for c in service).strip("_").lower()
    cleaned = cleaned or "service"
    if not cleaned[0].isalpha():
        cleaned = "svc_" + cleaned
    return f"{cleaned[:50]}_status_check"


@router.post("/pipeline/service-checks")
async def pipeline_service_check_create(
    request: Request,
    alias: str = Form(""),
    service: str = Form(""),
    group: str = Form(""),
    command: str = Form(""),
    platform: str = Form("linux"),
    frequency: str = Form(str(service_checks.DEFAULT_FREQUENCY)),
    level: str = Form(str(service_checks.DEFAULT_LEVEL)),
    new_group: str = Form(""),
    assign_agent_id: str = Form(""),
):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)

    # Creating the group first, when asked, so the check has somewhere to
    # land. Deliberately NOT rolled back if the check then fails: an empty
    # group is harmless and the operator likely wants to retry into it.
    if new_group.strip():
        group = new_group.strip()
        ok, message = agents_service.create_group(group)
        if not ok:
            return _render_error(request, user, "collect",
                                 f"Could not create the group: {message}")
        if assign_agent_id.strip():
            ok, message = agents_service.assign_agent(assign_agent_id.strip(), group)
            if not ok:
                return _render_error(
                    request, user, "collect",
                    f"Group '{group}' was created but the agent could not be "
                    f"added to it: {message}")

    if not group.strip():
        return _render_error(request, user, "collect",
                             "Choose a group, or create one, for this check.")

    error = service_checks.validate(alias.strip(), command, frequency, level)
    if error:
        return _render_error(request, user, "collect", error)

    ok, message = service_checks.create_check(
        alias=alias.strip(), service=service.strip() or alias.strip(),
        group=group.strip(), command=command.strip(), platform=platform,
        frequency=int(frequency), level=int(level),
    )
    request.state.log_target = f"{group}:{alias}"
    request.state.log_detail = str(message)
    if not ok:
        return _render_error(request, user, "collect", str(message))
    return _saved_redirect("/pipeline?saved=1&tab=collect", message)


@router.post("/pipeline/service-checks/delete")
async def pipeline_service_check_delete(
    request: Request, alias: str = Form(""), group: str = Form("")
):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)

    ok, message = service_checks.remove_check(alias=alias.strip(), group=group.strip())
    request.state.log_target = f"{group}:{alias}"
    request.state.log_detail = str(message)
    if not ok:
        return _render_error(request, user, "collect", str(message))
    return _saved_redirect("/pipeline?saved=1&tab=collect", message)


# ======================================================================
# COLLECT - rsyslog files (still over SSH: the Wazuh API does not manage
# the host's rsyslog, only Wazuh's own configuration)
# ======================================================================

@router.post("/pipeline/rsyslog")
async def pipeline_rsyslog_submit(
    request: Request,
    action: str = Form(...),
    name: str = Form(""),
    content: str = Form(""),
):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)

    name = name.strip()
    if not name or not RSYSLOG_FILE_RE.match(name):
        return _render_error(
            request, user, "collect",
            "File name must match wazuh-*.conf (e.g. wazuh-tcp.conf).",
        )

    if action in ("add", "update"):
        if not content.strip():
            return _render_error(
                request, user, "collect", "The rsyslog config content is required."
            )
        ok, message = rsyslog_file_save(name, content, overwrite=(action == "update"))
    elif action == "delete":
        ok, message = rsyslog_file_delete(name)
    else:
        return _render_error(request, user, "collect", f"Unknown action: {action}")

    request.state.log_target = f"rsyslog:{name}"
    request.state.log_detail = str(message)
    if not ok:
        return _render_error(request, user, "collect", str(message))
    return RedirectResponse("/pipeline?saved=1&tab=collect", status_code=303)

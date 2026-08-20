"""
ALERTING - how findings leave the manager.

Everything on this page answers one question: once the manager has decided
something matters, who hears about it? Two tabs:

  Email         delivery (how mail gets out) + rules (which alerts are sent)
  Integrations  ossec.conf <integration> blocks - external services

**Why delivery and rules share a tab.** They were previously two separate
tabs that looked interchangeable, and an operator could not tell which one
they were editing. They are not the same thing, though: delivery is the
transport, rules are the policy, and rules do nothing at all if delivery is
not working. Putting them on one screen in that order shows the dependency;
keeping them as clearly separated sections, each with its own provenance
badge, keeps them from blurring together.

**They also travel different channels.** Delivery reaches Postfix on the
manager's operating system, which the Wazuh API cannot express, so it still
goes over SSH. Rules are ossec.conf blocks and go through the API. The
badges say so.

Like the Pipeline page, only the active tab's data is fetched.
"""

from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse

from dashboard_core import config
from dashboard_core.auth import get_current_user
from dashboard_core.services import manager_control
from dashboard_core.services import ossec_config
from dashboard_core.services.plugins import recheck_postfix
from dashboard_core.services.ssh_transport import run_mail_command_via_ssh
from dashboard_core.storage import load_mail_settings, save_mail_settings
from dashboard_core.validation import EMAIL_RE, HOST_RE, _relay_host_only

router = APIRouter()

TABS = ("email", "integrations")

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



def _alerting_context(request: Request, user: str, tab: str, saved: bool,
                      error: str | None = None, mail_override: dict | None = None,
                      restart_failed: bool = False) -> dict:
    tab = tab if tab in TABS else "email"
    context = {
        "request": request,
        "username": user,
        "tab": tab,
        "saved": saved,
        "error": error,
        # Save succeeded, manager did not come back - see _saved_redirect.
        "restart_failed": restart_failed,
        "restart_failed_hint": manager_control.RESTART_FAILED_HINT,
        "mail": mail_override or load_mail_settings(),
        "email_alerts_list": [],
        "email_alerts_list_error": None,
        "integrations_list": [],
        "integrations_list_error": None,
    }

    if tab == "email":
        ok, result = ossec_config.list_blocks("email_alerts")
        context["email_alerts_list"] = result if ok else []
        context["email_alerts_list_error"] = None if ok else str(result)
    else:
        ok, result = ossec_config.list_blocks("integration")
        context["integrations_list"] = result if ok else []
        context["integrations_list_error"] = None if ok else str(result)

    return context


def _render(request: Request, user: str, tab: str, message: str,
            mail_override: dict | None = None):
    return config.templates.TemplateResponse(
        request, "alerting.html",
        _alerting_context(request, user, tab, False, error=message,
                          mail_override=mail_override),
        status_code=400,
    )


@router.get("/alerting")
async def alerting_page(request: Request, saved: str = None, tab: str = "email",
                        restart_failed: str = None):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    return config.templates.TemplateResponse(
        request, "alerting.html",
        _alerting_context(request, user, tab, bool(saved),
                          restart_failed=bool(restart_failed)),
    )


# ======================================================================
# DELIVERY - Postfix relay + the ossec.conf <global> mail fields.
# Still over SSH: the Wazuh API manages Wazuh, and Postfix is the host's
# mail system, not Wazuh's.
# ======================================================================

@router.post("/alerting/mail")
async def mail_submit(
    request: Request,
    email_to: str = Form(""),
    email_from: str = Form(""),
    smtp_server: str = Form(""),
    email_maxperhour: str = Form(""),
    relayhost: str = Form(""),
    sasl_user: str = Form(""),
    sasl_pass: str = Form(""),
    sasl_pass_confirm: str = Form(""),
):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)

    mail = load_mail_settings()
    submitted = {
        "email_to": email_to, "email_from": email_from,
        "smtp_server": smtp_server, "email_maxperhour": email_maxperhour,
        "relayhost": relayhost, "sasl_user": sasl_user,
        "sasl_pass_set": mail["sasl_pass_set"],
    }

    def fail(message: str):
        return _render(request, user, "email", message, mail_override=submitted)

    if email_to.strip() and not EMAIL_RE.match(email_to.strip()):
        return fail("The recipient is not a valid email address.")
    if email_from.strip() and not EMAIL_RE.match(email_from.strip()):
        return fail("The sender is not a valid email address.")
    if smtp_server.strip() and not HOST_RE.match(smtp_server.strip()):
        return fail("The SMTP server is not a valid host or IP.")
    if email_maxperhour.strip() and not email_maxperhour.strip().isdigit():
        return fail("The hourly limit must contain digits only.")
    if relayhost.strip() and not HOST_RE.match(_relay_host_only(relayhost)):
        return fail("The relay host is not a valid host or IP.")

    new_pass = sasl_pass.strip()
    if (new_pass or sasl_pass_confirm.strip()) and new_pass != sasl_pass_confirm.strip():
        return fail("The password and its confirmation do not match.")

    updated = {
        "email_to": email_to.strip(),
        "email_from": email_from.strip(),
        "smtp_server": smtp_server.strip(),
        "email_maxperhour": email_maxperhour.strip(),
        "relayhost": relayhost.strip(),
        "sasl_user": sasl_user.strip(),
        "sasl_pass_set": True if new_pass else mail["sasl_pass_set"],
    }

    ok, ssh_output = run_mail_command_via_ssh(updated, sasl_pass=new_pass or None)
    request.state.log_detail = ssh_output
    if not ok:
        # A Postfix-dependent operation failed at runtime: re-check postfix
        # ONLY (never the whole plugin list) and show that alongside the
        # original error. One of only two paths allowed to move checked_at.
        postfix_entry = recheck_postfix()
        message = f"Could not reach the manager: {ssh_output}"
        if postfix_entry is not None:
            state = (
                f"installed, version {postfix_entry['version']}"
                if postfix_entry["verified"] else "NOT installed"
            )
            message += f" — Postfix re-check: {state}."
        return fail(message)

    # Only sasl_pass_set is persisted; the password itself never lands on
    # disk (docs/security/dashboard-side.md).
    save_mail_settings(updated)
    return RedirectResponse("/alerting?saved=1&tab=email", status_code=303)


# ======================================================================
# RULES - ossec.conf <email_alerts> blocks.
# These have no naturally unique field, so a block is addressed by its
# position, and every mutation must also carry the email_to it believes
# lives there. A mismatch means the list shifted underneath the operator
# and the edit is refused rather than applied to the wrong block.
# ======================================================================

@router.post("/alerting/rules")
async def email_rules_submit(
    request: Request,
    action: str = Form(...),
    id: str = Form(""),
    confirm_email_to: str = Form(""),
    email_to: str = Form(""),
    level: str = Form(""),
    rules_group: str = Form(""),
    rule_id: str = Form(""),
    event_location: str = Form(""),
    do_not_delay: str = Form(""),
    do_not_group: str = Form(""),
):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)

    data = {
        "email_to": email_to.strip(),
        "level": level.strip(),
        "rules_group": rules_group.strip(),
        "rule_id": rule_id.strip(),
        "event_location": event_location.strip(),
        "do_not_delay": bool(do_not_delay),
        "do_not_group": bool(do_not_group),
    }

    if action == "add":
        if not data["email_to"]:
            return _render(request, user, "email", "A recipient is required.")
        ok, message = ossec_config.add_block("email_alerts", data)

    elif action == "update":
        if not id:
            return _render(request, user, "email", "Which entry to edit was not given.")
        data["_confirm_email_to"] = confirm_email_to
        ok, message = ossec_config.update_block("email_alerts", id, data)

    elif action == "delete":
        if not id:
            return _render(request, user, "email", "Which entry to remove was not given.")
        ok, message = ossec_config.delete_block("email_alerts", id, confirm_email_to)

    else:
        return _render(request, user, "email", f"Unknown action: {action}")

    request.state.log_target = data["email_to"] or confirm_email_to
    request.state.log_detail = str(message)
    if not ok:
        return _render(request, user, "email", str(message))
    return _saved_redirect("/alerting?saved=1&tab=email", message)


# ======================================================================
# INTEGRATIONS - ossec.conf <integration> blocks, keyed by name.
# A rename is delete + add, so "name" is ignored on update and the real
# target is the hidden original_name.
# ======================================================================

@router.post("/alerting/integrations")
async def integrations_submit(
    request: Request,
    action: str = Form(...),
    name: str = Form(""),
    original_name: str = Form(""),
    hook_url: str = Form(""),
    api_key: str = Form(""),
    alert_format: str = Form(""),
    rule_id: str = Form(""),
    level: str = Form(""),
    group: str = Form(""),
    event_location: str = Form(""),
    options: str = Form(""),
):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)

    data = {
        "name": name.strip(),
        "hook_url": hook_url.strip(),
        "api_key": api_key.strip(),
        "alert_format": alert_format.strip(),
        "rule_id": rule_id.strip(),
        "level": level.strip(),
        "group": group.strip(),
        "event_location": event_location.strip(),
        "options": options.strip(),
    }

    if action == "add":
        if not data["name"] or not data["alert_format"]:
            return _render(
                request, user, "integrations",
                "Both a name and an alert format are required.",
            )
        ok, message = ossec_config.add_block("integration", data)

    elif action == "update":
        if not original_name:
            return _render(request, user, "integrations", "Which integration to edit was not given.")
        # A submitted name is deliberately NOT dropped here. The service
        # layer refuses a rename explicitly, and letting that refusal
        # surface is better than silently discarding the change and
        # reporting success for an edit that did not happen. The edit
        # form does not submit the field at all, so this only ever fires
        # for a request that went around the form.
        if not (data.get("name") or "").strip():
            data.pop("name", None)
        ok, message = ossec_config.update_block("integration", original_name, data)

    elif action == "delete":
        if not original_name:
            return _render(request, user, "integrations", "Which integration to remove was not given.")
        ok, message = ossec_config.delete_block("integration", original_name)

    else:
        return _render(request, user, "integrations", f"Unknown action: {action}")

    request.state.log_target = data.get("name") or original_name
    request.state.log_detail = str(message)
    if not ok:
        return _render(request, user, "integrations", str(message))
    return _saved_redirect("/alerting?saved=1&tab=integrations", message)

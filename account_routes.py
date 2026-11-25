"""Private email linking, explicit verification and forgotten-password forms."""

import logging
import os
import re

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for,
)

from account_service import (
    consume_token, delete_account as delete_account_service, normalize_email,
    private_email_status, request_account_email, save_account_email,
    take_request_limit, token_valid,
)
from auth_routes import _login_required, _require_csrf
from auth_service import PASSWORD_PATTERN
from email_delivery import delivery_ready

email_bp = Blueprint("account_email", __name__)


class _RedactAccountTokens(logging.Filter):
    def filter(self, record):
        message = record.getMessage()
        # Werkzeug access logs would otherwise retain bearer secrets from email links.
        record.msg = re.sub(r"(?i)(token=)[^&\s\"']+", r"\1[redacted]", message)
        record.args = ()
        return True


@email_bp.record_once
def _configure_email(state):
    state.app.config.setdefault(
        "ACCOUNT_EMAIL_ENABLED", os.environ.get("ACCOUNT_EMAIL_ENABLED", "").lower() == "true",
    )
    state.app.config.setdefault("ACCOUNT_EMAIL_FROM", os.environ.get("ACCOUNT_EMAIL_FROM", ""))
    state.app.config.setdefault("ACCOUNT_BASE_URL", os.environ.get("ACCOUNT_BASE_URL", ""))
    logger = logging.getLogger("werkzeug")
    if not any(isinstance(item, _RedactAccountTokens) for item in logger.filters):
        logger.addFilter(_RedactAccountTokens())


@email_bp.after_app_request
def _private_account_responses(response):
    if request.blueprint in {"auth", "account_email"}:
        response.headers["Cache-Control"] = "no-store, private"
        response.headers["Pragma"] = "no-cache"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Robots-Tag"] = "noindex, nofollow"
        response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@email_bp.get("/account/check-email")
def check_email():
    return render_template(
        "email_check.html", delivery_sent=bool(session.pop("signup_email_sent", False)),
    )


@email_bp.route("/account/email", methods=["GET", "POST"])
@_login_required
def settings():
    if request.method == "POST":
        return _save_email()
    return render_template(
        "account_email.html", email_status=private_email_status(g.current_user["username"]),
        delivery_ready=delivery_ready(),
    )


@email_bp.get("/account/delete")
@_login_required
def confirm_delete_account():
    """Show what will be retained before an account is deactivated."""
    return render_template(
        "account_delete_confirm.html",
        username=g.current_user["username"],
        role=g.current_user["role"],
        error=None,
    )


@email_bp.post("/account/delete")
@_login_required
@_require_csrf
def delete_account():
    """Require explicit confirmation and the current password to deactivate."""
    if request.form.get("confirm_delete") != "yes":
        return render_template(
            "account_delete_confirm.html",
            username=g.current_user["username"],
            role=g.current_user["role"],
            error="Confirm that you understand what happens to your account history.",
        ), 400
    try:
        delete_account_service(
            g.current_user["username"],
            request.form.get("current_password", ""),
        )
    except ValueError as error:
        return render_template(
            "account_delete_confirm.html",
            username=g.current_user["username"],
            role=g.current_user["role"],
            error=str(error),
        ), 400

    session.clear()
    flash(
        "Your account has been deactivated. Historical event and certificate records were retained.",
        "success",
    )
    return redirect(url_for("auth.login"), code=303)


@_require_csrf
def _save_email():
    try:
        status = save_account_email(
            g.current_user["username"], request.form.get("email", ""),
            request.form.get("current_password", ""),
        )
        flash(
            "Email address saved to your account."
            if status.get("email") == normalize_email(request.form.get("email", ""))
            else "New address saved. Your current verified address remains active until the new one is confirmed.",
            "success",
        )
    except ValueError as error:
        flash(str(error), "error")
    return redirect(url_for("account_email.settings"))


@email_bp.post("/account/email/resend")
@_login_required
@_require_csrf
def resend_own():
    if not delivery_ready():
        return redirect(url_for("account_email.settings"))
    status = private_email_status(g.current_user["username"])
    address = status.get("pending_email") or (
        status.get("email") if not status.get("email_verified") else None
    )
    if not delivery_ready():
        flash("Email delivery is not configured yet. Please try again later.", "error")
    else:
        if address:
            try:
                request_account_email(address, "verify", request.remote_addr or "unknown")
            except ValueError as error:
                flash(str(error), "error")
                return redirect(url_for("account_email.settings"))
        flash("If an unverified address is eligible, a verification link will be sent. Please wait before requesting another.", "success")
    return redirect(url_for("account_email.settings"))


def _request_email(kind):
    if not delivery_ready():
        return redirect(url_for("auth.login"))
    submitted = False
    ready = delivery_ready()
    if request.method == "POST":
        return _request_email_post(kind, ready)
    return render_template("email_request.html", kind=kind, submitted=submitted, delivery_ready=ready)


@_require_csrf
def _request_email_post(kind, ready):
    try:
        # Keep recovery working for previously verified addresses; only new
        # sign-up and account-email changes are restricted to the campus domain.
        address = normalize_email(request.form.get("email", ""))
    except ValueError as error:
        flash(str(error), "error")
        return render_template(
            "email_request.html", kind=kind, submitted=False, delivery_ready=ready,
        ), 400
    if ready:
        request_account_email(address, kind, request.remote_addr or "unknown")
    return render_template(
        "email_request.html", kind=kind, submitted=True, delivery_ready=ready,
    )


@email_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    return _request_email("reset")


@email_bp.route("/resend-verification", methods=["GET", "POST"])
def resend_verification():
    return _request_email("verify")


def _token_page(kind):
    token = request.args.get("token", "") if request.method == "GET" else request.form.get("token", "")
    if request.method == "POST":
        return _consume_token_post(kind, token)
    # A GET only displays confirmation; email link scanners cannot consume it.
    return render_template(
        "email_token.html", kind=kind, token=token, valid=token_valid(token, kind),
        password_pattern=PASSWORD_PATTERN,
    )


@_require_csrf
def _consume_token_post(kind, token):
    if not take_request_limit("token", "all-attempts:" + (request.remote_addr or "unknown"),
                              request.remote_addr or "unknown"):
        flash("Too many attempts. Please try again in an hour.", "error")
        return render_template(
            "email_token.html", kind=kind, token="", valid=False,
            password_pattern=PASSWORD_PATTERN,
        ), 429
    password = request.form.get("new_password", "")
    try:
        if kind == "reset" and password != request.form.get("confirm_password", ""):
            raise ValueError("The new passwords do not match.")
        consumed = consume_token(token, kind, password)
    except ValueError as error:
        flash(str(error), "error")
        return render_template(
            "email_token.html", kind=kind, token=token, valid=token_valid(token, kind),
            password_pattern=PASSWORD_PATTERN,
        ), 400
    if not consumed:
        return render_template(
            "email_token.html", kind=kind, token="", valid=False,
            password_pattern=PASSWORD_PATTERN,
        ), 400
    session.clear()
    flash(
        "Your email is verified. You can now sign in with your username or verified email."
        if kind == "verify" else
        "Your password has been reset. Sign in with your new password. Other sessions have been signed out.",
        "success",
    )
    return redirect(url_for("auth.login"))


@email_bp.route("/account/verify-email", methods=["GET", "POST"])
def verify_email():
    return _token_page("verify")


@email_bp.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    return _token_page("reset")

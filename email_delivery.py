"""Transactional account email via the connected Resend service.

Only this server-side adapter handles runtime authentication. It never fetches,
prints or persists a provider API key, recipient list, or message body.
"""

import json
import os
import subprocess
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from flask import current_app


class EmailDeliveryError(RuntimeError):
    """A safe error without provider response bodies, addresses or tokens."""

    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status

def _identity_headers():
    """Use the connector SDK's audience-scoped runtime identity protocol."""
    audience = os.environ.get("REPLIT_CONNECTORS_AUDIENCE", "https://connectors.replit.com")
    if not audience.startswith(("https://", "http://")):
        audience = "https://" + audience
    deployed = not os.environ.get("REPLIT_CONRUN") and any(
        os.environ.get(name) for name in (
            "REPLIT_DEPLOYMENT_ID", "REPLIT_DEPLOYMENT_ENVIRONMENT", "WEB_REPL_RENEWAL"
        )
    )
    try:
        token = subprocess.run(
            [os.environ.get("REPLIT_CLI", "replit"), "identity", "create",
             "--audience", audience],
            capture_output=True, text=True, timeout=5, check=True,
        ).stdout.strip()
        if not token:
            raise ValueError("Empty identity")
        token = ("depl " if deployed else "") + token
    except (OSError, ValueError, subprocess.SubprocessError):
        if deployed:
            try:
                req = Request(
                    "http://127.0.0.1:1105/getIdentityToken",
                    data=json.dumps({"audience": audience}).encode(),
                    headers={"Content-Type": "application/json"}, method="POST",
                )
                with urlopen(req, timeout=5) as response:
                    token = "depl " + json.load(response)["identityToken"].strip()
            except (OSError, ValueError, KeyError):
                raise EmailDeliveryError("Email authentication is unavailable.") from None
        elif os.environ.get("REPL_IDENTITY"):
            token = "repl " + os.environ["REPL_IDENTITY"]
        else:
            raise EmailDeliveryError("Email authentication is unavailable.") from None
    header = "X-Replit-Token" if token.startswith(("depl ", "repl ")) else "Replit-Authentication"
    return {header: token if header == "X-Replit-Token" else "Bearer " + token}


def connector_request(path, payload=None):
    """Fixed Resend proxy, bounded timeout, no credential/body error logging."""
    host = os.environ.get("REPLIT_CONNECTORS_HOSTNAME", "connectors.replit.com")
    base = host if host.startswith("https://") else "https://" + host
    headers = {
        **_identity_headers(), "Connector-Name": "resend",
        "Content-Type": "application/json", "Accept": "application/json",
        "User-Agent": "SkillMatch/1.0",
    }
    request = Request(
        base.rstrip("/") + "/api/v2/proxy" + path,
        data=json.dumps(payload).encode() if payload is not None else None,
        headers=headers, method="POST" if payload is not None else "GET",
    )
    try:
        with urlopen(request, timeout=12) as response:
            result = json.load(response)
        if not isinstance(result, dict) or result.get("error"):
            raise EmailDeliveryError("Email delivery is unavailable.")
        return result
    except HTTPError as error:
        raise EmailDeliveryError("Email delivery is unavailable.", error.code) from None
    except (URLError, TimeoutError, ValueError, OSError):
        raise EmailDeliveryError("Email delivery is unavailable.") from None


def delivery_ready():
    """Do not silently use a sandbox sender or an untrusted request Host."""
    sender = current_app.config.get("ACCOUNT_EMAIL_FROM", "").strip()
    base = current_app.config.get("ACCOUNT_BASE_URL", "")
    parsed = urlsplit(base)
    return bool(
        current_app.config.get("ACCOUNT_EMAIL_ENABLED", False)
        and sender and "\n" not in sender and "\r" not in sender
        and parsed.scheme == "https" and parsed.netloc
        and not parsed.username and not parsed.password
        and not parsed.query and not parsed.fragment and parsed.path in ("", "/")
    )


def send_account_email(address, kind, token):
    """Send only the requested verification/reset message to its one recipient."""
    if not delivery_ready():
        raise EmailDeliveryError("Email delivery has not been configured.")
    verify = kind == "verify"
    path = "/account/verify-email" if verify else "/reset-password"
    link = current_app.config["ACCOUNT_BASE_URL"].rstrip("/") + path + "?token=" + token
    subject = "Verify your SkillMatch email" if verify else "Reset your SkillMatch password"
    purpose = "verify this email address" if verify else "choose a new password"
    expiry = "24 hours" if verify else "1 hour"
    body = (
        f"Use this link to {purpose}:\n\n{link}\n\n"
        f"This link expires in {expiry} and works only once. "
        "Your username and saved SkillMatch records will not change.\n\n"
        "If you did not request this, ignore this message. "
        "Never share this link or your password."
    )
    result = connector_request("/emails", {
        "from": current_app.config["ACCOUNT_EMAIL_FROM"],
        "to": [address], "subject": subject, "text": body,
    })
    if not result.get("id"):
        raise EmailDeliveryError("Email delivery was not accepted.")

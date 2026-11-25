"""Private verified email and single-use recovery for existing SkillMatch users."""

import hashlib
import hmac
import re
import secrets
import time
from datetime import datetime, timezone

from werkzeug.security import check_password_hash, generate_password_hash

from data_store import edit_documents, load
from email_delivery import EmailDeliveryError, delivery_ready, send_account_email

USERS_FILE = "users.json"
LIMITS_FILE = "account_limits.json"
EMAIL_ERROR = "Enter a valid email address, such as name@gmail.com."
ALLOWED_EMAIL_DOMAIN = "mitwpu.edu.in"
EMAIL_DOMAIN_ERROR = "Please use your MIT-WPU email."
DUPLICATE_EMAIL = "This email cannot be used. Use another address or try account recovery."
PASSWORD_ERROR = "Use at least 8 characters, including one digit and one special character."
_EMAIL_RE = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,63}")
TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{43}")


def normalize_email(value):
    email = value.strip().lower() if isinstance(value, str) else ""
    local, _, domain = email.partition("@")
    if (
        len(email) > 254 or len(local) > 64 or not _EMAIL_RE.fullmatch(email)
        or local.startswith(".") or local.endswith(".") or ".." in email
        or any(not label or len(label) > 63 or label.startswith("-")
               or label.endswith("-") for label in domain.split("."))
    ):
        raise ValueError(EMAIL_ERROR)
    return email


def validate_mitwpu_email(value):
    """Normalize an address and require the exact MIT-WPU account domain."""
    email = normalize_email(value)
    if email.rsplit("@", 1)[1] != ALLOWED_EMAIL_DOMAIN:
        raise ValueError(EMAIL_DOMAIN_ERROR)
    return email


def email_available(users, email, excluding=None):
    """Reserve active/pending addresses; never inherit imported CSV emails."""
    for username, user in users.items():
        if username == excluding or not isinstance(user, dict):
            continue
        addresses = [user.get("email"), user.get("pending_email")]
        # Existing email-shaped usernames must not become another user's email login.
        addresses.append(username if "@" in username else None)
        if any(isinstance(item, str) and item.casefold() == email for item in addresses):
            return False
    return True


def _digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def _admit(limits, key, max_requests, window):
    """Persist limits using hashed identifiers, with bounded retention."""
    now = time.time()
    for old_key in list(limits):
        if limits[old_key].get("until", 0) <= now:
            del limits[old_key]
    bucket = limits.setdefault(_digest(key), {"until": now + window, "count": 0})
    if bucket["count"] >= max_requests:
        return False
    bucket["count"] += 1
    return True


def take_request_limit(kind, address, client_ip):
    """Limit all attempts, including nonexistent accounts, across workers."""
    with edit_documents(LIMITS_FILE) as docs:
        limits = docs[LIMITS_FILE]
        ip_ok = _admit(limits, f"{kind}:ip:{client_ip}", 20, 3600)
        email_ok = _admit(limits, f"{kind}:email:{address}", 20 if kind == "token" else 3, 3600)
        return ip_ok and email_ok


def _token_record(kind, email):
    token = secrets.token_urlsafe(32)
    return token, {
        "hash": _digest(token), "email": email,
        "expires_at": time.time() + (86400 if kind == "verify" else 3600),
    }


def _send(username, kind, token, email):
    """On send failure invalidate just this token; keep other account data."""
    try:
        if not delivery_ready():
            raise EmailDeliveryError("Email delivery is disabled.")
        send_account_email(email, kind, token)
        return True
    except EmailDeliveryError:
        field = "email_verification" if kind == "verify" else "password_reset"
        with edit_documents(USERS_FILE) as docs:
            user = docs[USERS_FILE].get(username, {})
            if user.get(field, {}).get("hash") == _digest(token):
                user.pop(field, None)
        return False


def start_email_link(username, email, password):
    """Require current password; keep existing verified email until confirmed."""
    email = normalize_email(email)
    error = None
    with edit_documents(USERS_FILE, LIMITS_FILE) as docs:
        users, limits = docs[USERS_FILE], docs[LIMITS_FILE]
        user = users.get(username)
        if not _admit(limits, f"link:{username}", 5, 3600):
            error = "Too many attempts. Please try again in an hour."
        elif not user or not check_password_hash(user.get("password_hash", ""), password):
            error = "Your current password is incorrect."
        elif user.get("email_verified") and user.get("email") == email:
            error = "This email is already verified on your account."
        elif not email_available(users, email, excluding=username):
            error = DUPLICATE_EMAIL
        else:
            token, record = _token_record("verify", email)
            user["pending_email"] = email
            user["email_verification"] = record
            user.pop("password_reset", None)
    if error:
        raise ValueError(error)
    return _send(username, "verify", token, email)


def save_account_email(username, email, password):
    """Save a private recovery address without treating it as verified."""
    email = validate_mitwpu_email(email)
    error = None
    with edit_documents(USERS_FILE, LIMITS_FILE) as docs:
        users, limits = docs[USERS_FILE], docs[LIMITS_FILE]
        user = users.get(username)
        if not _admit(limits, f"link:{username}", 5, 3600):
            error = "Too many attempts. Please try again in an hour."
        elif not user or not check_password_hash(user.get("password_hash", ""), password):
            error = "Your current password is incorrect."
        elif not email_available(users, email, excluding=username):
            error = DUPLICATE_EMAIL
        elif user.get("email_verified") and user.get("email") != email:
            # Never silently discard an address already proven to belong to the user.
            user["pending_email"] = email
            user.pop("email_verification", None)
        elif user.get("email_verified") and user.get("email") == email:
            pass
        else:
            user["email"] = email
            user["email_verified"] = False
            user["verification_required"] = False
            user.pop("pending_email", None)
            user.pop("email_verification", None)
            user.pop("password_reset", None)
    if error:
        raise ValueError(error)
    return private_email_status(username)


def request_account_email(email, kind, client_ip):
    """Return no account details; reset only a verified, explicitly linked email."""
    email = normalize_email(email)
    if not take_request_limit(kind, email, client_ip):
        return False
    match = None
    with edit_documents(USERS_FILE) as docs:
        for username, user in docs[USERS_FILE].items():
            if not isinstance(user, dict):
                continue
            target = user.get("pending_email") or (
                user.get("email") if not user.get("email_verified") else None
            ) if kind == "verify" else (
                user.get("email") if user.get("email_verified") else None
            )
            if target != email:
                continue
            token, record = _token_record(kind, email)
            user["email_verification" if kind == "verify" else "password_reset"] = record
            match = username, token
            break
    return _send(match[0], kind, match[1], email) if match else False


def private_email_status(username):
    """Only own-account routes may use this view; never g.current_user."""
    user = load(USERS_FILE).get(username, {})
    return {key: user.get(key) for key in ("email", "email_verified", "pending_email")}


def _find_token(users, token, kind):
    if not isinstance(token, str) or not TOKEN_RE.fullmatch(token):
        return None
    field = "email_verification" if kind == "verify" else "password_reset"
    hashed = _digest(token)
    for username, user in users.items():
        record = user.get(field) if isinstance(user, dict) else None
        if (
            not isinstance(record, dict) or record.get("expires_at", 0) <= time.time()
            or not hmac.compare_digest(record.get("hash", ""), hashed)
        ):
            continue
        expected = (user.get("pending_email") or (
            user.get("email") if not user.get("email_verified") else None
        )) if kind == "verify" else (
            user.get("email") if user.get("email_verified") else None
        )
        if expected and record.get("email") == expected:
            return username, user, record
    return None


def token_valid(token, kind):
    return _find_token(load(USERS_FILE), token, kind) is not None


def consume_token(token, kind, new_password=None):
    """Consume under row lock: one winner, even with concurrent POSTs."""
    if kind == "reset":
        # Local import avoids a cycle with registration's email validation.
        from auth_service import PASSWORD_PATTERN
        if not isinstance(new_password, str) or not re.fullmatch(PASSWORD_PATTERN, new_password):
            raise ValueError(PASSWORD_ERROR)
        password_hash = generate_password_hash(new_password)
    with edit_documents(USERS_FILE) as docs:
        users = docs[USERS_FILE]
        found = _find_token(users, token, kind)
        if not found:
            return False
        username, user, record = found
        if kind == "verify":
            if not email_available(users, record["email"], excluding=username):
                return False
            user["email"] = record["email"]
            user["email_verified"] = True
            user.pop("pending_email", None)
            user.pop("email_verification", None)
            user.pop("verification_required", None)
        else:
            user["password_hash"] = password_hash
            user["must_change_password"] = False
            user["session_version"] = user.get("session_version", 0) + 1
        user.pop("password_reset", None)
    return True


def change_account_password(username, current_password, new_password):
    """Revoke reset tokens and other sessions when changing a known password."""
    with edit_documents(USERS_FILE) as docs:
        user = docs[USERS_FILE].get(username)
        if not user or not check_password_hash(user.get("password_hash", ""), current_password):
            return None
        user["password_hash"] = generate_password_hash(new_password)
        user["must_change_password"] = False
        user.pop("password_reset", None)
        user.pop("email_verification", None)
        user["session_version"] = user.get("session_version", 0) + 1
        return user["session_version"]


def delete_account(username, current_password):
    """Deactivate an account and scrub profile data while retaining history."""
    if not isinstance(username, str) or not username.strip():
        raise ValueError("Sign in to delete your account.")
    username = username.strip()
    events_file = "events.json"
    notifications_file = "notifications.json"

    with edit_documents(USERS_FILE, events_file, notifications_file) as docs:
        users = docs[USERS_FILE]
        events = docs[events_file]
        notifications = docs[notifications_file]
        if not isinstance(users, dict):
            raise ValueError("users.json must contain an object keyed by username.")
        if not isinstance(events, dict):
            raise ValueError("events.json must contain an object keyed by event ID.")
        if not isinstance(notifications, dict):
            raise ValueError("notifications.json must contain an object keyed by username.")

        user = users.get(username)
        password_hash = user.get("password_hash") if isinstance(user, dict) else None
        try:
            password_valid = bool(
                isinstance(password_hash, str)
                and password_hash
                and isinstance(current_password, str)
                and check_password_hash(password_hash, current_password)
            )
        except (TypeError, ValueError):
            password_valid = False
        if not password_valid:
            raise ValueError("Your password is incorrect.")

        role = user.get("role")
        if role not in {"Organizer", "Student Volunteer"}:
            raise ValueError("This account cannot be deleted from account settings.")
        previous_version = user.get("session_version", 0)
        if not isinstance(previous_version, int) or isinstance(previous_version, bool):
            previous_version = 0

        deleted_at = datetime.now(timezone.utc).isoformat()
        if role == "Organizer":
            for event in events.values():
                if (
                    isinstance(event, dict)
                    and event.get("organizer") == username
                    and not event.get("deleted_at")
                ):
                    event["deleted_at"] = deleted_at

        notifications.pop(username, None)
        # Keep a minimal tombstone so historical usernames are not reused.
        users[username] = {
            "account_deleted_at": deleted_at,
            "deleted_role": role,
            "session_version": previous_version + 1,
        }

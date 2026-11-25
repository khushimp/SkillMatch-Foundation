"""Account and skill-matching services backed by the shared JSON store."""

from collections.abc import Mapping
import re
from typing import Any

from werkzeug.security import check_password_hash, generate_password_hash

from data_store import edit_documents, load
from account_service import DUPLICATE_EMAIL, email_available, validate_mitwpu_email


USERS_FILE = "users.json"
ALLOWED_ROLES = {"Organizer", "Student Volunteer"}
PASSWORD_PATTERN = r"(?=.*[0-9])(?=.*[^A-Za-z0-9\s]).{8,1024}"
_PASSWORD_RE = re.compile(rf"^{PASSWORD_PATTERN}$")


def _validated_skills(skills: Any) -> dict[str, int] | None:
    """Return cleaned integer skill ratings, or None when the input is invalid."""
    if skills is None:
        return {}
    if not isinstance(skills, Mapping):
        return None

    cleaned: dict[str, int] = {}
    seen: set[str] = set()
    for skill, rating in skills.items():
        if not isinstance(skill, str) or not skill.strip():
            return None
        normalized_name = skill.strip().casefold()
        if normalized_name in seen:
            return None
        if not isinstance(rating, int) or isinstance(rating, bool) or rating < 0:
            return None
        seen.add(normalized_name)
        cleaned[skill.strip()] = rating
    return cleaned


def register_user(
    username: str,
    password: str,
    role: str,
    name: str,
    dept: str | None = None,
    skills: Mapping[str, Any] | None = None,
    email: str | None = None,
    require_verification: bool = True,
) -> tuple[bool, str]:
    """Save a hashed account; email-less calls are for legacy/imported accounts.

    The public registration route always validates and supplies an email.
    """
    username = username.strip() if isinstance(username, str) else ""
    name = name.strip() if isinstance(name, str) else ""
    role = role.strip() if isinstance(role, str) else ""
    dept = dept.strip() if isinstance(dept, str) else ""

    if not username or len(username) > 64:
        return False, "Enter a username of 1 to 64 characters."
    if not name or len(name) > 100:
        return False, "Enter a name of 1 to 100 characters."
    if role not in ALLOWED_ROLES:
        return False, "Choose Organizer or Student Volunteer."
    if not isinstance(password, str) or len(password) > 1024:
        return False, "Use a password of 8 to 1024 characters."
    if not _PASSWORD_RE.fullmatch(password):
        return False, (
            "Password must be at least 8 characters and include at least "
            "one digit and one special character."
        )

    if role == "Organizer":
        dept = ""
        cleaned_skills = {}
    else:
        if not dept:
            return False, "Enter your department."
        cleaned_skills = _validated_skills(skills)
        if cleaned_skills is None:
            return False, "Enter skills as names with non-negative whole-number ratings."
        if not cleaned_skills:
            return False, "Add at least one skill to your volunteer profile."

    if email is not None:
        try:
            email = validate_mitwpu_email(email)
        except ValueError as error:
            return False, str(error)
    password_hash = generate_password_hash(password)
    with edit_documents(USERS_FILE) as docs:
        users = docs[USERS_FILE]
        if not isinstance(users, dict):
            raise ValueError("users.json must contain a JSON object keyed by username.")
        if username in users or any(
            isinstance(user, dict) and (
                username.casefold() in {user.get("email"), user.get("pending_email")}
                or ("@" in username and existing.casefold() == username.casefold())
            )
            for existing, user in users.items()
        ):
            return False, "That username is already registered."
        if email is not None and not email_available(users, email, excluding=username):
            return False, DUPLICATE_EMAIL
        users[username] = {
            "password_hash": password_hash,
            "role": role,
            "name": name,
            "dept": dept or None,
            "skills": cleaned_skills,
        }
        if email is not None:
            users[username].update(
                email=email, email_verified=False, verification_required=require_verification,
            )
    return True, "Your account has been created."


def login_user(username: str, password: str) -> dict[str, Any] | None:
    """Return the account for valid credentials, without revealing which failed."""
    username = username.strip() if isinstance(username, str) else ""
    if not username or not isinstance(password, str):
        return None

    users = load(USERS_FILE)
    if not isinstance(users, dict):
        raise ValueError("users.json must contain a JSON object keyed by username.")
    user = users.get(username)
    canonical_username = username
    if user is None and "@" in username:
        for candidate, account in users.items():
            if (
                isinstance(account, dict) and account.get("email_verified")
                and account.get("email") == username.casefold()
            ):
                user = account
                canonical_username = candidate
                break
    if not isinstance(user, dict):
        return None
    if user.get("account_deleted_at"):
        return None

    password_hash = user.get("password_hash")
    if not isinstance(password_hash, str) or not password_hash:
        return None
    try:
        if check_password_hash(password_hash, password):
            return {**user, "username": canonical_username}
    except (TypeError, ValueError):
        return None
    return None


def check_eligibility(
    student_skills: Mapping[str, Any],
    required_skills: Mapping[str, Any],
) -> bool:
    """Check minimum skills using trimmed, case-insensitive skill names."""
    student = _validated_skills(student_skills)
    required = _validated_skills(required_skills)
    if student is None or required is None:
        return False

    student_by_name = {name.casefold(): rating for name, rating in student.items()}
    required_by_name = {name.casefold(): rating for name, rating in required.items()}
    return all(
        student_by_name.get(skill, -1) >= minimum
        for skill, minimum in required_by_name.items()
    )

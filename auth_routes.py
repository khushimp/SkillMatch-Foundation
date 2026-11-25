"""Flask routes for SkillMatch account registration and profile management."""

import hmac
import json
import os
import re
import secrets
from datetime import timedelta
from functools import wraps
from pathlib import Path
from urllib.parse import urlsplit

from flask import (
    Blueprint,
    abort,
    flash,
    g,
    get_template_attribute,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from auth_service import PASSWORD_PATTERN, login_user, register_user
from certificate_service import (
    get_skill_passport,
    get_user_certificates,
    get_volunteer_badge,
)
from data_store import edit_documents, load
from account_service import (
    change_account_password, validate_mitwpu_email, request_account_email,
    take_request_limit,
)
from email_delivery import delivery_ready
from notification_service import get_unread_notification_count
from prismlabs_service import (
    ORGANIZER_USERNAME,
    TEST_VOLUNTEER_USERNAME,
    ensure_seeded,
    own_profile as get_prismlabs_profile,
)


USERS_FILE = "users.json"
PROFILE_SKILLS_FILE = Path(__file__).resolve().parent / "static" / "data" / "profile-skills.json"
auth_bp = Blueprint("auth", __name__)


@auth_bp.record_once
def _configure_session(state):
    """Configure signed, browser-protected sessions."""
    secret = os.environ.get("SESSION_SECRET")
    if not secret:
        # Local-development fallback only; set SESSION_SECRET in Replit Secrets before public deployment.
        secret = secrets.token_urlsafe(32)

    state.app.config.update(
        SECRET_KEY=secret,
        SESSION_COOKIE_NAME="skillmatch_session",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_SAMESITE="Lax",
        PERMANENT_SESSION_LIFETIME=timedelta(days=7),
    )


@auth_bp.before_app_request
def _load_current_user():
    """Load a safe public account view for role-aware templates."""
    if request.endpoint == "static":
        g.current_user = None
        return

    username = session.get("username")
    if not isinstance(username, str):
        g.current_user = None
        return

    users = load(USERS_FILE)
    user = users.get(username) if isinstance(users, dict) else None
    if not isinstance(user, dict) or user.get("account_deleted_at"):
        session.pop("username", None)
        g.current_user = None
        return
    if session.get("session_version", 0) != user.get("session_version", 0):
        session.clear()
        g.current_user = None
        return

    g.current_user = {
        "username": username,
        "name": user.get("name", ""),
        "role": user.get("role", ""),
        "dept": user.get("dept"),
        "skills": user.get("skills", {}),
        "must_change_password": bool(user.get("must_change_password")),
    }


@auth_bp.app_context_processor
def _inject_auth_context():
    """Expose the current account and a per-session form token to templates."""
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    current_user = getattr(g, "current_user", None)
    notification_unread_count = 0
    if (
        isinstance(current_user, dict)
        and current_user.get("role") in {"Organizer", "Student Volunteer"}
    ):
        notification_unread_count = get_unread_notification_count(
            current_user["username"]
        )
    return {
        "current_user": current_user,
        "csrf_token": token,
        "notification_unread_count": notification_unread_count,
        "account_email_delivery_ready": delivery_ready(),
    }


def _is_htmx_request() -> bool:
    return request.headers.get("HX-Request", "").lower() == "true"


def _toast_response(message: str, kind: str = "error", status: int = 200):
    """Render a notification through the shared Jinja toast macro."""
    toast = get_template_attribute("macros.html", "toast")
    return make_response(toast(message, kind), status)


def _valid_csrf_token() -> bool:
    expected = session.get("csrf_token")
    submitted = request.form.get("csrf_token", "")
    return (
        isinstance(expected, str)
        and bool(expected)
        and isinstance(submitted, str)
        and hmac.compare_digest(expected, submitted)
    )


def _csrf_failure():
    if _is_htmx_request():
        return _toast_response("Your form expired. Refresh the page and try again.")
    abort(400, description="The form token is missing or invalid.")


def _require_csrf(view):
    @wraps(view)
    def checked_view(*args, **kwargs):
        if not _valid_csrf_token():
            return _csrf_failure()
        return view(*args, **kwargs)

    return checked_view


def _login_required(view):
    @wraps(view)
    def authenticated_view(*args, **kwargs):
        current_user = getattr(g, "current_user", None)
        if current_user is None:
            flash("Please sign in to view your profile.", "error")
            login_url = url_for("auth.login", next=request.full_path.rstrip("?"))
            if _is_htmx_request():
                response = make_response("", 204)
                response.headers["HX-Redirect"] = login_url
                return response
            return redirect(login_url)
        if (
            current_user.get("must_change_password")
            and request.endpoint != "auth.change_password"
        ):
            return redirect(url_for("auth.change_password"))
        return view(*args, **kwargs)

    return authenticated_view


def _redirect_after_post(location: str):
    if _is_htmx_request():
        response = make_response("", 204)
        response.headers["HX-Redirect"] = location
        return response
    return redirect(location)


def _safe_next_url(candidate: str | None) -> str | None:
    if (
        not candidate
        or not candidate.startswith("/")
        or candidate.startswith("//")
        or "\\" in candidate
    ):
        return None
    parsed = urlsplit(candidate)
    if parsed.scheme or parsed.netloc:
        return None
    return candidate


def _parse_skills(raw_skills: str) -> tuple[dict[str, int] | None, str | None]:
    if not raw_skills.strip():
        return {}, None

    skills: dict[str, int] = {}
    seen: set[str] = set()
    for entry in raw_skills.split(","):
        skill, separator, raw_rating = entry.partition(":")
        skill = skill.strip()
        raw_rating = raw_rating.strip()
        if not separator or not skill:
            return None, "Use the format Skill:rating, for example Photography:4."
        try:
            rating = int(raw_rating)
        except ValueError:
            return None, "Skill ratings must be whole numbers of zero or higher."
        if rating < 0:
            return None, "Skill ratings must be whole numbers of zero or higher."
        normalized_skill = skill.casefold()
        if normalized_skill in seen:
            return None, "Each skill can only be listed once."
        seen.add(normalized_skill)
        skills[skill] = rating
    return skills, None


def _load_profile_skills_data() -> dict:
    """Load editable department and skill options from the separate JSON file."""
    with PROFILE_SKILLS_FILE.open("r", encoding="utf-8") as data_file:
        data = json.load(data_file)
    if not isinstance(data, dict) or not isinstance(data.get("schools"), list):
        raise ValueError("Profile skills data must contain a schools list.")
    if not isinstance(data.get("general_skills"), list):
        raise ValueError("Profile skills data must contain a general_skills list.")
    if not isinstance(data.get("spoken_languages"), list):
        raise ValueError("Profile skills data must contain a spoken_languages list.")
    return data


def _normalize_profile_label(value: str) -> str:
    """Normalize case and repeated whitespace for catalog comparisons."""
    return " ".join(value.split()).casefold()


def _profile_skill_name_map() -> dict[str, str]:
    """Map normalized catalog skill names to their canonical spelling."""
    data = _load_profile_skills_data()
    names = []
    for school in data["schools"]:
        names.extend(school.get("skills", []))
        for department in school.get("departments", []):
            names.extend(department.get("skills", []))
    names.extend(data["general_skills"])
    names.extend(data["spoken_languages"])
    result = {}
    for name in names:
        result.setdefault(_normalize_profile_label(name), name)
    return result


def _profile_department_names() -> set[str]:
    """Return department names plus school-level choices without departments."""
    names = set()
    for school in _load_profile_skills_data()["schools"]:
        departments = school.get("departments", [])
        if departments:
            names.update(
                department["name"]
                for department in departments
                if isinstance(department, dict)
                and isinstance(department.get("name"), str)
            )
        elif isinstance(school.get("name"), str):
            names.add(school["name"])
    return names


def _profile_department_name_map() -> dict[str, str]:
    """Map saved department labels to current canonical names."""
    return {
        _normalize_profile_label(name): name
        for name in _profile_department_names()
    }


def _parse_profile_skills(raw_skills: str, *, enforce_limit: bool = True):
    """Parse the existing comma-separated skill format with 1–5 ratings."""
    if not isinstance(raw_skills, str):
        return None, "Choose at least one skill."
    if not raw_skills.strip():
        return {}, None

    skills = {}
    seen = set()
    for entry in raw_skills.split(","):
        name, separator, raw_rating = entry.partition(":")
        name = name.strip()
        if not separator or not name:
            return None, "Each selected skill needs a rating from 1 to 5."
        if len(name) > 80:
            return None, "Skill names can be up to 80 characters."
        try:
            rating = int(raw_rating.strip())
        except ValueError:
            return None, f"Choose a 1–5 rating for {name}."
        if not 1 <= rating <= 5:
            return None, f"{name} must have a rating from 1 to 5."
        normalized = name.casefold()
        if normalized in seen:
            return None, f"Remove the duplicate skill: {name}."
        seen.add(normalized)
        skills[name] = rating
        if enforce_limit and len(skills) > 15:
            return None, "Choose no more than 15 skills."
    return skills, None


def _profile_skills_for_picker(raw_skills):
    """Build editable rows from stored values, including older 0-rated skills."""
    if isinstance(raw_skills, dict):
        entries = raw_skills.items()
    elif isinstance(raw_skills, str):
        entries = []
        for part in raw_skills.split(","):
            name, separator, raw_rating = part.partition(":")
            if separator:
                try:
                    rating = int(raw_rating.strip())
                except ValueError:
                    rating = 3
                entries.append((name.strip(), rating))
    else:
        entries = []

    catalog_names = _profile_skill_name_map()
    selected = []
    seen = set()
    for name, rating in entries:
        if not isinstance(name, str) or not name.strip():
            continue
        normalized = _normalize_profile_label(name)
        if normalized in seen:
            continue
        seen.add(normalized)
        canonical_name = catalog_names.get(normalized, name.strip())
        if not isinstance(rating, int) or isinstance(rating, bool):
            rating = 3
        selected.append({
            "name": canonical_name,
            "rating": rating,
            "is_custom": normalized not in catalog_names,
        })
    return selected


def _serialize_profile_skill_rows(rows):
    return ", ".join(f"{row['name']}:{row['rating']}" for row in rows)


def _filtered_department_schools(search: str = ""):
    normalized_search = search.strip().casefold()
    schools = []
    for school in _load_profile_skills_data()["schools"]:
        if not isinstance(school, dict) or not isinstance(school.get("departments"), list):
            continue
        school_matches = (
            not normalized_search
            or normalized_search in school.get("name", "").casefold()
        )
        if not school["departments"]:
            if school_matches:
                schools.append({
                    "name": school.get("name", ""),
                    "departments": [],
                    "skills": school.get("skills", []),
                })
            continue
        departments = [
            department
            for department in school["departments"]
            if isinstance(department, dict)
            and isinstance(department.get("name"), str)
            and (
                not normalized_search
                or school_matches
                or normalized_search in department["name"].casefold()
            )
        ]
        if departments:
            schools.append({
                "name": school.get("name", ""),
                "departments": departments,
                "skills": [],
            })
    return schools


def _available_profile_skills(department: str, search: str = ""):
    data = _load_profile_skills_data()
    normalized_search = search.strip().casefold()
    department_skills = []
    for school in data["schools"]:
        if not school.get("departments") and school.get("name") == department:
            department_skills = school.get("skills", [])
            break
        for item in school.get("departments", []):
            if item.get("name") == department:
                department_skills = item.get("skills", [])
                break
        if department_skills:
            break
    spoken_languages = data["spoken_languages"]
    if normalized_search:
        department_skills = [
            skill for skill in department_skills
            if normalized_search in skill.casefold()
        ]
        general_skills = [
            skill for skill in data["general_skills"]
            if normalized_search in skill.casefold()
        ]
        spoken_languages = [
            language for language in spoken_languages
            if normalized_search in language.casefold()
        ]
    else:
        general_skills = data["general_skills"]
    return department_skills, general_skills, spoken_languages


def _cross_department_profile_skills(department: str, search: str = ""):
    """Return catalog skills from other departments, excluding current/general skills."""
    data = _load_profile_skills_data()
    current_department = department.strip().casefold()
    excluded = {
        _normalize_profile_label(skill)
        for skill in data["general_skills"] + data["spoken_languages"]
    }
    seen = set(excluded)
    current_skills = []
    for school in data["schools"]:
        if not school.get("departments") and _normalize_profile_label(
            school.get("name", "")
        ) == _normalize_profile_label(current_department):
            current_skills.extend(school.get("skills", []))
        for item in school.get("departments", []):
            if _normalize_profile_label(item.get("name", "")) == _normalize_profile_label(current_department):
                current_skills.extend(item.get("skills", []))
    excluded.update(_normalize_profile_label(skill) for skill in current_skills)

    normalized_search = search.strip().casefold()
    cross_department_skills = []
    for school in data["schools"]:
        for item in school.get("departments", []):
            if _normalize_profile_label(item.get("name", "")) == _normalize_profile_label(current_department):
                continue
            for skill in item.get("skills", []):
                normalized_skill = _normalize_profile_label(skill)
                if normalized_skill in excluded or normalized_skill in seen:
                    continue
                seen.add(normalized_skill)
                if not normalized_search or normalized_search in normalized_skill:
                    cross_department_skills.append(skill)
        if not school.get("departments") and _normalize_profile_label(
            school.get("name", "")
        ) != _normalize_profile_label(current_department):
            for skill in school.get("skills", []):
                normalized_skill = _normalize_profile_label(skill)
                if normalized_skill in excluded or normalized_skill in seen:
                    continue
                seen.add(normalized_skill)
                if not normalized_search or normalized_search in normalized_skill:
                    cross_department_skills.append(skill)
    return cross_department_skills


def _profile_form_error(field: str, message: str, form_data: dict):
    context = _profile_context(
        editing=True, form_data=form_data, form_errors={field: message},
    )
    if _is_htmx_request():
        return render_template(
            "profile_form_error.html", field=field, message=message,
        )
    return render_template("profile.html", **context), 400


def _profile_completion(user: dict) -> int:
    name_complete = bool(str(user.get("name") or "").strip())
    if user.get("role") == "Organizer":
        return 100 if name_complete else 0
    dept_complete = bool(str(user.get("dept") or "").strip())
    skills = user.get("skills")
    skills_complete = isinstance(skills, dict) and bool(skills)
    completed = sum((name_complete, dept_complete, skills_complete))
    return round(completed / 3 * 100)


def _form_error(message: str, template_name: str, context: dict):
    if _is_htmx_request():
        return _toast_response(message)
    flash(message, "error")
    return render_template(template_name, **context)


def _registration_context(form_data: dict | None = None) -> dict:
    values = {
        "role": "Student Volunteer",
        "dept": "",
        "skills": "",
    }
    values.update(form_data or {})
    selected_rows = _profile_skills_for_picker(values.get("skills", ""))
    values["skills"] = _serialize_profile_skill_rows(selected_rows)
    department_skills, general_skills, spoken_languages = _available_profile_skills(
        values.get("dept", "")
    )
    cross_department_skills = _cross_department_profile_skills(values.get("dept", ""))
    return {
        "form_data": values,
        "password_pattern": PASSWORD_PATTERN,
        "profile_schools": _filtered_department_schools(),
        "department_search": "",
        "selected_department": values.get("dept", ""),
        "known_profile_departments": _profile_department_names(),
        "department_needs_reselection": False,
        "profile_department": values.get("dept", ""),
        "profile_selected_skills": selected_rows,
        "profile_skills_string": values["skills"],
        "profile_skill_search": "",
        "profile_active_skill_group": "department",
        "profile_skill_error": None,
        "profile_department_skills": department_skills,
        "profile_general_skills": general_skills,
        "profile_spoken_languages": spoken_languages,
        "profile_cross_department_skills": cross_department_skills,
        "profile_cross_skill_search": "",
        "profile_form_id": "registration-form",
        "profile_skill_picker_url": url_for("auth.registration_skills"),
        "profile_department_options_url": url_for("auth.registration_department_options"),
    }


def _profile_context(
    editing: bool,
    form_data: dict | None = None,
    form_errors: dict | None = None,
) -> dict:
    user = g.current_user
    skills = user.get("skills") if isinstance(user.get("skills"), dict) else {}
    default_form_data = {
        "name": user.get("name", ""),
        "dept": user.get("dept") or "",
        "skills": ", ".join(
            f"{skill}:{rating}"
            for skill, rating in sorted(skills.items(), key=lambda item: item[0].casefold())
        ),
    }
    if form_data:
        default_form_data.update(form_data)
    department_name_map = _profile_department_name_map()
    saved_department = str(default_form_data.get("dept") or "")
    default_form_data["dept"] = department_name_map.get(
        _normalize_profile_label(saved_department),
        saved_department,
    )
    certificate_notifications = []
    certificate_notification_error = None
    volunteer_badge = None
    volunteer_badge_error = None
    skill_passport = None
    skill_passport_error = None
    if not editing and user.get("role") == "Student Volunteer":
        try:
            skill_passport = get_skill_passport(user["username"])
        except ValueError as error:
            skill_passport_error = str(error)
        try:
            certificate_notifications = [
                record
                for record in get_user_certificates(user["username"])
                if isinstance(record.get("verification_code"), str)
                and len(record["verification_code"]) == 10
                and record["verification_code"].isalnum()
            ]
        except ValueError as error:
            certificate_notification_error = str(error)
        try:
            volunteer_badge = get_volunteer_badge(user["username"])
        except ValueError as error:
            volunteer_badge_error = str(error)
    prismlabs_participation = None
    if not editing and user.get("role") == "Student Volunteer":
        prismlabs_participation = get_prismlabs_profile(user["username"])
    selected_rows = _profile_skills_for_picker(default_form_data.get("skills", ""))
    default_form_data["skills"] = _serialize_profile_skill_rows(selected_rows)
    department_skills, general_skills, spoken_languages = _available_profile_skills(
        default_form_data.get("dept", "")
    )
    cross_department_skills = _cross_department_profile_skills(
        default_form_data.get("dept", "")
    )
    return {
        "user": user,
        "is_organizer": user.get("role") == "Organizer",
        "completion_percent": _profile_completion(user),
        "editing": editing,
        "form_data": default_form_data,
        "form_errors": form_errors or {},
        "skill_items": [
            (row["name"], row["rating"], row["is_custom"])
            for row in selected_rows
        ],
        "profile_selected_skills": selected_rows,
        "selected_department": default_form_data.get("dept", ""),
        "profile_schools": _filtered_department_schools(),
        "known_profile_departments": _profile_department_names(),
        "department_search": "",
        "department_needs_reselection": (
            bool(default_form_data.get("dept"))
            and _normalize_profile_label(default_form_data.get("dept"))
            not in department_name_map
        ),
        "profile_department_options_url": url_for("auth.profile_department_options"),
        "profile_department_skills": department_skills,
        "profile_general_skills": general_skills,
        "profile_spoken_languages": spoken_languages,
        "profile_cross_department_skills": cross_department_skills,
        "profile_cross_skill_search": "",
        "profile_skill_search": "",
        "profile_active_skill_group": "department",
        "profile_skill_error": None,
        "profile_skill_picker_url": url_for("auth.profile_skill_picker"),
        "profile_form_id": "profile-edit-form",
        "certificate_notifications": certificate_notifications,
        "certificate_notification_error": certificate_notification_error,
        "volunteer_badge": volunteer_badge,
        "volunteer_badge_error": volunteer_badge_error,
        "skill_passport": skill_passport,
        "skill_passport_error": skill_passport_error,
        "prismlabs_participation": prismlabs_participation,
    }


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        if getattr(g, "current_user", None) is not None:
            return _redirect_after_post(url_for("auth.profile"))
        role = request.args.get("role", "Student Volunteer")
        if role not in ("Organizer", "Student Volunteer"):
            role = "Student Volunteer"
        return render_template(
            "register.html", **_registration_context({"role": role})
        )
    if not _valid_csrf_token():
        return _csrf_failure()

    password = request.form.get("password", "")
    if password != request.form.get("confirm_password", ""):
        return _form_error(
            "The passwords do not match.",
            "register.html",
            _registration_context({
                "username": request.form.get("username", "").strip(),
                "name": request.form.get("name", "").strip(),
                "role": request.form.get("role", "Student Volunteer").strip(),
                "dept": request.form.get("dept", "").strip(),
                "skills": request.form.get("skills", "").strip(),
                "email": request.form.get("email", "").strip(),
            }),
        )

    form_data = {
        "username": request.form.get("username", "").strip(),
        "name": request.form.get("name", "").strip(),
        "role": request.form.get("role", "Student Volunteer").strip(),
        "dept": request.form.get("dept", "").strip(),
        "skills": request.form.get("skills", "").strip(),
        "email": request.form.get("email", "").strip(),
    }
    if (
        not form_data["name"]
        or not any(character.isalpha() for character in form_data["name"])
        or any(
            not character.isalpha() and character != " "
            for character in form_data["name"]
        )
    ):
        return _form_error(
            "Full name can contain letters and spaces only.",
            "register.html",
            _registration_context(form_data),
        )
    if form_data["role"] == "Organizer":
        form_data["dept"] = ""
        form_data["skills"] = ""
        skills = {}
    else:
        if not form_data["dept"]:
            return _form_error(
                "Enter your department.",
                "register.html",
                _registration_context(form_data),
            )
        skills, skills_error = _parse_skills(form_data["skills"])
        if skills_error:
            return _form_error(
                skills_error,
                "register.html",
                _registration_context(form_data),
            )
        if not skills:
            return _form_error(
                "Add at least one skill to your volunteer profile.",
                "register.html",
                _registration_context(form_data),
            )

    try:
        form_data["email"] = validate_mitwpu_email(form_data["email"])
    except ValueError as error:
        return _form_error(str(error), "register.html", _registration_context(form_data))
    if not take_request_limit("signup", form_data["email"], request.remote_addr or "unknown"):
        return _form_error(
            "Too many sign-up attempts. Please try again in an hour.",
            "register.html", _registration_context(form_data),
        )
    success, message = register_user(
        username=form_data["username"],
        password=password,
        role=form_data["role"],
        name=form_data["name"],
        dept=form_data["dept"] or None,
        skills=skills,
        email=form_data["email"],
        require_verification=delivery_ready(),
    )
    if not success:
        return _form_error(
            message,
            "register.html",
            _registration_context(form_data),
        )

    sent = False
    if delivery_ready():
        sent = request_account_email(
            form_data["email"], "verify", request.remote_addr or "unknown"
        )
    session.clear()
    if not delivery_ready():
        session["username"] = form_data["username"]
        session["session_version"] = 0
        session.permanent = True
        flash("Your account is ready. You can sign in with your username.", "success")
        return _redirect_after_post(url_for("auth.profile"))
    session["signup_email_sent"] = sent
    if not sent:
        with edit_documents(USERS_FILE) as docs:
            account = docs[USERS_FILE].get(form_data["username"])
            if isinstance(account, dict):
                account["verification_required"] = False
        session["username"] = form_data["username"]
        session["session_version"] = 0
        session.permanent = True
        flash("Your account is ready. You can sign in with your username.", "success")
        return _redirect_after_post(url_for("auth.profile"))
    return _redirect_after_post(url_for("account_email.check_email"))


@auth_bp.get("/register/profile-fields")
def registration_profile_fields():
    """Return role-specific registration fields after an HTMX role change."""
    role = request.args.get("role", "Student Volunteer")
    if role not in ("Organizer", "Student Volunteer"):
        role = "Student Volunteer"
    context = _registration_context({
        "role": role,
        "dept": request.args.get("dept", ""),
        "skills": request.args.get("skills", ""),
    })
    return render_template("registration_fields.html", **context)


@auth_bp.get("/register/departments")
def registration_department_options():
    """Return searchable department options for the public sign-up form."""
    return render_template(
        "profile_department_select.html",
        selected_department=request.args.get("dept", "").strip(),
        department_search=request.args.get("department_search", "").strip(),
        profile_schools=_filtered_department_schools(
            request.args.get("department_search", "")
        ),
        known_profile_departments=_profile_department_names(),
        department_needs_reselection=False,
        profile_department_options_url=url_for("auth.registration_department_options"),
        profile_skill_picker_url=url_for("auth.registration_skills"),
        profile_form_id="registration-form",
    )


@auth_bp.route("/register/skills", methods=["GET", "POST"])
def registration_skills():
    """Serve the sign-up skill picker without requiring an existing account."""
    if request.method == "POST" and not _valid_csrf_token():
        return _csrf_failure()
    department = request.values.get("dept", "").strip()
    search = request.values.get("skill_search", "").strip()
    cross_search = request.values.get("cross_skill_search", "").strip()
    active_skill_group = request.values.get("skill_group", "department")
    raw_skills = request.values.get("skills", "")
    parsed_skills, error = _parse_profile_skills(raw_skills, enforce_limit=False)
    selected_rows = (
        _profile_skills_for_picker(parsed_skills)
        if parsed_skills is not None
        else _profile_skills_for_picker(raw_skills)
    )
    context = {
        **_profile_skill_picker_context(department, selected_rows, search),
        "profile_skill_picker_url": url_for("auth.registration_skills"),
        "profile_form_id": "registration-form",
        "profile_cross_department_skills": _cross_department_profile_skills(
            department, cross_search,
        ),
        "profile_cross_skill_search": cross_search,
        "profile_active_skill_group": active_skill_group,
    }
    if request.method == "GET":
        if _cross_skill_fragment_requested():
            return render_template("profile_cross_department_skills.html", **context)
        return render_template("profile_available_skills.html", **context)

    action = request.form.get("action", "")
    action_skill = _requested_profile_skill()
    if error is None and action == "add_skill":
        available = _available_profile_skills(department)
        allowed = {
            name.casefold()
            for group in (*available, _cross_department_profile_skills(department))
            for name in group
        }
        if action_skill.casefold() not in allowed:
            error = "Choose a skill from the available skill lists."
        elif any(row["name"].casefold() == action_skill.casefold() for row in selected_rows):
            error = f"{action_skill} is already selected."
        elif len(selected_rows) >= 15:
            error = "Choose no more than 15 skills."
        else:
            selected_rows.append({"name": action_skill, "rating": 3})
    elif error is None and action == "add_custom":
        custom_skill = request.form.get("custom_skill", "").strip()
        if not custom_skill or len(custom_skill) > 80:
            error = "Enter a custom skill name of 1 to 80 characters."
        elif "," in custom_skill or ":" in custom_skill:
            error = "Custom skill names cannot include commas or colons."
        elif any(row["name"].casefold() == custom_skill.casefold() for row in selected_rows):
            error = f"{custom_skill} is already selected."
        elif len(selected_rows) >= 15:
            error = "Choose no more than 15 skills."
        else:
            selected_rows.append({"name": custom_skill, "rating": 3})
    elif error is None and action == "remove":
        before = len(selected_rows)
        selected_rows = [
            row for row in selected_rows
            if row["name"].casefold() != action_skill.casefold()
        ]
        if len(selected_rows) == before:
            error = "That selected skill could not be found."
    elif error is None and action == "rate":
        try:
            rating = int(request.form.get("rating", ""))
        except ValueError:
            rating = 0
        match = next(
            (
                row for row in selected_rows
                if row["name"].casefold() == action_skill.casefold()
            ),
            None,
        )
        if match is None:
            error = "That selected skill could not be found."
        elif not 1 <= rating <= 5:
            error = "Choose a rating from 1 to 5."
        else:
            match["rating"] = rating
    elif error is None and action not in {"", "department"}:
        error = "Choose a valid skill action."

    context.update(
        _profile_skill_picker_context(department, selected_rows, search, error)
    )
    context["profile_skill_picker_url"] = url_for("auth.registration_skills")
    context["profile_form_id"] = "registration-form"
    context["profile_cross_department_skills"] = _cross_department_profile_skills(
        department, cross_search,
    )
    context["profile_cross_skill_search"] = cross_search
    context["profile_active_skill_group"] = active_skill_group
    return render_template("profile_skill_picker.html", **context)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        if getattr(g, "current_user", None) is not None:
            return _redirect_after_post(url_for("auth.profile"))
        return render_template(
            "login.html",
            username="",
            next_url=_safe_next_url(request.args.get("next")),
        )
    if not _valid_csrf_token():
        return _csrf_failure()

    username = request.form.get("username", "").strip()
    if username in {ORGANIZER_USERNAME, TEST_VOLUNTEER_USERNAME}:
        ensure_seeded()
    next_url = _safe_next_url(request.form.get("next"))
    user = login_user(username, request.form.get("password", ""))
    if user is None:
        if _is_htmx_request():
            return _toast_response("Username or password is incorrect.")
        flash("Username or password is incorrect.", "error")
        return render_template(
            "login.html",
            username=username,
            next_url=next_url,
        )

    if user.get("verification_required") and not user.get("email_verified"):
        message = "Verify your email before signing in. Use Resend verification email if you need a new link."
        if _is_htmx_request():
            return _toast_response(message)
        flash(message, "error")
        return render_template("login.html", username=username, next_url=next_url)
    session.clear()
    session["username"] = user["username"]
    session["session_version"] = user.get("session_version", 0)
    session.permanent = True
    if user.get("must_change_password"):
        return _redirect_after_post(url_for("auth.change_password"))
    flash("You are signed in.", "success")
    return _redirect_after_post(next_url or url_for("auth.profile"))


@auth_bp.route("/account/password", methods=["GET", "POST"])
@_login_required
def change_password():
    if request.method == "GET":
        return render_template("change_password.html")
    if not _valid_csrf_token():
        return _csrf_failure()
    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    if new_password != request.form.get("confirm_password", ""):
        flash("The new passwords do not match.", "error")
        return render_template("change_password.html"), 400
    if not re.fullmatch(PASSWORD_PATTERN, new_password):
        flash(
            "Use at least 8 characters, including one digit and one special character.",
            "error",
        )
        return render_template("change_password.html"), 400
    username = g.current_user["username"]
    version = change_account_password(username, current_password, new_password)
    if version is None:
        flash("The current password is incorrect.", "error")
        return render_template("change_password.html"), 400
    session["session_version"] = version
    flash("Your password has been updated.", "success")
    return _redirect_after_post(
        url_for("dashboard.home")
        if g.current_user.get("role") == "Organizer"
        else url_for("auth.profile")
    )


@auth_bp.post("/logout")
@_require_csrf
def logout():
    session.clear()
    flash("You have signed out.", "success")
    return _redirect_after_post(url_for("auth.login"))


@auth_bp.get("/profile")
@_login_required
def profile():
    return render_template("profile.html", **_profile_context(editing=False))


@auth_bp.route("/profile/edit", methods=["GET", "POST"])
@_login_required
def edit_profile():
    if request.method == "GET":
        return render_template("profile.html", **_profile_context(editing=True))
    if not _valid_csrf_token():
        return _csrf_failure()

    form_data = {
        "name": request.form.get("name", "").strip(),
        "dept": request.form.get("dept", "").strip(),
        "skills": request.form.get("skills", "").strip(),
    }
    if not form_data["name"] or len(form_data["name"]) > 100:
        return _profile_form_error(
            "name",
            "Enter a name of 1 to 100 characters.",
            form_data,
        )
    username = session.get("username")
    users = load(USERS_FILE)
    account = users.get(username) if isinstance(users, dict) else None
    if not isinstance(account, dict):
        session.clear()
        return _redirect_after_post(url_for("auth.login"))

    if account.get("role") == "Organizer":
        form_data["dept"] = ""
        form_data["skills"] = ""
        skills = {}
    else:
        if not form_data["dept"]:
            return _profile_form_error(
                "dept",
                "Enter your department.",
                form_data,
            )
        if len(form_data["dept"]) > 100:
            return _profile_form_error(
                "dept",
                "Department names can be up to 100 characters.",
                form_data,
            )
        known_departments = _profile_department_names()
        if (
            form_data["dept"] not in known_departments
            and form_data["dept"] != g.current_user.get("dept")
        ):
            return _profile_form_error(
                "dept",
                "Choose a department from the list.",
                form_data,
            )
        skills, skills_error = _parse_profile_skills(form_data["skills"])
        if skills_error:
            return _profile_form_error(
                "skills",
                skills_error,
                form_data,
            )
        if not skills:
            return _profile_form_error(
                "skills",
                "Add at least one skill to your volunteer profile.",
                form_data,
            )

    with edit_documents(USERS_FILE) as docs:
        docs[USERS_FILE][username].update(
            name=form_data["name"],
            dept=form_data["dept"] or None,
            skills=skills,
        )
    flash("Your profile has been updated.", "success")
    return _redirect_after_post(url_for("auth.profile"))


@auth_bp.get("/profile/edit/departments")
@_login_required
def profile_department_options():
    """Return searchable department options while preserving the current value."""
    if g.current_user.get("role") != "Student Volunteer":
        abort(403)
    selected_department = request.args.get("dept", "").strip()
    department_map = _profile_department_name_map()
    selected_department = department_map.get(
        _normalize_profile_label(selected_department),
        selected_department,
    )
    return render_template(
        "profile_department_select.html",
        selected_department=selected_department,
        department_search=request.args.get("department_search", "").strip(),
        profile_schools=_filtered_department_schools(
            request.args.get("department_search", "")
        ),
        known_profile_departments=_profile_department_names(),
        department_needs_reselection=(
            bool(selected_department)
            and _normalize_profile_label(selected_department) not in department_map
        ),
        profile_skill_picker_url=url_for("auth.profile_skill_picker"),
        profile_form_id="profile-edit-form",
    )


def _profile_skill_picker_context(
    department, selected_rows, search="", error=None, active_skill_group="department",
):
    department_skills, general_skills, spoken_languages = _available_profile_skills(
        department, search,
    )
    return {
        "profile_department": department,
        "profile_selected_skills": selected_rows,
        "profile_skills_string": _serialize_profile_skill_rows(selected_rows),
        "profile_skill_search": search,
        "profile_active_skill_group": active_skill_group,
        "profile_skill_error": error,
        "profile_department_skills": department_skills,
        "profile_general_skills": general_skills,
        "profile_spoken_languages": spoken_languages,
        "profile_cross_department_skills": _cross_department_profile_skills(department),
        "profile_cross_skill_search": "",
        "profile_skill_picker_url": url_for("auth.profile_skill_picker"),
        "profile_form_id": "profile-edit-form",
    }

def _cross_skill_fragment_requested():
    """Use the request's target, not other search fields included by the form."""
    target = request.headers.get("HX-Target", "")
    if target:
        return target == "cross-department-skill-options"
    group = request.args.get("skill_group")
    if group:
        return group == "cross"
    return "cross_skill_search" in request.args and "skill_search" not in request.args


def _requested_profile_skill():
    """Each selector has its own name so other selectors cannot override it."""
    group = request.form.get("skill_group", "")
    field = {"department": "department_skill", "general": "general_skill", "cross": "cross_skill"}.get(group)
    if field and request.form.get("action") == "add_skill":
        return request.form.get(field, request.form.get("skill", "")).strip()
    return request.form.get("skill", "").strip()


@auth_bp.route("/profile/edit/skills", methods=["GET", "POST"])
@_login_required
def profile_skill_picker():
    """Update skill picker choices through server-rendered HTMX fragments."""
    if g.current_user.get("role") != "Student Volunteer":
        abort(403)
    if request.method == "POST" and not _valid_csrf_token():
        return _csrf_failure()
    department = request.values.get("dept", "").strip()
    search = request.values.get("skill_search", "").strip()
    cross_search = request.values.get("cross_skill_search", "").strip()
    active_skill_group = request.values.get("skill_group", "department")
    raw_skills = request.values.get("skills", "")
    parsed_skills, error = _parse_profile_skills(raw_skills, enforce_limit=False)
    selected_rows = (
        _profile_skills_for_picker(parsed_skills)
        if parsed_skills is not None
        else _profile_skills_for_picker(raw_skills)
    )
    if request.method == "GET":
        if _cross_skill_fragment_requested():
            return render_template(
                "profile_cross_department_skills.html",
                **{
                    **_profile_skill_picker_context(
                        department, selected_rows, search,
                        active_skill_group=active_skill_group,
                    ),
                    "profile_cross_department_skills": _cross_department_profile_skills(
                        department, cross_search,
                    ),
                    "profile_cross_skill_search": cross_search,
                },
            )
        return render_template(
            "profile_available_skills.html",
            **_profile_skill_picker_context(
                department, selected_rows, search,
                active_skill_group=active_skill_group,
            ),
        )

    action = request.form.get("action", "")
    action_skill = _requested_profile_skill()
    if error is None and action == "add_skill":
        available = _available_profile_skills(department)
        allowed = {
            name.casefold()
            for group in (*available, _cross_department_profile_skills(department))
            for name in group
        }
        if action_skill.casefold() not in allowed:
            error = "Choose a skill from the available skill lists."
        elif any(row["name"].casefold() == action_skill.casefold() for row in selected_rows):
            error = f"{action_skill} is already selected."
        elif len(selected_rows) >= 15:
            error = "Choose no more than 15 skills."
        else:
            selected_rows.append({"name": action_skill, "rating": 3})
    elif error is None and action == "add_custom":
        custom_skill = request.form.get("custom_skill", "").strip()
        if not custom_skill or len(custom_skill) > 80:
            error = "Enter a custom skill name of 1 to 80 characters."
        elif "," in custom_skill or ":" in custom_skill:
            error = "Custom skill names cannot include commas or colons."
        elif any(row["name"].casefold() == custom_skill.casefold() for row in selected_rows):
            error = f"{custom_skill} is already selected."
        elif len(selected_rows) >= 15:
            error = "Choose no more than 15 skills."
        else:
            selected_rows.append({"name": custom_skill, "rating": 3})
    elif error is None and action == "remove":
        before = len(selected_rows)
        selected_rows = [
            row for row in selected_rows
            if row["name"].casefold() != action_skill.casefold()
        ]
        if len(selected_rows) == before:
            error = "That selected skill could not be found."
    elif error is None and action == "rate":
        try:
            rating = int(request.form.get("rating", ""))
        except ValueError:
            rating = 0
        match = next(
            (
                row for row in selected_rows
                if row["name"].casefold() == action_skill.casefold()
            ),
            None,
        )
        if match is None:
            error = "That selected skill could not be found."
        elif not 1 <= rating <= 5:
            error = "Choose a rating from 1 to 5."
        else:
            match["rating"] = rating
    elif error is None and action not in {"", "department"}:
        error = "Choose a valid skill action."

    context = _profile_skill_picker_context(
        department, selected_rows, search, error, active_skill_group,
    )
    context.update(
        profile_cross_department_skills=_cross_department_profile_skills(
            department, cross_search,
        ),
        profile_cross_skill_search=cross_search,
    )
    return render_template("profile_skill_picker.html", **context)

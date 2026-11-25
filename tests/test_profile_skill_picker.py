"""Profile skill picker preserves the existing skill-name/rating storage shape."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import data_store
from app import app


class ProfileSkillPickerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="skillmatch-profile-skills-")
        self.storage = patch.object(data_store, "DATA_DIR", Path(self.temp.name))
        self.storage.start()
        self.old_config = {
            key: app.config[key] for key in ("TESTING", "SESSION_COOKIE_SECURE")
        }
        app.config.update(TESTING=True, SESSION_COOKIE_SECURE=False)
        data_store.save("users.json", {
            "student": {
                "name": "Demo Student",
                "role": "Student Volunteer",
                "dept": "CSE",
                "skills": {"Python": 3},
            },
        })
        self.client = app.test_client()
        with self.client.session_transaction() as session:
            session["username"] = "student"
            session["csrf_token"] = "test-csrf"

    def tearDown(self):
        app.config.update(self.old_config)
        self.storage.stop()
        self.temp.cleanup()

    def test_edit_form_renders_grouped_department_and_accessible_skill_picker(self):
        response = self.client.get("/profile/edit")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"School of Engineering and Technology", response.data)
        self.assertIn(b"School of Computer Science &amp; Engineering", response.data)
        self.assertIn(b"Hafeez Contractor School of Architecture", response.data)
        self.assertIn(b"Select your department", response.data)
        self.assertIn(b"General skills", response.data)
        self.assertIn(b"Spoken languages", response.data)
        self.assertIn(b'value="English"', response.data)
        self.assertEqual(response.data.count(b"<h3 id=\"cross-department-skills-title\">"), 1)
        self.assertIn(b"Rating for Python", response.data)
        self.assertIn(b"1 = Beginner", response.data)
        self.assertIn(b'name="skills" value="Python:3"', response.data)
        self.assertNotIn(b'<textarea id="skills"', response.data)
        self.assertIn(b"profile-skills.css", response.data)
        stylesheet = self.client.get("/static/profile-skills.css")
        self.assertEqual(stylesheet.status_code, 200)
        stylesheet.close()
        self.assertIn(b'hx-post="/profile/edit/skills"', response.data)

    def test_legacy_profile_values_are_kept_and_catalog_names_are_canonicalized(self):
        data_store.save("users.json", {
            "student": {
                "name": "Demo Student",
                "role": "Student Volunteer",
                "dept": "BBA",
                "skills": {
                    "  python   ": 0,
                    "One-off volunteer skill": 2,
                },
            },
        })
        response = self.client.get("/profile/edit")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'BBA \xe2\x80\x94 Please re-select your department', response.data)
        self.assertIn(b'name="skills" value="Python:0, One-off volunteer skill:2"', response.data)
        self.assertIn(b"One-off volunteer skill", response.data)
        self.assertIn(b"Custom skill", response.data)
        profile = self.client.get("/profile")
        self.assertEqual(profile.status_code, 200)
        self.assertIn(b"Please re-select your department", profile.data)
        self.assertIn(b"Python \xc2\xb7 rating 0", profile.data)
        self.assertIn(b"One-off volunteer skill", profile.data)

    def test_school_level_department_choice_can_be_saved(self):
        response = self.client.post("/profile/edit", data={
            "csrf_token": "test-csrf",
            "name": "Demo Student",
            "dept": "Hafeez Contractor School of Architecture",
            "skills": "Architectural design:4",
        })
        self.assertEqual(response.status_code, 302)
        saved = data_store.load("users.json")["student"]
        self.assertEqual(saved["dept"], "Hafeez Contractor School of Architecture")
        self.assertEqual(saved["skills"], {"Architectural design": 4})

    def test_signup_renders_department_selector_and_searchable_skill_picker(self):
        signup_client = app.test_client()
        response = signup_client.get("/register")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'<select id="dept" name="dept"', response.data)
        self.assertIn(b"Search departments", response.data)
        self.assertIn(b"Your department", response.data)
        self.assertIn(b"General skills and languages", response.data)
        self.assertEqual(response.data.count(b'id="cross-department-skills-title"'), 1)
        self.assertIn(b"Add custom skill", response.data)
        self.assertIn(b'<select id="department-skill"', response.data)
        self.assertIn(b'<select id="cross-department-skill"', response.data)
        self.assertIn(b"profile-skills.css", response.data)
        self.assertNotIn(b'<textarea id="skills"', response.data)
        self.assertIn(b'hx-post="/register/skills"', response.data)

        with signup_client.session_transaction() as session:
            csrf_token = session["csrf_token"]
        selected_department = signup_client.post("/register/skills", data={
            "csrf_token": csrf_token,
            "role": "Student Volunteer",
            "dept": "Computer Engineering and Technology",
            "skills": "",
            "action": "department",
        })
        self.assertEqual(selected_department.status_code, 200)
        self.assertIn(b'value="Machine learning"', selected_department.data)
        self.assertEqual(selected_department.data.count(b'id="cross-department-skills-title"'), 1)

        added = signup_client.post("/register/skills", data={
            "csrf_token": csrf_token,
            "role": "Student Volunteer",
            "dept": "Computer Engineering and Technology",
            "skills": "",
            "action": "add_skill",
            "skill": "Machine learning",
        })
        self.assertEqual(added.status_code, 200)
        self.assertIn(b'name="skills" value="Machine learning:3"', added.data)
        self.assertIn(b'hx-post="/register/skills"', added.data)

        cross_search = signup_client.get("/register/skills", query_string={
            "dept": "Computer Engineering and Technology",
            "skills": "Machine learning:3",
            "cross_skill_search": "digital marketing",
        })
        self.assertEqual(cross_search.status_code, 200)
        self.assertIn(b"Digital marketing", cross_search.data)
        self.assertNotIn(b"Machine learning", cross_search.data)
        self.assertNotIn(b"Communication", cross_search.data)

        cross_added = signup_client.post("/register/skills", data={
            "csrf_token": csrf_token,
            "role": "Student Volunteer",
            "dept": "Computer Engineering and Technology",
            "skills": "Machine learning:3",
            "action": "add_skill",
            "skill": "Digital marketing",
        })
        self.assertIn(
            b'name="skills" value="Machine learning:3, Digital marketing:3"',
            cross_added.data,
        )

    def test_signup_saves_department_and_selected_skills(self):
        signup_client = app.test_client()
        signup_client.get("/register")
        with signup_client.session_transaction() as session:
            csrf_token = session["csrf_token"]

        with patch("auth_routes.delivery_ready", return_value=False):
            response = signup_client.post("/register", data={
                "csrf_token": csrf_token,
                "username": "new-volunteer",
                "email": "new-volunteer@mitwpu.edu.in",
                "name": "New Volunteer",
                "password": "safe-pass1",
                "confirm_password": "safe-pass1",
                "role": "Student Volunteer",
                "dept": "Computer Engineering and Technology",
                "skills": "Machine learning:4, Teamwork:3",
            })
        self.assertEqual(response.status_code, 302)
        account = data_store.load("users.json")["new-volunteer"]
        self.assertEqual(account["dept"], "Computer Engineering and Technology")
        self.assertEqual(account["skills"], {"Machine learning": 4, "Teamwork": 3})

    def test_department_change_keeps_selected_skills_and_search_filters_skills(self):
        response = self.client.post("/profile/edit/skills", data={
            "csrf_token": "test-csrf",
            "name": "Demo Student",
            "dept": "Computer Engineering and Technology",
            "skills": "Python:4, Event planning:3",
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'name="skills" value="Python:4, Event planning:3"', response.data)
        self.assertIn(b'value="Machine learning"', response.data)

        filtered = self.client.get("/profile/edit/skills", query_string={
            "dept": "Computer Engineering and Technology",
            "skills": "Python:4, Event planning:3",
            "skill_search": "Teamwork",
        })
        self.assertEqual(filtered.status_code, 200)
        self.assertIn(b"Teamwork", filtered.data)
        self.assertNotIn(b"Public speaking", filtered.data)

        cross_filtered = self.client.get("/profile/edit/skills", query_string={
            "dept": "Computer Engineering and Technology",
            "skills": "Python:4",
            "cross_skill_search": "financial",
        })
        self.assertEqual(cross_filtered.status_code, 200)
        self.assertIn(b"Financial analysis", cross_filtered.data)
        self.assertNotIn(b"Machine learning", cross_filtered.data)
        self.assertNotIn(b"Teamwork", cross_filtered.data)

        cross_added = self.client.post("/profile/edit/skills", data={
            "csrf_token": "test-csrf",
            "name": "Demo Student",
            "dept": "Computer Engineering and Technology",
            "skills": "Python:4",
            "action": "add_skill",
            "skill": "Financial analysis",
        })
        self.assertIn(
            b'name="skills" value="Python:4, Financial analysis:3"',
            cross_added.data,
        )

    def test_custom_skill_addition_defaults_to_three_and_keeps_existing_selection(self):
        response = self.client.post("/profile/edit/skills", data={
            "csrf_token": "test-csrf",
            "name": "Demo Student",
            "dept": "CSE",
            "skills": "Python:4",
            "action": "add_custom",
            "custom_skill": "Event planning",
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'name="skills" value="Python:4, Event planning:3"', response.data)
        self.assertIn(b"Event planning", response.data)

    def test_search_targets_stay_separate_when_both_search_fields_are_submitted(self):
        """Mirror hx-include of the whole form, not artificially isolated fields."""
        signup = app.test_client()
        for client, route in (
            (self.client, "/profile/edit/skills"),
            (signup, "/register/skills"),
        ):
            with self.subTest(route=route):
                params = {
                    "dept": "Computer Engineering and Technology",
                    "skills": "Python:4",
                    "skill_search": "Machine",
                    "cross_skill_search": "",
                    "skill_group": "department",
                }
                response = client.get(route, query_string=params, headers={
                    "HX-Request": "true", "HX-Target": "available-skill-options",
                })
                self.assertEqual(response.status_code, 200)
                self.assertIn(b'<select id="department-skill"', response.data)
                self.assertIn(b'value="Machine learning"', response.data)
                self.assertNotIn(b'<select id="cross-department-skill"', response.data)
                params.update(cross_skill_search="financial", skill_group="cross")
                response = client.get(route, query_string=params, headers={
                    "HX-Request": "true", "HX-Target": "cross-department-skill-options",
                })
                self.assertIn(b'value="Financial analysis"', response.data)
                self.assertNotIn(b'<select id="department-skill"', response.data)
                self.assertNotIn(b"value=\"Machine learning\"", response.data)

    def test_searching_departments_keeps_the_skill_update_wired(self):
        response = self.client.get("/profile/edit/departments", query_string={
            "department_search": "Computer", "dept": "Computer Engineering and Technology",
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'hx-post="/profile/edit/skills"', response.data)
        self.assertIn(b'hx-include="#profile-edit-form"', response.data)

    def test_each_dropdown_adds_only_its_chosen_skill_on_both_forms(self):
        signup = app.test_client()
        signup.get("/register")
        with signup.session_transaction() as session:
            signup_token = session["csrf_token"]
        for client, route, token in (
            (self.client, "/profile/edit/skills", "test-csrf"),
            (signup, "/register/skills", signup_token),
        ):
            for group, skill in (
                ("department", "Machine learning"),
                ("general", "English"),
                ("cross", "Financial analysis"),
            ):
                with self.subTest(route=route, group=group):
                    response = client.post(route, data={
                        "csrf_token": token,
                        "dept": "Computer Engineering and Technology",
                        "skills": "Python:4",
                        "action": "add_skill",
                        "skill_group": group,
                        "department_skill": "Machine learning",
                        "general_skill": "English",
                        "cross_skill": "Financial analysis",
                        "skill_search": "",
                        "cross_skill_search": "",
                    })
                    self.assertEqual(response.status_code, 200)
                    self.assertIn(
                        f'name="skills" value="Python:4, {skill}:3"'.encode(),
                        response.data,
                    )
                    self.assertEqual(response.data.count(b'id="department-skill"'), 1)
                    self.assertEqual(response.data.count(b'id="cross-department-skill"'), 1)
                    self.assertEqual(response.data.count(b'id="custom-skill"'), 1)

    def test_add_rating_remove_and_save_use_existing_dict_shape(self):
        added = self.client.post("/profile/edit/skills", data={
            "csrf_token": "test-csrf",
            "name": "Demo Student",
            "dept": "Computer Engineering and Technology",
            "skills": "Python:3",
            "action": "add_skill",
            "skill": "Machine learning",
        })
        self.assertIn(b'name="skills" value="Python:3, Machine learning:3"', added.data)

        rated = self.client.post("/profile/edit/skills", data={
            "csrf_token": "test-csrf",
            "name": "Demo Student",
            "dept": "Computer Engineering and Technology",
            "skills": "Python:3, Machine learning:3",
            "action": "rate",
            "skill": "Machine learning",
            "rating": "5",
        })
        self.assertIn(b'name="skills" value="Python:3, Machine learning:5"', rated.data)

        removed = self.client.post("/profile/edit/skills", data={
            "csrf_token": "test-csrf",
            "name": "Demo Student",
            "dept": "Computer Engineering and Technology",
            "skills": "Python:3, Machine learning:5",
            "action": "remove",
            "skill": "Python",
        })
        self.assertIn(b'name="skills" value="Machine learning:5"', removed.data)

        saved = self.client.post("/profile/edit", data={
            "csrf_token": "test-csrf",
            "name": "Demo Student",
            "dept": "Computer Engineering and Technology",
            "skills": "Machine learning:5, Teamwork:2",
        })
        self.assertEqual(saved.status_code, 302)
        self.assertEqual(
            data_store.load("users.json")["student"]["skills"],
            {"Machine learning": 5, "Teamwork": 2},
        )

    def test_server_rejects_missing_duplicate_out_of_range_and_over_limit(self):
        original = data_store.load("users.json")["student"].copy()
        cases = (
            ("CSE", "", "Add at least one skill"),
            ("CSE", "Python:0", "rating from 1 to 5"),
            ("CSE", "Python:6", "rating from 1 to 5"),
            ("CSE", "Python:3, python:4", "duplicate skill"),
            ("", "Python:3", "Enter your department"),
            ("CSE", ", ".join(f"Skill {n}:3" for n in range(1, 17)), "no more than 15"),
        )
        for department, skills, message in cases:
            with self.subTest(department=department, skills=skills[:20]):
                response = self.client.post("/profile/edit", data={
                    "csrf_token": "test-csrf",
                    "name": "Demo Student",
                    "dept": department,
                    "skills": skills,
                })
                self.assertEqual(response.status_code, 400)
                self.assertIn(message.encode(), response.data)
                self.assertEqual(data_store.load("users.json")["student"], original)

    def test_htmx_validation_errors_render_inline_without_a_full_page_swap(self):
        response = self.client.post(
            "/profile/edit",
            headers={"HX-Request": "true"},
            data={
                "csrf_token": "test-csrf",
                "name": "Demo Student",
                "dept": "CSE",
                "skills": "",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Skills: Add at least one skill", response.data)
        self.assertNotIn(b"<!doctype html>", response.data.lower())

    def test_department_search_keeps_the_legacy_current_department_option(self):
        response = self.client.get("/profile/edit/departments", query_string={
            "dept": "CSE",
            "department_search": "Photography",
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Current department", response.data)
        self.assertIn(b'value="CSE" selected', response.data)
        self.assertIn(b"Photography", response.data)

    def test_skills_data_is_valid_json_and_editable_separately(self):
        data_path = Path(__file__).resolve().parents[1] / "static" / "data" / "profile-skills.json"
        data = json.loads(data_path.read_text(encoding="utf-8"))
        self.assertGreater(len(data["schools"]), 1)
        self.assertIn("Communication", data["general_skills"])


if __name__ == "__main__":
    unittest.main()

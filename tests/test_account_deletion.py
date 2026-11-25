"""Account deletion confirms the user and preserves historical records."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import auth_service
import data_store
from app import app
from werkzeug.security import generate_password_hash


class AccountDeletionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="skillmatch-account-delete-")
        self.storage = patch.object(data_store, "DATA_DIR", Path(self.temp.name))
        self.storage.start()
        self.old_config = {
            key: app.config[key] for key in ("TESTING", "SESSION_COOKIE_SECURE")
        }
        app.config.update(TESTING=True, SESSION_COOKIE_SECURE=False)
        self.client = app.test_client()
        data_store.save("users.json", {
            "volunteer": {
                "name": "Demo Volunteer",
                "role": "Student Volunteer",
                "dept": "Engineering",
                "skills": {"Planning": 3},
                "email": "volunteer@mitwpu.edu.in",
                "email_verified": True,
                "password_hash": generate_password_hash("Current123!"),
                "session_version": 2,
            },
            "organizer": {
                "name": "Demo Organizer",
                "role": "Organizer",
                "skills": {},
                "password_hash": generate_password_hash("Current123!"),
                "session_version": 4,
            },
        })
        data_store.save("events.json", {
            "e1": {
                "name": "Campus Workshop",
                "organizer": "organizer",
                "organizer_name": "Demo Organizer",
                "status": "completed",
            },
            "e2": {
                "name": "Another event",
                "organizer": "other-organizer",
                "status": "open",
            },
        })
        data_store.save("applications.json", {
            "e1": {"volunteer": {"status": "accepted", "hours": 4}},
        })
        data_store.save("certificates.json", {
            "certificate-code": {
                "username": "volunteer",
                "volunteer_name": "Demo Volunteer",
                "event_id": "e1",
            },
        })
        data_store.save("notifications.json", {
            username: [{
                "id": f"{username}-notice",
                "kind": "event_posted",
                "title": "Event posted",
                "message": "A sample event notice.",
                "event_id": "e1",
                "created_at": "2030-01-01T00:00:00+00:00",
                "is_read": False,
            }]
            for username in ("volunteer", "organizer", "other-user")
        })

    def tearDown(self):
        app.config.update(self.old_config)
        self.storage.stop()
        self.temp.cleanup()

    def sign_in(self, username, client=None):
        client = client or self.client
        with client.session_transaction() as session:
            session["username"] = username
            session["session_version"] = data_store.load("users.json")[username]["session_version"]
            session["csrf_token"] = "test-csrf"

    @staticmethod
    def deletion_form(**overrides):
        form = {
            "current_password": "Current123!",
            "confirm_delete": "yes",
            "csrf_token": "test-csrf",
        }
        form.update(overrides)
        return form

    def test_volunteer_deletion_scrubs_profile_but_keeps_history(self):
        self.sign_in("volunteer")
        self.assertEqual(self.client.get("/account/delete").status_code, 200)

        wrong_password = self.client.post(
            "/account/delete", data=self.deletion_form(current_password="Wrong123!")
        )
        self.assertEqual(wrong_password.status_code, 400)
        self.assertEqual(data_store.load("users.json")["volunteer"]["name"], "Demo Volunteer")

        response = self.client.post("/account/delete", data=self.deletion_form())
        self.assertEqual(response.status_code, 303)
        tombstone = data_store.load("users.json")["volunteer"]
        self.assertEqual(tombstone["deleted_role"], "Student Volunteer")
        self.assertIn("account_deleted_at", tombstone)
        self.assertNotIn("password_hash", tombstone)
        self.assertNotIn("email", tombstone)
        self.assertNotIn("name", tombstone)
        self.assertNotIn("skills", tombstone)
        self.assertIn("volunteer", data_store.load("applications.json")["e1"])
        self.assertIn("certificate-code", data_store.load("certificates.json"))
        self.assertNotIn("volunteer", data_store.load("notifications.json"))
        self.assertIn("other-user", data_store.load("notifications.json"))

    def test_organizer_deletion_hides_owned_events_and_keeps_applicant_history(self):
        self.sign_in("organizer")
        response = self.client.post("/account/delete", data=self.deletion_form())

        self.assertEqual(response.status_code, 303)
        events = data_store.load("events.json")
        self.assertTrue(events["e1"]["deleted_at"])
        self.assertNotIn("deleted_at", events["e2"])
        self.assertIn("volunteer", data_store.load("applications.json")["e1"])
        self.assertIn("certificate-code", data_store.load("certificates.json"))
        self.assertNotIn("organizer", data_store.load("notifications.json"))

    def test_csrf_and_explicit_confirmation_are_required(self):
        self.sign_in("volunteer")
        missing_confirmation = self.client.post(
            "/account/delete",
            data=self.deletion_form(confirm_delete=""),
        )
        self.assertEqual(missing_confirmation.status_code, 400)
        missing_csrf = self.client.post(
            "/account/delete",
            data=self.deletion_form(csrf_token=""),
        )
        self.assertEqual(missing_csrf.status_code, 400)
        self.assertNotIn(
            "account_deleted_at", data_store.load("users.json")["volunteer"]
        )

    def test_deletion_invalidates_existing_sessions_and_credentials(self):
        self.sign_in("volunteer")
        another_session = app.test_client()
        self.sign_in("volunteer", another_session)
        self.client.post("/account/delete", data=self.deletion_form())

        self.assertEqual(another_session.get("/profile").status_code, 302)
        self.assertIsNone(auth_service.login_user("volunteer", "Current123!"))

    def test_logged_out_users_cannot_open_account_deletion(self):
        client = app.test_client()
        response = client.get("/account/delete")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])


if __name__ == "__main__":
    unittest.main()

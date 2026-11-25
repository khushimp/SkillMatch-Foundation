"""Email/recovery tests use synthetic accounts, temporary storage and fake mail."""

import io
import json
import logging
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError

import account_service as accounts
import auth_service
import data_store
import email_delivery
from account_routes import _RedactAccountTokens
from app import app
from event_service import toggle_saved_event


class AccountEmailTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="skillmatch-email-test-")
        self.storage = patch.object(data_store, "DATA_DIR", Path(self.temp.name))
        self.storage.start()
        self.config = dict(app.config)
        app.config.update(
            TESTING=True, SESSION_COOKIE_SECURE=False,
            ACCOUNT_EMAIL_ENABLED=True,
            ACCOUNT_EMAIL_FROM="SkillMatch <accounts@skillmatch.example>",
            ACCOUNT_BASE_URL="https://skillmatch.example",
        )
        self.mail = patch("account_service.send_account_email")
        self.sender = self.mail.start()
        self.client = app.test_client()
        auth_service.register_user("volunteer", "Example123!", "Student Volunteer",
                                   "Demo Volunteer", "Engineering", {"Planning": 4})
        auth_service.register_user("other", "Example123!", "Organizer", "Demo Organizer")

    def tearDown(self):
        app.config.clear()
        app.config.update(self.config)
        self.mail.stop()
        self.storage.stop()
        self.temp.cleanup()

    def csrf(self, client=None):
        client = client or self.client
        client.get("/login", follow_redirects=True)
        with client.session_transaction() as session:
            return session["csrf_token"]

    def sign_in(self, username="volunteer", password="Example123!", client=None):
        client = client or self.client
        return client.post("/login", data={
            "username": username, "password": password, "csrf_token": self.csrf(client),
        })

    def last_token(self):
        return self.sender.call_args.args[2]

    def verify_own(self):
        accounts.start_email_link("volunteer", "private@example.com", "Example123!")
        token = self.last_token()
        self.assertTrue(accounts.consume_token(token, "verify"))
        return token

    def signup(self, **overrides):
        data = {
            "username": "new-student", "name": "New Student",
            "email": "NEW.Student@MITWPU.edu.in", "password": "Example123!",
            "confirm_password": "Example123!",
            "role": "Student Volunteer", "dept": "Engineering",
            "skills": "Planning:4", "csrf_token": self.csrf(),
        }
        data.update(overrides)
        return self.client.post("/register", data=data)

    def test_signup_requires_unique_normalized_email_for_both_roles(self):
        with app.app_context():
            self.assertEqual(self.signup().status_code, 302)
            users = data_store.load("users.json")
            self.assertEqual(users["new-student"]["email"], "new.student@mitwpu.edu.in")
            self.assertFalse(users["new-student"]["email_verified"])
            self.assertNotIn("password", users["new-student"])
            self.assertNotEqual(users["new-student"]["password_hash"], "Example123!")
            self.assertEqual(self.signup(
                username="new-organizer", role="Organizer", email="ORGANIZER@mitwpu.edu.in",
            ).status_code, 302)
            duplicate = self.signup(username="duplicate", email="new.student@MITWPU.EDU.IN")
            self.assertIn(b"This email cannot be used", duplicate.data)
            self.assertNotIn("duplicate", data_store.load("users.json"))
            missing = self.signup(username="missing", email="")
            self.assertIn(b"Enter a valid email", missing.data)

    def test_disabled_delivery_keeps_new_and_existing_logins_working(self):
        app.config["ACCOUNT_EMAIL_ENABLED"] = False
        response = self.signup()
        self.assertEqual(response.headers["Location"], "/profile")
        account = data_store.load("users.json")["new-student"]
        self.assertFalse(account["email_verified"])
        self.assertFalse(account["verification_required"])
        self.assertNotIn("email_verification", account)
        self.sender.assert_not_called()
        profile = self.client.get("/profile")
        self.assertEqual(profile.status_code, 200)
        self.assertNotIn(b"email delivery", profile.data.lower())
        self.assertEqual(
            data_store.load("users.json")["new-student"]["email"],
            "new.student@mitwpu.edu.in",
        )
        self.assertEqual(self.sign_in("new-student").status_code, 302)
        self.assertEqual(self.sign_in().status_code, 302)
        self.assertEqual(self.client.get("/profile").status_code, 200)
        request = self.client.post("/forgot-password", data={
            "email": "new.student@mitwpu.edu.in", "csrf_token": self.csrf(),
        })
        self.assertEqual(request.status_code, 302)
        self.assertEqual(request.headers["Location"], "/login")
        self.sender.assert_not_called()

    def test_disabled_delivery_saves_existing_email_without_verifying(self):
        app.config["ACCOUNT_EMAIL_ENABLED"] = False
        self.sign_in()
        response = self.client.post("/account/email", data={
            "email": "Saved@MITWPU.edu.in", "current_password": "Example123!",
            "csrf_token": self.csrf(),
        }, follow_redirects=True)
        self.assertIn(b"Email address saved to your account", response.data)
        user = data_store.load("users.json")["volunteer"]
        self.assertEqual(user["email"], "saved@mitwpu.edu.in")
        self.assertNotIn("email_verification", user)
        self.assertFalse(user.get("email_verified", False))
        self.assertEqual(self.client.get("/profile").status_code, 200)
        self.sender.assert_not_called()
        page = self.client.get("/account/email")
        self.assertNotIn(b"email delivery is not enabled yet", page.data.lower())
        self.assertIn(b'value="saved@mitwpu.edu.in"', page.data)

    def test_signup_requires_matching_password_confirmation_and_mitwpu_email(self):
        mismatch = self.signup(confirm_password="Different123!")
        self.assertIn(b"The passwords do not match", mismatch.data)
        self.assertNotIn("new-student", data_store.load("users.json"))

        outside_domain = self.signup(email="student@gmail.com")
        self.assertIn(b"Please use your MIT-WPU email.", outside_domain.data)
        self.assertNotIn("new-student", data_store.load("users.json"))

    def test_existing_account_email_changes_reject_non_mitwpu_domain(self):
        self.sign_in()
        response = self.client.post("/account/email", data={
            "email": "personal@gmail.com", "current_password": "Example123!",
            "csrf_token": self.csrf(),
        }, follow_redirects=True)
        self.assertIn(b"Please use your MIT-WPU email.", response.data)
        self.assertNotIn("email", data_store.load("users.json")["volunteer"])

    def test_new_accounts_verify_before_login_when_sending_enabled(self):
        with app.app_context():
            response = self.signup()
            self.assertEqual(response.headers["Location"], "/account/check-email")
            self.assertIn(b"Verify your email before signing", self.sign_in("new-student").data)
            token = self.last_token()
            self.assertEqual(self.client.get(
                "/account/verify-email?token=" + token,
            ).status_code, 200)
            self.assertTrue(accounts.token_valid(token, "verify"))
            confirmed = self.client.post("/account/verify-email", data={
                "token": token, "csrf_token": self.csrf(),
            })
            self.assertEqual(confirmed.status_code, 302)
            self.assertFalse(accounts.token_valid(token, "verify"))
            self.assertEqual(self.sign_in("NEW.STUDENT@MITWPU.EDU.IN").status_code, 302)
            with self.client.session_transaction() as session:
                self.assertEqual(session["username"], "new-student")
            self.assertEqual(self.client.get("/profile").status_code, 200)

    def test_verification_and_reset_tokens_are_hashed_purpose_bound_and_expire(self):
        with app.app_context():
            accounts.start_email_link("volunteer", "private@example.com", "Example123!")
            token = self.last_token()
            user = data_store.load("users.json")["volunteer"]
            self.assertNotIn(token, json.dumps(user))
            self.assertAlmostEqual(user["email_verification"]["expires_at"] - time.time(),
                                   86400, delta=5)
            self.assertFalse(accounts.token_valid(token, "reset"))
            with data_store.edit_documents("users.json") as docs:
                docs["users.json"]["volunteer"]["email_verification"]["expires_at"] = 1
            self.assertFalse(accounts.consume_token(token, "verify"))
            accounts.request_account_email("private@example.com", "verify", "test-ip")
            self.assertNotEqual(token, self.last_token())
            self.assertTrue(accounts.consume_token(self.last_token(), "verify"))
            accounts.request_account_email("private@example.com", "reset", "test-ip")
            reset = self.last_token()
            user = data_store.load("users.json")["volunteer"]
            self.assertNotIn(reset, json.dumps(user))
            self.assertAlmostEqual(user["password_reset"]["expires_at"] - time.time(),
                                   3600, delta=5)
            self.assertFalse(accounts.consume_token(reset, "verify"))
            with data_store.edit_documents("users.json") as docs:
                docs["users.json"]["volunteer"]["password_reset"]["expires_at"] = 1
            self.assertFalse(accounts.consume_token(reset, "reset", "Changed123!"))

    def test_reset_consumes_once_preserves_records_and_revokes_old_sessions(self):
        with app.app_context():
            self.verify_own()
            self.sign_in()
            other_session = app.test_client()
            self.sign_in(client=other_session)
            with data_store.edit_documents("users.json") as docs:
                docs["users.json"]["volunteer"]["saved_events"] = ["e1"]
            data_store.save("applications.json", {"e1": {"volunteer": {"status": "accepted"}}})
            data_store.save("certificates.json", {"stable-code": {"student_id": "volunteer"}})
            before = {name: data_store.load(name) for name in (
                "applications.json", "certificates.json",
            )}
            accounts.request_account_email("private@example.com", "reset", "test-ip")
            token = self.last_token()
            self.assertIn(b"Choose a new password", self.client.get(
                "/reset-password?token=" + token,
            ).data)
            self.assertTrue(accounts.token_valid(token, "reset"))
            response = self.client.post("/reset-password", data={
                "token": token, "new_password": "Changed123!",
                "confirm_password": "Changed123!", "csrf_token": self.csrf(),
            })
            self.assertEqual(response.status_code, 302)
            self.assertEqual(other_session.get("/profile").status_code, 302)
            self.assertIsNone(auth_service.login_user("volunteer", "Example123!"))
            self.assertIsNotNone(auth_service.login_user("volunteer", "Changed123!"))
            self.assertFalse(accounts.consume_token(token, "reset", "Another123!"))
            user = data_store.load("users.json")["volunteer"]
            self.assertEqual(user["skills"], {"Planning": 4})
            self.assertEqual(user["saved_events"], ["e1"])
            for name, original in before.items():
                self.assertEqual(data_store.load(name), original)

    def test_reset_rejects_weak_mismatched_and_forged_password_posts(self):
        with app.app_context():
            self.verify_own()
            accounts.request_account_email("private@example.com", "reset", "test-ip")
            token = self.last_token()
            for password, confirm in (("short", "short"), ("Changed123!", "Mismatch123!")):
                response = self.client.post("/reset-password", data={
                    "token": token, "new_password": password, "confirm_password": confirm,
                    "csrf_token": self.csrf(),
                })
                self.assertEqual(response.status_code, 400)
                self.assertTrue(accounts.token_valid(token, "reset"))
            self.assertEqual(self.client.post("/reset-password", data={
                "token": token, "new_password": "Changed123!", "confirm_password": "Changed123!",
            }).status_code, 400)
            self.assertTrue(accounts.token_valid(token, "reset"))
            self.assertFalse(accounts.consume_token("forged", "reset", "Changed123!"))

    def test_private_settings_ignore_other_username_and_require_current_password(self):
        with app.app_context():
            self.verify_own()
            self.assertEqual(self.client.get("/account/email").status_code, 302)
            self.sign_in("other")
            page = self.client.get("/account/email?username=volunteer")
            self.assertNotIn(b"private@example.com", page.data)
            rejected = self.client.post("/account/email?username=volunteer", data={
                "email": "intruder@mitwpu.edu.in", "current_password": "incorrect",
                "csrf_token": self.csrf(),
            }, follow_redirects=True)
            self.assertIn(b"current password is incorrect", rejected.data)
            self.assertIsNone(data_store.load("users.json")["other"].get("pending_email"))
            self.assertEqual(data_store.load("users.json")["volunteer"]["email"], "private@example.com")
            csrf_rejected = self.client.post("/account/email", data={
                "email": "other@mitwpu.edu.in", "current_password": "Example123!",
            })
            self.assertEqual(csrf_rejected.status_code, 400)

    def test_email_replacement_keeps_verified_address_until_confirmation(self):
        with app.app_context():
            self.verify_own()
            accounts.request_account_email("private@example.com", "reset", "test-ip")
            old_reset = self.last_token()
            accounts.start_email_link("volunteer", "replacement@example.com", "Example123!")
            verify = self.last_token()
            self.assertEqual(accounts.private_email_status("volunteer")["email"], "private@example.com")
            self.assertIsNotNone(auth_service.login_user("private@example.com", "Example123!"))
            self.assertIsNone(auth_service.login_user("replacement@example.com", "Example123!"))
            self.assertFalse(accounts.token_valid(old_reset, "reset"))
            self.assertTrue(accounts.consume_token(verify, "verify"))
            self.assertIsNone(auth_service.login_user("private@example.com", "Example123!"))
            self.assertIsNotNone(auth_service.login_user("replacement@example.com", "Example123!"))
            self.assertFalse(accounts.consume_token(verify, "verify"))

    def test_forgot_response_identical_for_unknown_unverified_and_verified_email(self):
        with app.app_context():
            self.verify_own()
            pages = []
            for email in ("unknown@example.com", "private@example.com", "other@example.com"):
                pages.append(self.client.post("/forgot-password", data={
                    "email": email, "csrf_token": self.csrf(),
                }).data)
            self.assertEqual(pages[0], pages[1])
            self.assertEqual(pages[0], pages[2])
            self.assertNotIn(b"private@example.com", pages[0])
            reset_calls = [c for c in self.sender.call_args_list if c.args[1] == "reset"]
            self.assertEqual(len(reset_calls), 1)

    def test_resend_limits_persist_and_superseded_tokens_cannot_be_used(self):
        with app.app_context():
            accounts.start_email_link("volunteer", "private@example.com", "Example123!")
            old_token = self.last_token()
            self.sender.reset_mock()
            for _ in range(8):
                self.client.post("/resend-verification", data={
                    "email": "private@example.com", "csrf_token": self.csrf(),
                })
            self.assertEqual(self.sender.call_count, 3)
            self.assertFalse(accounts.token_valid(old_token, "verify"))
            limits = json.dumps(data_store.load("account_limits.json"))
            self.assertNotIn("private@example.com", limits)
            self.assertNotIn("127.0.0.1", limits)

    def test_failed_password_attempts_count_toward_link_limit(self):
        with app.app_context():
            for _ in range(5):
                with self.assertRaisesRegex(ValueError, "current password"):
                    accounts.start_email_link("volunteer", "private@example.com", "bad")
            with self.assertRaisesRegex(ValueError, "Too many"):
                accounts.start_email_link("volunteer", "private@example.com", "Example123!")
            self.sender.assert_not_called()

    def test_email_validation_and_email_shaped_username_cannot_steal_login(self):
        for bad in ("", "two@@example.com", "name\n@example.com", "a..b@example.com",
                    ".abc@example.com", "abc@-example.com", "a@localhost"):
            with self.assertRaises(ValueError):
                accounts.normalize_email(bad)
        with app.app_context():
            self.verify_own()
            success, _ = auth_service.register_user(
                "private@example.com", "Example123!", "Organizer", "Another",
            )
            self.assertFalse(success)
            with self.assertRaisesRegex(ValueError, "cannot be used"):
                accounts.start_email_link("other", "PRIVATE@example.com", "Example123!")
            auth_service.register_user("legacy@example.com", "Example123!", "Organizer", "Legacy")
            with self.assertRaisesRegex(ValueError, "cannot be used"):
                accounts.start_email_link("other", "legacy@example.com", "Example123!")

    def test_mail_failure_does_not_verify_email_or_leave_usable_token(self):
        with app.app_context():
            self.sender.side_effect = email_delivery.EmailDeliveryError("Unavailable")
            self.assertFalse(accounts.start_email_link(
                "volunteer", "private@example.com", "Example123!",
            ))
            user = data_store.load("users.json")["volunteer"]
            self.assertEqual(user["pending_email"], "private@example.com")
            self.assertNotIn("email_verification", user)
            self.assertFalse(user.get("email_verified"))
            self.assertIsNotNone(auth_service.login_user("volunteer", "Example123!"))

    def test_password_change_revokes_reset_links_and_other_sessions(self):
        with app.app_context():
            self.verify_own()
            self.sign_in()
            accounts.request_account_email("private@example.com", "reset", "test-ip")
            token = self.last_token()
            response = self.client.post("/account/password", data={
                "current_password": "Example123!", "new_password": "Changed123!",
                "confirm_password": "Changed123!", "csrf_token": self.csrf(),
            })
            self.assertEqual(response.status_code, 302)
            self.assertFalse(accounts.token_valid(token, "reset"))
            self.assertEqual(self.client.get("/profile").status_code, 200)

    def test_bookmark_and_profile_edits_preserve_email_security_fields(self):
        with app.app_context():
            self.verify_own()
            accounts.request_account_email("private@example.com", "reset", "test-ip")
            token = self.last_token()
            data_store.save("events.json", {"e1": {"name": "Demo"}})
            self.assertTrue(toggle_saved_event("volunteer", "e1"))
            self.sign_in()
            self.client.post("/profile/edit", data={
                "name": "Updated Demo", "dept": "Engineering", "skills": "Planning:5",
                "csrf_token": self.csrf(),
            })
            user = data_store.load("users.json")["volunteer"]
            self.assertEqual(user["email"], "private@example.com")
            self.assertTrue(user["email_verified"])
            self.assertTrue(accounts.token_valid(token, "reset"))

    def test_private_pages_do_not_cache_or_leak_tokens_in_access_logs(self):
        for path in ("/login", "/register", "/forgot-password",
                     "/reset-password?token=invalid", "/account/verify-email?token=invalid"):
            response = self.client.get(path)
            self.assertEqual(response.headers["Cache-Control"], "no-store, private")
            self.assertEqual(response.headers["Referrer-Policy"], "no-referrer")
            self.assertIn("noindex", response.headers["X-Robots-Tag"])
        record = logging.LogRecord(
            "werkzeug", logging.INFO, "", 1,
            "GET /reset-password?token=%s HTTP/1.1", ("secret-token",), None,
        )
        _RedactAccountTokens().filter(record)
        self.assertNotIn("secret-token", record.getMessage())
        self.assertIn("[redacted]", record.getMessage())

    def test_concurrent_token_consumption_has_only_one_winner(self):
        with app.app_context():
            self.verify_own()
            accounts.request_account_email("private@example.com", "reset", "test-ip")
            token = self.last_token()
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(
                lambda _: accounts.consume_token(token, "reset", "Changed123!"), range(2),
            ))
        self.assertEqual(sorted(results), [False, True])

    def test_transaction_rolls_back_when_callback_fails(self):
        before = data_store.load("users.json")
        with self.assertRaises(RuntimeError):
            with data_store.edit_documents("users.json") as docs:
                docs["users.json"].clear()
                raise RuntimeError("Test rollback")
        self.assertEqual(data_store.load("users.json"), before)

    def test_resend_adapter_sends_one_recipient_without_passwords_or_copies(self):
        with app.app_context(), patch(
            "email_delivery._identity_headers", return_value={"X-Replit-Token": "fake"}
        ), patch("email_delivery.urlopen", return_value=io.BytesIO(b'{"id":"fake-message"}')) as opened:
            email_delivery.send_account_email("demo@example.com", "reset", "synthetic-token")
            request = opened.call_args.args[0]
            payload = json.loads(request.data)
            self.assertEqual(payload["to"], ["demo@example.com"])
            self.assertNotIn("bcc", payload)
            self.assertNotIn("cc", payload)
            self.assertNotIn("Example123!", payload["text"])
            self.assertIn("https://skillmatch.example/reset-password?token=synthetic-token", payload["text"])
            self.assertIn("1 hour", payload["text"])
            self.assertNotIn("replit", payload["text"].lower())
            self.assertEqual(request.get_header("User-agent"), "SkillMatch/1.0")

    def test_sender_disabled_and_provider_failures_are_explicit_and_safe(self):
        with app.app_context():
            app.config["ACCOUNT_EMAIL_ENABLED"] = False
            self.assertFalse(email_delivery.delivery_ready())
            with self.assertRaises(email_delivery.EmailDeliveryError):
                email_delivery.send_account_email("demo@example.com", "verify", "test")
            app.config["ACCOUNT_EMAIL_ENABLED"] = True
            app.config["ACCOUNT_BASE_URL"] = "https://attacker.example/path"
            self.assertFalse(email_delivery.delivery_ready())
        with patch("email_delivery._identity_headers", return_value={}), patch(
            "email_delivery.urlopen",
            side_effect=HTTPError("https://example.com", 403, "private-provider-details", {}, None),
        ):
            with self.assertRaises(email_delivery.EmailDeliveryError) as caught:
                email_delivery.connector_request("/emails", {})
            self.assertNotIn("private-provider-details", str(caught.exception))

# SkillMatch JSON data shapes

Named JSON documents are persisted in PostgreSQL through `data_store.py`.
Only isolated tests use a temporary file directory. Each top-level JSON object
is keyed by the record identifier.

## Private account email fields

`users.json` retains its existing username keys, password hashes, roles and
profile fields. Optional account-security fields are:

- `email`: normalized lowercase account email, distinct from imported roster email.
- `email_verified`: false until the owner confirms the emailed link.
- `pending_email`: a proposed replacement; does not replace a verified address yet.
- `verification_required`: enabled for new public registrations when delivery is
  configured. Absent/false for legacy accounts and registrations while sending is off.
- `email_verification` / `password_reset`: objects containing only `hash`, `email`
  and `expires_at` (UTC epoch seconds); no raw token is persisted. Removed on
  consumption or invalidation. Verification lasts 24 hours; recovery one hour.
- `session_version`: integer incremented by password reset/change. Sessions with
  older versions are rejected; missing versions default to zero for compatibility.

`account_limits.json` stores SHA-256-keyed request buckets with `count` and `until`
(UTC epoch seconds). It does not store plaintext emails or IP addresses.
Security writes lock the relevant documents atomically across server workers.

The general template account view deliberately excludes email, password hashes,
tokens and security metadata. Only own-account email settings receive email fields.
The examples below show the complete record shapes used by the shared foundation.

## `users.json`

The key is the user's username. `role` is either `Organizer` or
`Student Volunteer`. `dept` is `null` for organizers and a department name for
student volunteers. Skill ratings are non-negative integers; the foundation does
not impose an upper limit.

```json
{
  "samira": {
    "password_hash": "<stored password hash>",
    "role": "Student Volunteer",
    "name": "Samira Patel",
    "dept": "Environmental Science",
    "skills": {
      "Photography": 4,
      "Event planning": 3
    }
  }
}
```

The attached command-line prototype stores raw passwords in a `password` field.
Do not carry that into new features; use a password hash if password-based
accounts are implemented.

## `events.json`

The key is the event ID. `organizer` refers to a username in `users.json`.
`required_skills` maps skill names to minimum non-negative ratings; an empty map
means no skill requirement. `slots_needed` is a positive integer.

```json
{
  "campus-garden-day": {
    "name": "Campus Garden Day",
    "description": "Help prepare the community garden for spring.",
    "organizer": "lee",
    "required_skills": {
      "Gardening": 2
    },
    "slots_needed": 8,
    "status": "open"
  }
}
```

Event status is `open` or `completed`.

Optional additive event fields:
- `departments`: list of departments allowed to apply. An empty list means all
  departments; this list controls application eligibility, not discovery visibility.
  Older events without the field keep their previous behavior.
- `department`: legacy display and discovery-filter label. For new events, the
  `departments` list is the authoritative participation scope.
- `category`: one of the keys in `CERTIFICATE_THEMES`, default `Community Service`.
  Legacy records without it are classified for display from their existing type/name.
- `image_url`: an optional HTTPS image URL, default empty. Only an explicitly
  supplied image is displayed; missing or invalid images do not select a stock
  photo or generate a placeholder. Existing event IDs and other fields are unchanged.

Newly issued certificate records snapshot `category` and `theme_category`.
Reissuing an existing certificate preserves its original theme selection.
Certificates without `theme_category` use the Community Service default theme,
regardless of later event edits. Verification codes remain private on PDFs.

Production storage uses JSON documents in the existing PostgreSQL
`skillmatch_documents` table via `data_store.py`. These optional JSON fields
require no SQL column/table migration and do not rewrite existing documents.

The unused local category images in `static/images/events/` are legacy stock
assets, not automatic fallbacks or photographs of actual SkillMatch events. Sources are free
Pexels photos, distributed under https://www.pexels.com/license/:

| Category | Source |
| --- | --- |
| Environment | https://www.pexels.com/photo/37172064/ |
| Education | https://www.pexels.com/photo/8423049/ |
| Health | https://www.pexels.com/photo/8460125/ |
| Community Service | https://www.pexels.com/photo/6646926/ |
| Tech | https://www.pexels.com/photo/9159069/ |
| Arts | https://www.pexels.com/photo/34512916/ |
| Sports/Fitness | https://www.pexels.com/photo/38010741/ |
| Animal Welfare | https://www.pexels.com/photo/35231857/ |
| Fundraising | https://www.pexels.com/photo/6995106/ |

## `applications.json`

The first key is the event ID; the nested key is the applicant's username.
`role` is `null` until an organizer accepts the application. `hours` is
non-negative and `notes` is a string.

```json
{
  "campus-garden-day": {
    "samira": {
      "status": "pending",
      "role": null,
      "hours": 0,
      "notes": ""
    }
  }
}
```

Application status is `pending`, `accepted`, or `rejected`.

## PrismLabs event integration

PrismLabs is a completed event in the existing `events.json` document.
Its coordinator and linked volunteers are normal SkillMatch users in
`users.json`, using the existing login, session, organizer dashboard, and
profile. Seeded accounts have `must_change_password` until their first
password update through `/account/password`.

- `prismlabs_volunteers.json`, keyed by trimmed PRN (with review-row keys only
  for missing PRNs): `full_name`, `prn`, `email`, `academic_year`, `department`,
  `interested_areas`, `registered_at`, nullable `hours`, and review flags.
- `prismlabs_participants.json`, keyed by PRN: `event_id`, nullable `hours`,
  and an optional `skillmatch_username` linking a roster row to an existing
  SkillMatch account. No accounts are created for unlinked roster rows.
- The regular `events.json` record includes an optional ISO `date`, venue,
  description, completed status, name-visibility toggle, and CSV registration
  period. Its `organizer` is a normal SkillMatch Organizer username.
- `prismlabs_certificates.json`, keyed by random certificate ID: PRN, event ID,
  and issue date. Event details are resolved at render time so an admin date
  change updates every certificate without changing its ID or issue date.
- `prismlabs_seed.json` records that the import and shared-account migration
  completed. Legacy separate account/event documents are emptied after their
  data is transferred; there is no independent PrismLabs authentication.

Roster hours begin as `null`, never zero. Emails outside the expected MIT-WPU
domain and PRNs with invalid or duplicate formats are preserved and flagged
for admin review rather than silently edited.

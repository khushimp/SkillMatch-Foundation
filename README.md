# SkillMatch

SkillMatch is a Flask web app for matching student volunteers with campus events. Volunteers can browse and apply to opportunities, while organizers manage events, applicants, attendance, and certificates.

## Features

- Student volunteer and organizer accounts
- Event discovery, search, filters, and skill matching
- Event applications, bookmarks, and notifications
- Organizer event and applicant management
- Attendance and volunteer-hour records
- Certificates with public verification
- Contribution and campus-impact charts 

## Technology

- Python 3.13+
- Flask and Jinja templates
- PostgreSQL via Psycopg
- Matplotlib for charts
- ReportLab for certificate PDFs
- HTML, CSS, and HTMX

## Setup

Install Python 3.13 or newer and `uv`. Then install the project dependencies:

```bash
uv sync

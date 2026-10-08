# Smart Campus Cybersecurity Monitoring System

A local-first, defensive cybersecurity monitoring platform for a simulated smart campus. The application centralizes campus asset inventory, rule-based detection of demonstration telemetry, risk scoring, alert triage, audit logs, and security analytics. It does not scan networks or connect to campus devices.

## Features

- Role-based sign-in for Admin, Security Analyst, and Viewer users; password hashes use Werkzeug's secure password hashing.
- Responsive SOC dashboard with device posture, recent events, alert severity, risk distribution, and activity charts.
- Device inventory with validated create, edit, delete, detail, search, and filter workflows.
- A dedicated threat-detection workbench with visible rule thresholds and safe simulated event submission.
- Safe event classification for repeated failed logins, unusual login times, repeated connections, suspicious-IP flags, simulated port probes, excessive requests, abnormal device behavior, and traffic spikes.
- Automatic LOW/MEDIUM/HIGH/CRITICAL alerts, linked threat events, and bounded 0-100 device risk scoring.
- Alert status workflow (New, Investigating, Resolved), searchable security audit trail, and analytics reports.
- A profile page for changing the display name and password; role assignment remains administrator-managed.
- CSRF-protected browser forms, parameterized SQLAlchemy queries, validated inputs, secure cookie defaults, and environment-based secrets/database configuration.
- SQLite for zero-setup local demonstration; PostgreSQL and MySQL are supported through `DATABASE_URL`.
- Production WSGI serving with Gunicorn on Linux hosts such as Render.

## Technology

Python 3.10+, Flask, Flask-Login, Flask-WTF, Flask-SQLAlchemy, SQLAlchemy, SQLite, PostgreSQL/psycopg, MySQL/PyMySQL, Gunicorn, HTML5, CSS3, Bootstrap 5, JavaScript, and Chart.js.

## Architecture

```text
app/
  models.py                 Relational SQLAlchemy models
  security.py               Role authorization decorators
  seed.py                    Reproducible demo accounts and telemetry
  threat_detection.py        Pure rule-based classifier and risk bands
  threat_service.py          Shared detection, risk, alert, and audit persistence
  routes/
    auth.py                  Registration, login, logout
    dashboard.py             SOC overview and chart summaries
    devices.py               Device inventory workflows
    alerts.py                Alert filtering and triage
    logs.py                  Searchable security audit trail
    reports.py               Analytics summaries
    api.py                   Authenticated simulated-event API
    threats.py               Detection rule workbench and local simulator
    profile.py               Profile/password updates
  templates/                 Jinja pages and error views
static/css, static/js/        Responsive interface and charts
config.py, extensions.py      App configuration and Flask extensions
run.py                       Local entry point (honors PORT)
wsgi.py                      Production WSGI application entry point
```

## Installation

1. Install Python 3.10 or newer. MySQL is optional for the default local demo.
2. From the project directory, create and activate a virtual environment:

   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   python -m pip install -r requirements.txt
   ```

3. Copy `.env.example` to `.env`, then replace `SECRET_KEY` with a random value. One way to generate it:

   ```powershell
   python -c "import secrets; print(secrets.token_hex(32))"
   ```

4. For the default SQLite demonstration, no database server setup is required. On first startup, tables and demo content are created automatically in `campus_security.db`.

## MySQL setup

Use MySQL 8 or later. Create the database and relational schema with the included MySQL-specific SQL file:

```powershell
mysql -u root -p < database.sql
```

Create an application-specific MySQL user with access only to `smart_campus_security`, then set `DATABASE_URL` in `.env`:

```text
DATABASE_URL=mysql+pymysql://YOUR_DB_USER:YOUR_DB_PASSWORD@localhost/smart_campus_security?charset=utf8mb4
```

The app creates any missing application tables and seeds demo users, devices, alerts, logs, threat events, and a report on first start. Existing user data prevents reseeding, so seed only a new/empty database. The schema file uses InnoDB foreign keys and JSON columns. The application also supports PostgreSQL; its tables are created from the SQLAlchemy models, so do not run the MySQL-specific `database.sql` against PostgreSQL.

## Deploy to Render

1. Push this project to a GitHub repository and create a Render **PostgreSQL** database and **Web Service** in the same region. Use the database's **Internal Database URL** for the web service's `DATABASE_URL` environment variable.
2. Set the Web Service build command to:

    ```text
    pip install -r requirements.txt
    ```

3. Set the Web Service start command to:

    ```text
    gunicorn --bind 0.0.0.0:$PORT --workers 2 --access-logfile - --error-logfile - wsgi:app
    ```

4. Set these environment variables in the Render dashboard. Do not add their values to source control:

    | Variable | Value |
    |---|---|
    | `APP_ENV` | `production` |
    | `SECRET_KEY` | Generate a private random value in Render (at least 32 random bytes). |
    | `DATABASE_URL` | Render PostgreSQL Internal Database URL, or a production MySQL URL using `mysql+pymysql://`. |
    | `COOKIE_SECURE` | `true` |
    | `SEED_DEMO` | Temporarily `true` only for a new academic demo database. |
    | `DEMO_ADMIN_PASSWORD` | Unique strong value, required when production demo seeding is enabled. |
    | `DEMO_ANALYST_PASSWORD` | Unique strong value, required when production demo seeding is enabled. |
    | `DEMO_VIEWER_PASSWORD` | Unique strong value, required when production demo seeding is enabled. |

    Render supplies `PORT`; do not set a fixed production port. On first deployment with a new demo database, `SEED_DEMO=true` provisions the accounts and sample campus data. After confirming initialization, set `SEED_DEMO=false` and remove the three demo-password variables from Render. Existing database users are not reseeded. For a non-demo deployment, use a separately provisioned Admin account and leave demo seeding disabled.

5. Optionally set the Render health-check path to `/api/health`. Confirm the first deploy's logs show a successful database connection and that login works before sharing the service URL.

Render's `postgres://` and `postgresql://` connection URLs are normalized to the installed `psycopg` driver. SQLite remains the local default; production startup deliberately rejects SQLite so an ephemeral deployment cannot appear healthy while losing data on restart. The included `database.sql` is MySQL-specific; PostgreSQL schema is generated from the application models.

## Run locally

```powershell
python run.py
```

Open http://127.0.0.1:5000. `run.py` loads `.env` before configuration and honors `PORT` (default `5000`). For production, set `APP_ENV=production`, use a strong private `SECRET_KEY`, set `COOKIE_SECURE=true`, and use Gunicorn; the Flask development server is for local academic demonstration only. Demo seeding defaults off in production.

## Demo accounts

| Role | Email | Password source |
|---|---|---|
| Admin | `admin@campus.edu` | Randomly generated at first seed; printed in the local server console |
| Security Analyst | `analyst@campus.edu` | Randomly generated at first seed; printed in the local server console |
| Viewer | `viewer@campus.edu` | Randomly generated at first seed; printed in the local server console |

These are academic localhost demo accounts, not production credentials. For repeatable local passwords, set `DEMO_ADMIN_PASSWORD`, `DEMO_ANALYST_PASSWORD`, and `DEMO_VIEWER_PASSWORD` in `.env` before first-time seeding. `.env.example` contains placeholders only. Use unique passwords and replace the generated demo passwords and private `SECRET_KEY` before any public deployment. Public registration is restricted to Viewer; an administrator must provision elevated roles.

Seeding only creates accounts when the database has no users. An existing SQLite database keeps its current password hashes; change those passwords through Profile or use a new empty demo database to generate fresh console credentials.

## Simulated event API

`POST /api/events` requires a signed-in Security Analyst or Admin and a CSRF token (`X-CSRFToken` header for JSON clients). It accepts only allowlisted demonstration event types. Example request body:

```json
{
  "event_type": "failed_login_attempts",
  "asset_tag": "WS-108",
  "source_ip": "10.24.3.108",
  "attributes": {"count": 6}
}
```

Thresholds and severity mappings live in `app/threat_detection.py`. The API never opens sockets, probes hosts, or performs real network scanning. `/api/health` is a minimal service liveness endpoint.

## Tests

```powershell
python -m pytest -q
```

Tests use an isolated in-memory SQLite database and cover startup, authentication, registration, profile changes, protected views, device and alert workflows, role access, and safe event ingestion.

## Future enhancements

- Add a production migration workflow (Alembic) and operator-managed account provisioning.
- Add configurable detection thresholds, retention policies, exports, and scheduled reports.
- Add signed service-to-service telemetry ingestion and deployment behind a production WSGI server with HTTPS.
- Replace seeded telemetry with a formally approved campus data source and privacy review.

# CyberCrime Watch — Regional Threat Awareness Dashboard

A fully working Flask + SQLite prototype for tracking and visualizing regional
cyber-crime threat trends, with role-based access (admin / analyst / user),
filterable interactive charts, and mock data generation.

## Features

- **Auth**: session-based login/register (Flask-Login), hashed passwords.
- **Roles**:
  - `admin` — everything, plus a user-management page (change roles,
    activate/deactivate, delete users).
  - `analyst` — full data access, filtering, and CSV export.
  - `user` — dashboard + charts with a summarized/paginated (capped) data
    table, no export, no user management.
- **Data model**: `ThreatEvent` (region, country, threat type, severity,
  incident count, date, source, description) seeded with ~1 year of
  realistic mock data across 7 regions, 8 threat types, 4 severities.
- **Interactive dashboard** (Chart.js):
  - KPI cards (total incidents, reported events, critical incidents, top region)
  - Trend line chart over time
  - Doughnut chart by threat type
  - Bar chart by region
  - Polar area chart by severity
  - Region × Severity heatmap table
  - Filterable, paginated incident log
- **Filters**: region, threat type, severity, date range — applied
  consistently across every chart/endpoint via query params.
- **REST-style JSON API** under `/api/*` (see below) that a real data feed
  could later replace the mock generator with.
- **CSV export** endpoint (`analyst`/`admin` only).

## Project structure

```
cyber_dashboard/
├── app.py              # App factory, routes, all API endpoints
├── config.py           # Config (secret key, DB URI)
├── extensions.py       # db, login_manager singletons
├── models.py           # User, ThreatEvent models + lookup constants
├── seed_data.py        # Mock data + demo user seeding
├── requirements.txt
├── templates/
│   ├── base.html
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   ├── admin.html
│   └── error.html
└── static/
    ├── css/style.css
    └── js/dashboard.js
```

## Setup & run

```bash
cd cyber_dashboard
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt

# First run creates the SQLite DB and seeds demo users + 1 year of mock data
python app.py
```

Then open **http://localhost:5000**.

To re-seed manually at any time:
```bash
python seed_data.py
```
(It's idempotent — it won't duplicate data or users that already exist.)

## Demo accounts

| Role    | Username  | Password    |
|---------|-----------|-------------|
| Admin   | admin     | Admin@123   |
| Analyst | analyst1  | Analyst@123 |
| User    | user1     | User@123    |

New self-registered accounts always start as `user`; an admin can promote
them from **Manage Users**.

⚠️ This is a prototype — change `SECRET_KEY` and all demo passwords before
any real deployment, and put it behind HTTPS.

## API endpoints (all require login)

| Endpoint                  | Notes |
|----------------------------|-------|
| `GET /api/meta`            | Regions/types/severities + current role & permissions |
| `GET /api/threats`         | Paginated raw events (filtered, role-limited page size) |
| `GET /api/stats/summary`   | KPI totals |
| `GET /api/stats/trend`     | Daily incident totals for the line chart |
| `GET /api/stats/by_region` | Totals grouped by region |
| `GET /api/stats/by_type`   | Totals grouped by threat type |
| `GET /api/stats/by_severity`| Totals grouped by severity |
| `GET /api/stats/heatmap`   | Region × severity matrix |
| `GET /api/export.csv`      | CSV export — `analyst`/`admin` only (403 otherwise) |

All accept optional query params: `region`, `threat_type`, `severity`,
`start_date` (`YYYY-MM-DD`), `end_date` (`YYYY-MM-DD`).

## Swapping in real data

Replace the contents of `seed_data.py`'s generation logic (or write a new
ingestion script) that inserts rows into `ThreatEvent` — the dashboard and
API layer need no changes since everything queries that one table.

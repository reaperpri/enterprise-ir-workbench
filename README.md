# Enterprise IR Workbench

A local, educational SOC incident dashboard built with Streamlit, Pandas, and Plotly. It reads a clearly labeled synthetic incident CSV and provides interactive triage, incident timelines, severity analytics, entity-based scoping, SHA-256 evidence integrity checks, educational CSIRT coordination guidance, and downloadable investigation reports.

> **Safety and scope:** This application is a training/demo workbench. It does not connect to production systems, send alerts, isolate hosts, change accounts, or perform any incident response action. Sample records and evidence are synthetic and must not be treated as real evidence.

## Fedora / Linux setup

Python 3.10 or newer is required.

```bash
cd /path/to/enterprise-ir-workbench
sudo dnf install python3 python3-pip
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Run the dashboard

From the project directory with the virtual environment activated:

```bash
streamlit run streamlit_app.py
```

Streamlit prints a local URL (normally `http://localhost:8501`). The dashboard uses `data/incidents.csv` by default. Keep the CSV columns and timestamp/boolean formats intact when extending the educational dataset; startup validation reports missing or malformed data.

## Features

- Overview KPIs, incident lifecycle timeline, daily incident trend, and severity distribution.
- Searchable incident queue with severity/status/date filtering.
- Entity-based scoping for shared assets, accounts, and indicators.
- SHA-256 calculation for uploaded evidence; an optional expected digest enables integrity comparison. A synthetic sample file is included for a safe demonstration.
- Rule-based CSIRT coordination recommendations with rationale and review checklist.
- Downloadable per-incident Markdown investigation report and filtered queue CSV.

Evidence hashing is an integrity aid, not proof of authenticity or chain of custody. Handle any real evidence only under your organization's approved procedures.

## Tests

Run the unit tests from the project directory:

```bash
python -m unittest discover -s tests -v
```

The tests cover dataset validation, triage filters, lifecycle timeline generation, incident scoping, educational escalation guidance, SHA-256 comparisons, and report generation.

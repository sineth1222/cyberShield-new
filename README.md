# CyberShield — Cybersecurity Awareness Platform

A multi-file web application built with **Python (Flask)** for the backend and **HTML / CSS / JavaScript** for the frontend.

## Project Structure

```
cybershield/
├── app.py               ← Flask backend (routes, auth, REST API)
├── templates/
│   ├── login.html       ← Login page
│   └── index.html       ← Main dashboard (SPA shell + all JS logic)
├── static/
│   └── style.css        ← Global stylesheet
└── README.md
```

## How to Run

1. Install Flask:
   ```
   pip install flask
   ```

2. Start the server:
   ```
   python app.py
   ```

3. Open your browser at `http://localhost:5050`

## Accounts

| Username | Password  | Role          |
|----------|-----------|---------------|
| admin    | admin123  | Administrator |
| alice    | pass1     | Employee      |
| bob      | pass2     | Employee      |
| carol    | pass3     | Employee      |
| dave     | pass4     | Employee      |

## Features

### Employee
- **Learn** — Training modules with progress tracking
- **Quiz** — 6-question knowledge assessment
- **Password Check** — Real-time strength meter
- **Report Incident** — Structured form with live threat intelligence feed

### Admin
- **Overview** — Stats across all employees
- **Employees** — Per-user progress cards
- **Quiz Answers** — Full answer breakdown per employee
- **Incidents** — All submitted incident reports
- **Cyber News Feed** — Aggregated live RSS from CISA, BleepingComputer, The Hacker News

## Architecture Notes

- State is stored **in-memory** on the server (per session). For production, replace with a database (SQLite / PostgreSQL).
- The threat intelligence feed is fetched client-side via the `rss2json.com` public API proxy to resolve CORS.
- Authentication uses Flask server-side sessions.

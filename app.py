"""
CyberShield — Cybersecurity Awareness Platform
Flask backend: authentication, user state, incident API.
"""

from flask import (
    Flask, render_template, request, session,
    jsonify, redirect, url_for
)
from functools import wraps
from datetime import datetime
import time, random, string

app = Flask(__name__)
app.secret_key = "cybershield-secret-key-change-in-production"

# ─── ACCOUNTS ────────────────────────────────────────────────────
ACCOUNTS = {
    "admin": {"password": "admin123", "role": "admin",    "name": "Administrator"},
    "alice": {"password": "pass1",    "role": "employee", "name": "Alice Johnson"},
    "bob":   {"password": "pass2",    "role": "employee", "name": "Bob Smith"},
    "carol": {"password": "pass3",    "role": "employee", "name": "Carol White"},
    "dave":  {"password": "pass4",    "role": "employee", "name": "Dave Brown"},
}

# ─── IN-MEMORY STATE (keyed by username) ─────────────────────────
USER_STATE = {
    u: {"completed_modules": [], "quiz_answers": None,
        "quiz_score": None, "quiz_date": None, "incidents": []}
    for u in ACCOUNTS if ACCOUNTS[u]["role"] == "employee"
}

MODULES = [
    {"id": "m1", "title": "What is Phishing?",   "icon": "🎣",
     "desc": "Identify phishing emails and social engineering attacks.",
     "content": "<p>Phishing uses disguised emails to steal sensitive data.</p><p><b>Signs:</b> Urgent language · Mismatched senders · Suspicious links · Password requests</p><p><b>Action:</b> Never click suspicious links. Report to IT immediately.</p>"},
    {"id": "m2", "title": "Password Security",    "icon": "🔑",
     "desc": "Best practices for creating and managing strong passwords.",
     "content": "<p>Weak passwords are the #1 cause of data breaches.</p><p><b>Rules:</b> 12+ characters · Mix of types · Never reuse · Use a manager</p><p><b>Note:</b> Real IT will never ask for your password.</p>"},
    {"id": "m3", "title": "Safe Internet Use",    "icon": "🌐",
     "desc": "Browse safely and avoid malicious websites.",
     "content": "<p><b>Tips:</b> Check for HTTPS · Avoid pop-up ads · Avoid public Wi-Fi for sensitive tasks · Use a VPN remotely</p>"},
    {"id": "m4", "title": "Data Protection",      "icon": "🗄️",
     "desc": "Handle sensitive company and customer data correctly.",
     "content": "<p><b>Rules:</b> No personal devices for sensitive data · Lock screen when away · Encrypt emails with customer data · Shred physical documents</p>"},
    {"id": "m5", "title": "Incident Reporting",   "icon": "🚨",
     "desc": "Know how and when to report a cybersecurity incident.",
     "content": "<p>Fast reporting limits damage.</p><p><b>Report if:</b> You clicked a phishing link · Your device behaves oddly · Unauthorised access · Device lost/stolen</p>"},
]

QUIZ = [
    {"q": "What is the most common sign of a phishing email?",
     "opts": ["Colourful logo", "Urgent request for your password", "Very long body", "No subject line"], "ans": 1},
    {"q": "Which password is the strongest?",
     "opts": ["password123", "MyDog2020", "T#9kLm!2pQw@", "qwerty"], "ans": 2},
    {"q": "What should you do with an unexpected email attachment?",
     "opts": ["Open immediately", "Delete without opening", "Report to IT and do not open", "Forward to colleagues"], "ans": 2},
    {"q": "What does HTTPS indicate in a URL?",
     "opts": ["The site is fast", "The site has a secure connection", "Government-owned", "Login required"], "ans": 1},
    {"q": "Which is an example of social engineering?",
     "opts": ["Installing antivirus", "Caller pretending to be IT support", "Updating your browser", "Using a strong password"], "ans": 1},
    {"q": "What should you do when leaving your workstation?",
     "opts": ["Leave it as is", "Lock the screen", "Shut down", "Ask a colleague"], "ans": 1},
]

# ─── AUTH HELPERS ─────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if "user" not in session:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return wrapped

def admin_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if "user" not in session or ACCOUNTS[session["user"]]["role"] != "admin":
            return jsonify({"error": "Forbidden"}), 403
        return f(*args, **kwargs)
    return wrapped

def get_state(user):
    return USER_STATE.get(user, {
        "completed_modules": [], "quiz_answers": None,
        "quiz_score": None, "quiz_date": None, "incidents": []
    })

# ─── ROUTES ──────────────────────────────────────────────────────
@app.route("/")
def index():
    if "user" in session:
        return redirect(url_for("dashboard"))
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("index"))
    return render_template("index.html",
        user=session["user"],
        name=ACCOUNTS[session["user"]]["name"],
        role=ACCOUNTS[session["user"]]["role"]
    )

# ─── AUTH API ─────────────────────────────────────────────────────
@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json()
    username = (data.get("username") or "").strip().lower()
    password = data.get("password") or ""
    acct = ACCOUNTS.get(username)
    if not acct or acct["password"] != password:
        return jsonify({"ok": False, "error": "Invalid username or password."}), 401
    session["user"] = username
    return jsonify({"ok": True, "role": acct["role"], "name": acct["name"]})

@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"ok": True})

@app.route("/api/me")
@login_required
def api_me():
    u = session["user"]
    acct = ACCOUNTS[u]
    return jsonify({"username": u, "name": acct["name"], "role": acct["role"]})

# ─── MODULE API ───────────────────────────────────────────────────
@app.route("/api/modules")
@login_required
def api_modules():
    u = session["user"]
    state = get_state(u)
    return jsonify({"modules": MODULES, "completed": state["completed_modules"]})

@app.route("/api/modules/<mod_id>/complete", methods=["POST"])
@login_required
def api_complete_module(mod_id):
    u = session["user"]
    state = get_state(u)
    if mod_id not in state["completed_modules"]:
        state["completed_modules"].append(mod_id)
    return jsonify({"ok": True, "completed": state["completed_modules"]})

# ─── QUIZ API ─────────────────────────────────────────────────────
@app.route("/api/quiz")
@login_required
def api_quiz():
    u = session["user"]
    state = get_state(u)
    safe_quiz = [{"q": q["q"], "opts": q["opts"]} for q in QUIZ]
    return jsonify({
        "questions": safe_quiz,
        "submitted": state["quiz_answers"] is not None,
        "score": state["quiz_score"],
        "total": len(QUIZ),
        "answers": state["quiz_answers"],
        "date": state["quiz_date"],
        "correct_answers": [q["ans"] for q in QUIZ] if state["quiz_answers"] is not None else None
    })

@app.route("/api/quiz/submit", methods=["POST"])
@login_required
def api_quiz_submit():
    u = session["user"]
    state = get_state(u)
    data = request.get_json()
    answers = data.get("answers", [])
    if len(answers) != len(QUIZ):
        return jsonify({"error": "Incomplete answers"}), 400
    score = sum(1 for i, a in enumerate(answers) if a == QUIZ[i]["ans"])
    state["quiz_answers"] = answers
    state["quiz_score"] = score
    state["quiz_date"] = datetime.now().isoformat()
    return jsonify({"ok": True, "score": score, "total": len(QUIZ)})

@app.route("/api/quiz/reset", methods=["POST"])
@login_required
def api_quiz_reset():
    u = session["user"]
    state = get_state(u)
    state["quiz_answers"] = None
    state["quiz_score"] = None
    state["quiz_date"] = None
    return jsonify({"ok": True})

# ─── INCIDENT API ─────────────────────────────────────────────────
@app.route("/api/incidents", methods=["GET"])
@login_required
def api_incidents_get():
    u = session["user"]
    state = get_state(u)
    return jsonify({"incidents": state["incidents"]})

@app.route("/api/incidents", methods=["POST"])
@login_required
def api_incidents_post():
    u = session["user"]
    state = get_state(u)
    data = request.get_json()
    ref = "INC-" + "".join(random.choices(string.ascii_uppercase + string.digits, k=8))
    incident = {
        "ref": ref,
        "type": data.get("type", ""),
        "severity": data.get("severity", ""),
        "description": data.get("description", ""),
        "date": data.get("date", datetime.now().date().isoformat()),
        "time": data.get("time", ""),
        "location": data.get("location", ""),
        "others_affected": data.get("othersAffected", ""),
        "data_exposed": data.get("dataExposed", ""),
        "extra": data.get("extra", ""),
        "actions_taken": data.get("actionsTaken", []),
        "status": "Open",
        "submitted_at": datetime.now().isoformat()
    }
    state["incidents"].append(incident)
    return jsonify({"ok": True, "ref": ref})

# ─── ADMIN API ────────────────────────────────────────────────────
@app.route("/api/admin/overview")
@admin_required
def api_admin_overview():
    employees = [u for u in ACCOUNTS if ACCOUNTS[u]["role"] == "employee"]
    rows = []
    total_score, scored = 0, 0
    total_mods = 0
    open_inc = 0
    for u in employees:
        s = get_state(u)
        pct = None
        if s["quiz_score"] is not None:
            pct = round(s["quiz_score"] / len(QUIZ) * 100)
            total_score += pct
            scored += 1
        total_mods += len(s["completed_modules"])
        for inc in s["incidents"]:
            if inc["status"] == "Open":
                open_inc += 1
        rows.append({
            "username": u, "name": ACCOUNTS[u]["name"],
            "modules_done": len(s["completed_modules"]),
            "modules_total": len(MODULES),
            "quiz_pct": pct,
            "incidents": len(s["incidents"])
        })
    avg_mods = round(total_mods / len(employees) / len(MODULES) * 100) if employees else 0
    avg_quiz = round(total_score / scored) if scored else 0
    return jsonify({
        "rows": rows, "avg_mods": avg_mods,
        "avg_quiz": avg_quiz, "open_incidents": open_inc,
        "employee_count": len(employees)
    })

@app.route("/api/admin/quiz-answers")
@admin_required
def api_admin_quiz():
    employees = [u for u in ACCOUNTS if ACCOUNTS[u]["role"] == "employee"]
    result = []
    for u in employees:
        s = get_state(u)
        if s["quiz_answers"] is not None:
            result.append({
                "username": u, "name": ACCOUNTS[u]["name"],
                "score": s["quiz_score"], "total": len(QUIZ),
                "pct": round(s["quiz_score"] / len(QUIZ) * 100),
                "answers": s["quiz_answers"],
                "correct": [q["ans"] for q in QUIZ],
                "questions": [q["q"] for q in QUIZ],
                "opts": [q["opts"] for q in QUIZ],
                "date": s["quiz_date"]
            })
    return jsonify({"data": result})

@app.route("/api/admin/incidents")
@admin_required
def api_admin_incidents():
    employees = [u for u in ACCOUNTS if ACCOUNTS[u]["role"] == "employee"]
    all_inc = []
    for u in employees:
        s = get_state(u)
        for inc in s["incidents"]:
            all_inc.append({**inc, "reporter": u, "reporter_name": ACCOUNTS[u]["name"]})
    all_inc.sort(key=lambda x: x["submitted_at"], reverse=True)
    return jsonify({"incidents": all_inc})

if __name__ == "__main__":
    app.run(debug=True, port=5050)

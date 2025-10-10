from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from passlib.context import CryptContext
from pydantic import BaseModel
import sqlite3
from db import init_db, get_all_users, create_user, delete_user, reset_password, authenticate_user, is_admin_user
from datetime import datetime
import os
import csv
import io
import pandas as pd
app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key="super-secret-key")
API_KEY = os.getenv("API_KEY", "supersecretkey123")

init_db()

# ---------- AUTH ROUTES ----------

@app.get("/users", response_class=HTMLResponse)
def manage_users(request: Request):
    #if "user" not in request.session or request.session["role"] != "admin":
    #    return RedirectResponse("/login", status_code=302)
    #	
    #from db import get_all_users
    users = get_all_users()
    return templates.TemplateResponse(
        "users.html",
        {
            "request": request,
            "user": request.session["user"],
            "role": request.session["role"],
            "users": users
        }
    )


@app.post("/users/create")
def create_user_route(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    role: str = Form("user")
):
    if "user" not in request.session or request.session["role"] != "admin":
        return RedirectResponse("/login", status_code=302)

    from db import create_user
    try:
        create_user(username, password, role)
        return RedirectResponse("/users", status_code=302)
    except Exception as e:
        return HTMLResponse(f"<h3>❌ Error: {e}</h3>", status_code=400)

@app.get("/reset-password", response_class=HTMLResponse)
def reset_password_page(request: Request):
    if "user" not in request.session:
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse("reset_password.html", {"request": request})

@app.post("/reset-password")
def reset_password(request: Request, old_password: str = Form(...), new_password: str = Form(...)):
    if "user" not in request.session:
        return RedirectResponse("/login", status_code=302)

    username = request.session["user"]
    if not authenticate_user(username, old_password):
        return HTMLResponse("<h3>Old password is incorrect</h3>", status_code=400)

    try:
        update_password(username, new_password)
    except ValueError as ve:
        return HTMLResponse(content=f"<h3>Error: {ve}</h3>", status_code=400)

    return HTMLResponse("<h3>Password updated successfully. Please <a href='/logout'>login again</a>.</h3>")

@app.get("/admin/reset-password", response_class=HTMLResponse)
def admin_reset_password_page(request: Request):
    if "user" not in request.session or not is_admin_user(request.session["user"]):
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse("admin_reset_password.html", {"request": request})

@app.post("/admin/reset-password")
def admin_reset_password(request: Request, target_username: str = Form(...), new_password: str = Form(...)):
    if "user" not in request.session or not is_admin_user(request.session["user"]):
        return RedirectResponse("/login", status_code=302)

    try:
        update_password(target_username, new_password)
    except ValueError as ve:
        return HTMLResponse(content=f"<h3>Error: {ve}</h3>", status_code=400)
    except Exception as e:
        return HTMLResponse(content=f"<h3>User not found: {e}</h3>", status_code=400)

    return HTMLResponse(f"<h3>Password for {target_username} updated successfully.</h3>")

@app.get("/export/csv")
def export_csv(request: Request):
    if not request.session.get("user"):
        return RedirectResponse("/login")

    cur = conn.cursor()
    cur.execute("SELECT hostname, source, column_name, detected, timestamp FROM pii_results ORDER BY timestamp DESC")
    rows = cur.fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Hostname", "Source", "Column", "Detected", "Timestamp"])
    writer.writerows(rows)
    output.seek(0)

    return StreamingResponse(output, media_type="text/csv", headers={"Content-Disposition": "attachment; filename=pii_report.csv"})


@app.get("/export/excel")
def export_excel(request: Request):
    if not request.session.get("user"):
        return RedirectResponse("/login")

    cur = conn.cursor()
    cur.execute("SELECT hostname, source, column_name, detected, timestamp FROM pii_results ORDER BY timestamp DESC")
    rows = cur.fetchall()

    df = pd.DataFrame(rows, columns=["Hostname", "Source", "Column", "Detected", "Timestamp"])
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="PII Findings")
    output.seek(0)

    return StreamingResponse(output, media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                             headers={"Content-Disposition": "attachment; filename=pii_report.xlsx"})

# -----------------------------
# FastAPI App
# -----------------------------
app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key="supersecretkey")  # change this key!
templates = Jinja2Templates(directory="templates")

# -----------------------------
# SQLite DB
# -----------------------------
DB_PATH = "central_pii_results.db"
conn = sqlite3.connect(DB_PATH, check_same_thread=False)
cur = conn.cursor()
cur.execute("""
CREATE TABLE IF NOT EXISTS pii_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname TEXT,
    source TEXT,
    column_name TEXT,
    detected TEXT,
    timestamp TEXT
)
""")
conn.commit()

# -----------------------------
# Helper: Check login
# -----------------------------
def require_login(request: Request):
    if not request.session.get("user"):
        return RedirectResponse(url="/login", status_code=302)
    return True


# -----------------------------
# Routes: Auth
# -----------------------------
@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    if authenticate_user(username, password):
        request.session["user"] = username
        request.session["role"] = "admin" if is_admin_user(username) else "user"
        return RedirectResponse("/", status_code=302)
    return HTMLResponse("<h3>❌ Invalid username or password</h3>", status_code=400)

@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=302)


# -----------------------------
# API Model
# -----------------------------
class PiiRecord(BaseModel):
    hostname: str
    source: str
    column: str
    detected: list
    api: str

# -----------------------------
# API Endpoint: Upload results
# -----------------------------
@app.post("/upload")
def upload(record: PiiRecord):
    # 🔒 Check API key
    if record.api != API_KEY:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    ts = datetime.now().isoformat()
    conn.execute("INSERT INTO pii_results (hostname, source, column_name, detected, timestamp) VALUES (?, ?, ?, ?, ?)",
                 (record.hostname, record.source, record.column, ",".join(record.detected), ts))
    conn.commit()
    return {"status": "ok"}

def get_dashboard_data(pii_filter: str = None):
    """Prepare rows and chart data, with optional PII filter."""
    cur = conn.cursor()

    if pii_filter:
        # Filtered rows
        cur.execute("""
            SELECT hostname, source, column_name, detected, timestamp 
            FROM pii_results 
            WHERE detected LIKE ? 
            ORDER BY timestamp DESC LIMIT 100
        """, (f"%{pii_filter}%",))
        rows = cur.fetchall()

        # Counts by type (only filtered data)
        cur.execute("SELECT detected FROM pii_results WHERE detected LIKE ?", (f"%{pii_filter}%",))
    else:
        # All rows
        cur.execute("""
            SELECT hostname, source, column_name, detected, timestamp 
            FROM pii_results 
            ORDER BY timestamp DESC LIMIT 100
        """)
        rows = cur.fetchall()

        # Counts by type (all data)
        cur.execute("SELECT detected FROM pii_results")

    # Aggregate PII counts
    pii_counts = {"aadhaar": 0, "pan": 0, "email": 0, "phone": 0, "credit_card": 0}
    for (detected,) in cur.fetchall():
        for pii in pii_counts:
            if pii in detected.lower():
                pii_counts[pii] += 1

    # Counts by host (with optional filter)
    if pii_filter:
        cur.execute("SELECT hostname, COUNT(*) FROM pii_results WHERE detected LIKE ? GROUP BY hostname", (f"%{pii_filter}%",))
    else:
        cur.execute("SELECT hostname, COUNT(*) FROM pii_results GROUP BY hostname")
    host_counts = {hostname: count for hostname, count in cur.fetchall()}

    return rows, pii_counts, host_counts

@app.get("/", response_class=HTMLResponse)

def dashboard(request: Request, hostname: str = None, source: str = None):
    if not request.session.get("user"):
        return RedirectResponse("/login")

    if "user" not in request.session:
        return RedirectResponse("/login", status_code=302)
    # fetch unique hostnames and sources
    cur.execute("SELECT DISTINCT hostname FROM pii_results WHERE hostname IS NOT NULL")
    hostnames = [row[0] for row in cur.fetchall()]

    cur.execute("SELECT DISTINCT source FROM pii_results WHERE source IS NOT NULL")
    sources = [row[0] for row in cur.fetchall()]

    # build query based on filters
    query = "SELECT * FROM pii_results WHERE 1=1"
    params = []
    if hostname:
        query += " AND hostname = ?"
        params.append(hostname)
    if source:
        query += " AND source = ?"
        params.append(source)

    cur.execute(query, params)
    rows = cur.fetchall()

    # prepare chart data (simple count by detected type)
    cur.execute("SELECT detected, COUNT(*) FROM pii_results GROUP BY detected")
    chart_data = {
        "labels": [r[0] for r in cur.fetchall()],
        "counts": [r[1] for r in cur.fetchall()]
    }
    rows, pii_counts, host_counts = get_dashboard_data()

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "user": request.session["user"],
        "role": request.session["role"],
        "rows": rows,
        "hostnames": hostnames,
        "sources": sources,
        "chart_data": chart_data,
        "pii_type_data": pii_counts,
        "pii_host_data": host_counts
    })


def dashboard(request: Request):
    if not request.session.get("user"):
        return RedirectResponse("/login")
    rows, pii_counts, host_counts = get_dashboard_data()
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "rows": rows,
        "pii_type_data": pii_counts,
        "pii_host_data": host_counts
    })


@app.get("/filter/{pii_type}", response_class=HTMLResponse)
def filter_by_type(request: Request, pii_type: str):
    if not request.session.get("user"):
        return RedirectResponse("/login")
    rows, pii_counts, host_counts = get_dashboard_data(pii_filter=pii_type)
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "rows": rows,
        "pii_type_data": pii_counts,
        "pii_host_data": host_counts,
        "filter": pii_type
    })

# -----------------------------
# Dashboard: Homepage
# -----------------------------
@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    cur = conn.cursor()
    cur.execute("SELECT hostname, source, column_name, detected, timestamp FROM pii_results ORDER BY timestamp DESC LIMIT 100")
    rows = cur.fetchall()

    # Aggregate counts by type
    cur.execute("SELECT detected FROM pii_results")
    pii_counts = {"aadhaar": 0, "pan": 0, "email": 0, "phone": 0, "credit_card": 0}
    for (detected,) in cur.fetchall():
        for pii in pii_counts:
            if pii in detected.lower():
                pii_counts[pii] += 1

    # Aggregate counts by host
    cur.execute("SELECT hostname, COUNT(*) FROM pii_results GROUP BY hostname")
    host_counts = {hostname: count for hostname, count in cur.fetchall()}

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "rows": rows,
        "pii_type_data": pii_counts,
        "pii_host_data": host_counts
    })


#@app.get("/", response_class=HTMLResponse)
#def dashboard(request: Request):
#    cur = conn.cursor()
#    cur.execute("SELECT hostname, source, column_name, detected, timestamp FROM pii_results ORDER BY timestamp DESC LIMIT 100")
#    rows = cur.fetchall()
#    return templates.TemplateResponse("dashboard.html", {"request": request, "rows": rows})

# -----------------------------
# Dashboard: Filter by type
# -----------------------------
@app.get("/filter/{pii_type}", response_class=HTMLResponse)
def filter_by_type(request: Request, pii_type: str):
    cur = conn.cursor()
    cur.execute("SELECT hostname, source, column_name, detected, timestamp FROM pii_results WHERE detected LIKE ? ORDER BY timestamp DESC",
                (f"%{pii_type}%",))
    rows = cur.fetchall()
    return templates.TemplateResponse("dashboard.html", {"request": request, "rows": rows, "filter": pii_type})

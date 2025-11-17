from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from passlib.context import CryptContext
from pydantic import BaseModel
import psycopg2
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from db import (
    init_db, get_all_users, create_user, delete_user, 
    reset_password, authenticate_user, is_admin_user, 
    get_db_connection, return_db_connection
)
from db import connection_pool

from typing import List
from contextlib import asynccontextmanager

class PiiRecord(BaseModel):
    hostname: str
    source: str
    column_name: str
    detected: List[str]
from datetime import datetime
import os
import csv
import io
import pandas as pd
import logging
import time

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup event
    logger.info("Starting up application")
    try:
        # Wait for database to be ready
        max_retries = 5
        retry_count = 0
        while retry_count < max_retries:
            try:
                init_db()
                logger.info("Database initialized successfully")
                break
            except Exception as e:
                retry_count += 1
                if retry_count == max_retries:
                    logger.error(f"Failed to initialize database after {max_retries} attempts: {str(e)}")
                    raise
                logger.warning(f"Database initialization attempt {retry_count} failed, retrying...")
                time.sleep(2 ** retry_count)  # Exponential backoff
    except Exception as e:
        logger.error(f"Failed to initialize database: {str(e)}")
        # Don't raise the exception, just log it
        pass
    
    yield
    
    # Shutdown event
    logger.info("Shutting down application")
    # Clean up any remaining connections
    if 'connection_pool' in globals():
        connection_pool.closeall()

app = FastAPI(lifespan=lifespan)

# Add CORS middleware for Cloud Run
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust this in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(SessionMiddleware, secret_key="super-secret-key")
API_KEY = os.getenv("API_KEY", "supersecretkey123")

from fastapi.staticfiles import StaticFiles
app.mount("/static", StaticFiles(directory="static"), name="static")

# templates directory
templates = Jinja2Templates(directory="templates")

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

# ------------------------------
# Home/Dashboard
# ------------------------------
@app.get("/", response_class=HTMLResponse)

def dashboard(request: Request, hostname: str = None, source: str = None):
    try:
        logger.info("Dashboard route accessed")
        
        if not request.session.get("user"):
            logger.info("No user in session, redirecting to login")
            return RedirectResponse("/login")

        logger.info(f"User in session: {request.session.get('user')}")

        conn = None
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            
            # fetch unique hostnames and sources
            cur.execute("SELECT DISTINCT hostname FROM pii_results WHERE hostname IS NOT NULL")
            hostnames = [row[0] for row in cur.fetchall()]
            logger.info(f"Found {len(hostnames)} unique hostnames")

            cur.execute("SELECT DISTINCT source FROM pii_results WHERE source IS NOT NULL")
            sources = [row[0] for row in cur.fetchall()]
            logger.info(f"Found {len(sources)} unique sources")

            # build query based on filters
            query = "SELECT * FROM pii_results WHERE 1=1"
            params = []
            if hostname:
                query += " AND hostname = %s"
                params.append(hostname)
            if source:
                query += " AND source = %s"
                params.append(source)

            logger.info(f"Executing query: {query} with params: {params}")
            cur.execute(query, params)
            filtered_rows = cur.fetchall()
            logger.info(f"Found {len(filtered_rows)} rows matching filters")

            # prepare chart data
            cur.execute("SELECT detected, COUNT(*) FROM pii_results GROUP BY detected")
            chart_results = cur.fetchall() or []
            logger.info(f"Found {len(chart_results)} unique detection types")
            
            chart_data = {
                "labels": [r[0] if r[0] is not None else "Unknown" for r in chart_results],
                "counts": [r[1] for r in chart_results]
            }
            
            logger.info("Getting dashboard data...")
            rows, pii_counts, host_counts = get_dashboard_data(conn)
            logger.info("Dashboard data retrieved successfully")

            result = templates.TemplateResponse("dashboard.html", {
                "request": request,
                "user": request.session["user"],
                "role": request.session["role"],
                "rows": rows,
                "hostnames": hostnames or [],
                "sources": sources or [],
                "chart_data": chart_data,
                "pii_type_data": pii_counts,
                "pii_host_data": host_counts,
                "filter": None
            })

            return result

        except Exception as db_error:
            logger.error(f"Database error in dashboard: {str(db_error)}")
            raise
        finally:
            if conn:
                try:
                    return_db_connection(conn)
                    logger.info("Database connection returned to pool")
                except Exception as close_error:
                    logger.error(f"Error returning connection to pool: {str(close_error)}")

    except Exception as e:
        logger.error(f"Unhandled error in dashboard: {str(e)}")
        return templates.TemplateResponse("error.html", {
            "request": request,
            "error_message": "An error occurred while loading the dashboard. Please try again later."
        }, status_code=500)


def get_dashboard_data(connection, pii_filter: str = None):
    """Prepare rows and chart data, with optional PII filter."""
    logger.info(f"Getting dashboard data with filter: {pii_filter}")
    cur = connection.cursor()
    
    try:
        if pii_filter:
            # Filtered rows
            cur.execute("""
                SELECT hostname, source, column_name, detected, timestamp 
                FROM pii_results 
                WHERE detected LIKE %s 
                ORDER BY timestamp DESC LIMIT 100
            """, (f"%{pii_filter}%",))
        else:
            # All rows
            cur.execute("""
                SELECT hostname, source, column_name, detected, timestamp 
                FROM pii_results 
                ORDER BY timestamp DESC LIMIT 100
            """)
        
        rows = cur.fetchall()
        logger.info(f"Retrieved {len(rows)} rows")

        # Initialize counts
        pii_counts = {"aadhaar": 0, "pan": 0, "email": 0, "phone": 0, "credit_card": 0}
        host_counts = {}

        # Process the same rows for both PII counts and host counts
        for row in rows:
            hostname, _, _, detected, _ = row
            
            # Count PII types
            if detected:
                detected_lower = detected.lower()
                for pii in pii_counts:
                    if pii in detected_lower:
                        pii_counts[pii] += 1

            # Count by hostname
            if hostname:
                host_counts[hostname] = host_counts.get(hostname, 0) + 1

        logger.info(f"PII counts: {pii_counts}")
        logger.info(f"Host counts: {dict(sorted(host_counts.items()))}")
        
        return rows, pii_counts, host_counts
        
    except Exception as e:
        logger.error(f"Error in get_dashboard_data: {str(e)}")
        # Return empty data instead of raising
        return [], {"aadhaar": 0, "pan": 0, "email": 0, "phone": 0, "credit_card": 0}, {}

    return rows, pii_counts, host_counts







@app.get("/filter/{pii_type}", response_class=HTMLResponse)
def filter_by_type(request: Request, pii_type: str):
    if not request.session.get("user"):
        return RedirectResponse("/login")
    
    conn = get_db_connection()
    try:
        rows, pii_counts, host_counts = get_dashboard_data(conn, pii_filter=pii_type)
        conn.close()
        return templates.TemplateResponse("dashboard.html", {
            "request": request,
            "rows": rows,
            "pii_type_data": pii_counts,
            "pii_host_data": host_counts,
            "filter": pii_type
        })
    except Exception as e:
        if conn:
            conn.close()
        print(f"Error in filter_by_type: {str(e)}")
        raise


@app.post("/upload")
async def upload(record: PiiRecord, request: Request):
    # Check API key
    if request.headers.get("X-API-Key") != API_KEY:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Join the list of detections with a comma
        detected_str = ", ".join(record.detected)
        
        cur.execute("""
            INSERT INTO pii_results (hostname, source, column_name, detected, timestamp) 
            VALUES (%s, %s, %s, %s, %s)
        """, (record.hostname, record.source, record.column_name, detected_str, datetime.now()))
        
        conn.commit()
        return_db_connection(conn)
        return {"status": "success"}
    except Exception as e:
        logger.error(f"Error uploading record: {str(e)}")
        return JSONResponse({"error": str(e)}, status_code=500)



# ------------------------------
# User Management (Admins only)
# ------------------------------
@app.get("/users", response_class=HTMLResponse)
def manage_users(request: Request):
    if "user" not in request.session or request.session.get("role") != "admin":
        return RedirectResponse("/login", status_code=302)

    users = get_all_users()
    return templates.TemplateResponse(
        "users.html",
        {"request": request, "user": request.session["user"], "role": request.session["role"], "users": users}
    )

@app.post("/users/create")
def create_user_route(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    role: str = Form("user")
):
    if "user" not in request.session or request.session.get("role") != "admin":
        return RedirectResponse("/login", status_code=302)

    create_user(username, password, role)
    return RedirectResponse("/users", status_code=302)

@app.post("/users/delete/{user_name}")
def delete_user_route(request: Request, user_name: str):
    if "user" not in request.session or request.session.get("role") != "admin":
        return RedirectResponse("/login", status_code=302)

    delete_user(user_name)
    return RedirectResponse("/users", status_code=302)

@app.post("/users/reset/{user_name}")
def reset_user_password(request: Request, user_name: str, new_password: str = Form(...)):
    if "user" not in request.session or request.session.get("role") != "admin":
        return RedirectResponse("/login", status_code=302)

    reset_password(user_name, new_password)
    return RedirectResponse("/users", status_code=302)

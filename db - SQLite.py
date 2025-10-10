# db.py
import sqlite3
import re
from passlib.hash import argon2


def init_db():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()

    # Create users table if not exists
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user'
    )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS pii_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hostname TEXT,
            file_path TEXT,
            pii_type TEXT,
            source TEXT
        )
    """)

    conn.commit()
    conn.close()


def validate_password(password: str) -> bool:
    """Check if password meets complexity rules"""
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):  # uppercase
        return False
    if not re.search(r"[a-z]", password):  # lowercase
        return False
    if not re.search(r"\d", password):     # digit
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):  # special char
        return False
    return True


DB_FILE = "pii_data.db"

def get_all_users():
    conn = sqlite3.connect("pii_data.db")
    cur = conn.cursor()
    cur.execute("SELECT username, role FROM users ORDER BY username")
    users = cur.fetchall()
    conn.close()
    return users


def delete_user(user_name: str):
    conn = sqlite3.connect("pii_data.db")
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE username=?", (user_name,))
    conn.commit()
    conn.close()


def reset_password(user_name: str, new_password: str):
    from argon2 import PasswordHasher
    ph = PasswordHasher()
    hashed = ph.hash(new_password)

    conn = sqlite3.connect("pii_data.db")
    cur = conn.cursor()
    cur.execute("UPDATE users SET password_hash=? WHERE username=?", (hashed, user_name))
    conn.commit()
    conn.close()


def create_user(username: str, password: str, role: str = "user"):
    if not validate_password(password):
        raise ValueError("Password does not meet complexity requirements")
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    password_hash = argon2.hash(password)
    cur.execute(
        "INSERT OR REPLACE INTO users (username, password_hash, role) VALUES (?, ?, ?)",
        (username, password_hash, role)
    )
    conn.commit()
    conn.close()

def authenticate_user(username: str, password: str) -> bool:
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT password_hash FROM users WHERE username=?", (username,))
    row = cur.fetchone()
    conn.close()
    return row is not None and argon2.verify(password, row[0])

def is_admin_user(username: str) -> bool:
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT role FROM users WHERE username=?", (username,))
    row = cur.fetchone()
    conn.close()
    return row is not None and row[0] == "admin"
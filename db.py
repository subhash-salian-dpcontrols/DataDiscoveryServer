# db.py
import os
import psycopg2
import re
from passlib.hash import argon2
from dotenv import load_dotenv

load_dotenv()

from psycopg2 import pool

# Create a thread-safe connection pool
connection_pool = None

def init_connection_pool():
    global connection_pool
    try:
        # First try to use DATABASE_URL (Heroku)
        database_url = os.getenv('DATABASE_URL')
        if database_url:
            # Heroku's DATABASE_URL starts with postgres://, but psycopg2 expects postgresql://
            if database_url.startswith('postgres://'):
                database_url = database_url.replace('postgres://', 'postgresql://', 1)
            
            connection_pool = pool.SimpleConnectionPool(
                1, 20,  # min connections, max connections
                database_url
            )
        else:
            # Fallback to individual configuration variables
            connection_pool = pool.SimpleConnectionPool(
                1, 20,  # min connections, max connections
                dbname=os.getenv("POSTGRES_DB", "pii_data"),
                user=os.getenv("POSTGRES_USER", "postgres"),
                password=os.getenv("POSTGRES_PASSWORD", ""),
                host=os.getenv("POSTGRES_HOST", "localhost"),
                port=os.getenv("POSTGRES_PORT", "5432")
            )
        return True
    except Exception as e:
        print(f"Error creating connection pool: {str(e)}")
        return False

def get_db_connection():
    global connection_pool
    if connection_pool is None:
        init_connection_pool()
    return connection_pool.getconn()

def return_db_connection(conn):
    global connection_pool
    if connection_pool is not None:
        connection_pool.putconn(conn)

def insert_sample_data():
    try:
        print("Inserting sample data...")
        conn = get_db_connection()
        cur = conn.cursor()

        # Check if data already exists
        cur.execute("SELECT COUNT(*) FROM pii_results")
        count = cur.fetchone()[0]
        
        if count == 0:
            # Sample data with various PII types and sources
            sample_data = [
                ("server1.example.com", "/var/log/app.log", "email", "log_analysis", "user_email", "email detected: john.doe@example.com"),
                ("server1.example.com", "/home/user/documents/report.pdf", "phone", "document_scan", "contact", "phone number found: +1-555-0123"),
                ("server2.example.com", "/data/customer/info.xlsx", "credit_card", "database_scan", "payment_info", "credit card pattern detected"),
                ("server2.example.com", "/usr/local/data/records.csv", "pan", "file_scan", "id_column", "PAN number detected in records"),
                ("server3.example.com", "/opt/data/forms/kyc.pdf", "aadhaar", "form_analysis", "id_proof", "Aadhaar number detected"),
                ("server3.example.com", "/var/www/uploads/user_data.json", "email", "web_scan", "contact_info", "multiple email addresses found"),
                ("server4.example.com", "/home/admin/backups/users.db", "phone", "backup_scan", "phone_field", "phone numbers in backup"),
                ("server4.example.com", "/etc/config/settings.yml", "credit_card", "config_scan", "api_data", "encrypted credit card data"),
                ("server5.example.com", "/var/log/transactions.log", "pan", "log_scan", "transaction_id", "PAN in transaction logs"),
                ("server5.example.com", "/data/archive/2025/records.txt", "aadhaar", "archive_scan", "customer_id", "Aadhaar numbers in archive")
            ]

            cur.executemany("""
                INSERT INTO pii_results (hostname, file_path, pii_type, source, column_name, detected)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, sample_data)

            conn.commit()
            print(f"Inserted {len(sample_data)} sample records")
        else:
            print("Sample data already exists, skipping insertion")

        return_db_connection(conn)
    except Exception as e:
        print(f"Error inserting sample data: {str(e)}")
        if conn:
            return_db_connection(conn)
        raise

def init_db():
    try:
        print("Initializing connection pool...")
        if not init_connection_pool():
            raise Exception("Failed to initialize connection pool")

        print("Attempting to connect to database...")
        conn = get_db_connection()
        cur = conn.cursor()
        print("Successfully connected to database")

        print("Creating users table...")
        # Create users table if not exists
        cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
        )
        """)
        print("Users table created successfully")

        
        # Create the table with the correct schema
        cur.execute("""
            CREATE TABLE IF NOT EXISTS pii_results (
                id SERIAL PRIMARY KEY,
                hostname TEXT,
                source TEXT,
                column_name TEXT,
                detected TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        print("PII results table created successfully")

        conn.commit()
        return_db_connection(conn)
        print("Database initialization completed successfully")

        # Insert sample data
        #insert_sample_data()

    except Exception as e:
        print(f"Error initializing database: {str(e)}")
        raise


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
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT username, role FROM users ORDER BY username")
    users = cur.fetchall()
    conn.close()
    return users


def delete_user(user_name: str):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE username=%s", (user_name,))
    conn.commit()
    conn.close()


def reset_password(user_name: str, new_password: str):
    from argon2 import PasswordHasher
    ph = PasswordHasher()
    hashed = ph.hash(new_password)

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE users SET password_hash=%s WHERE username=%s", (hashed, user_name))
    conn.commit()
    conn.close()


def create_user(username: str, password: str, role: str = "user"):
    if not validate_password(password):
        raise ValueError("Password does not meet complexity requirements")
    conn = get_db_connection()
    cur = conn.cursor()
    password_hash = argon2.hash(password)
    cur.execute(
        """
        INSERT INTO users (username, password_hash, role) 
        VALUES (%s, %s, %s)
        ON CONFLICT (username) DO UPDATE 
        SET password_hash = EXCLUDED.password_hash,
            role = EXCLUDED.role
        """,
        (username, password_hash, role)
    )
    conn.commit()
    conn.close()

def authenticate_user(username: str, password: str) -> bool:
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT password_hash FROM users WHERE username=%s", (username,))
    row = cur.fetchone()
    conn.close()
    return row is not None and argon2.verify(password, row[0])

def is_admin_user(username: str) -> bool:
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT role FROM users WHERE username=%s", (username,))
    row = cur.fetchone()
    conn.close()
    return row is not None and row[0] == "admin"
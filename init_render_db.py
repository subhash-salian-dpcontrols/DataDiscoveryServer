from db import init_db, create_user, get_db_connection
import psycopg2
from datetime import datetime, timedelta

def insert_sample_data():
    print("Inserting sample data...")
    conn = get_db_connection()
    cur = conn.cursor()

    try:
        # Check if data already exists
        cur.execute("SELECT COUNT(*) FROM pii_results")
        count = cur.fetchone()[0]
        
        if count == 0:
            # Sample data with various PII types and sources
            sample_data = [
                ("server1.example.com", "/var/log/app.log", "email", "log_analysis", "user_email", "email detected: john.doe@example.com", datetime.now() - timedelta(days=5)),
                ("server1.example.com", "/home/user/documents/report.pdf", "phone", "document_scan", "contact", "phone number found: +1-555-0123", datetime.now() - timedelta(days=4)),
                ("server2.example.com", "/data/customer/info.xlsx", "credit_card", "database_scan", "payment_info", "credit card pattern detected", datetime.now() - timedelta(days=3)),
                ("server2.example.com", "/usr/local/data/records.csv", "pan", "file_scan", "id_column", "PAN number detected in records", datetime.now() - timedelta(days=2)),
                ("server3.example.com", "/opt/data/forms/kyc.pdf", "aadhaar", "form_analysis", "id_proof", "Aadhaar number detected", datetime.now() - timedelta(days=1)),
                ("server3.example.com", "/var/www/uploads/user_data.json", "email", "web_scan", "contact_info", "multiple email addresses found", datetime.now()),
                ("server4.example.com", "/home/admin/backups/users.db", "phone", "backup_scan", "phone_field", "phone numbers in backup", datetime.now()),
                ("server4.example.com", "/etc/config/settings.yml", "credit_card", "config_scan", "api_data", "encrypted credit card data", datetime.now()),
                ("server5.example.com", "/var/log/transactions.log", "pan", "log_scan", "transaction_id", "PAN in transaction logs", datetime.now()),
                ("server5.example.com", "/data/archive/2025/records.txt", "aadhaar", "archive_scan", "customer_id", "Aadhaar numbers in archive", datetime.now())
            ]

            cur.executemany("""
                INSERT INTO pii_results (hostname, file_path, pii_type, source, column_name, detected, timestamp)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, sample_data)

            conn.commit()
            print(f"Inserted {len(sample_data)} sample records")
        else:
            print("Sample data already exists, skipping insertion")

    except Exception as e:
        print(f"Error inserting sample data: {str(e)}")
        conn.rollback()
    finally:
        cur.close()
        conn.close()

def main():
    try:
        print("Initializing database...")
        init_db()
        print("Creating admin user...")
        #create_user('Admin', 'Admin@123', 'admin')
        print("Inserting sample data...")
        insert_sample_data()
        print("Database initialization completed successfully!")
    except Exception as e:
        print(f"Error during database initialization: {str(e)}")

if __name__ == "__main__":
    main()
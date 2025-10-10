import sqlite3
conn = sqlite3.connect("pii_data.db")
cur = conn.cursor()
cur.execute("SELECT username, role FROM users")
print(cur.fetchall())
conn.close()
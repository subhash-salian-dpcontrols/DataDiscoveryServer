from db import init_db, create_user
init_db()
create_user("admin", "Admin@123", "admin")
print("✅ Admin user created: username=admin, password=Admin@123")

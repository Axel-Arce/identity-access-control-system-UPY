import sqlite3

DB_NAME = "users.db"

def initialize_database():
    """Initializes the SQLite database and creates the users table if it does not exist."""
    connection = sqlite3.connect(DB_NAME)
    cursor = connection.cursor()

    # Create the users table schema
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            role TEXT NOT NULL,
            camera_ip TEXT NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')

    connection.commit()
    connection.close()
    print("[INFO] Database initialized successfully.")

def seed_users():
    """Populates the database with initial dummy users for testing."""
    sample_users = [
        ("Admin User", "admin@example.com", "Admin", "192.168.1.100", "placeholder_hash_admin"),
        ("Operator User", "operator@example.com", "Operator", "192.168.1.101", "placeholder_hash_operator"),
        ("Viewer User", "viewer@example.com", "Viewer", "192.168.1.102", "placeholder_hash_viewer")
    ]

    connection = sqlite3.connect(DB_NAME)
    cursor = connection.cursor()

    for user in sample_users:
        try:
            cursor.execute('''
                INSERT INTO users (name, email, role, camera_ip, password_hash)
                VALUES (?, ?, ?, ?, ?)
            ''', user)
        except sqlite3.IntegrityError:
            # Skip insertion if email already exists
            pass

    connection.commit()
    connection.close()
    print("[INFO] Initial users seeded successfully.")

def fetch_all_users():
    """Retrieves and displays all registered users from the database."""
    connection = sqlite3.connect(DB_NAME)
    cursor = connection.cursor()

    cursor.execute("SELECT id, name, email, role, camera_ip, password_hash FROM users")
    rows = cursor.fetchall()

    print("\n--- Registered Users in Database ---")
    for row in rows:
        print(f"ID: {row[0]} | Name: {row[1]} | Email: {row[2]} | Role: {row[3]} | Camera IP: {row[4]} | Hash: {row[5]}")

    connection.close()

if __name__ == "__main__":
    initialize_database()
    seed_users()
    fetch_all_users()
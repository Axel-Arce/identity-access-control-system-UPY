import hashlib
import sqlite3

DB_NAME = "users.db"

def hash_password(password):
    #Hashes a plaintext password using SHA-256.
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def verify_credentials(email, password) -> dict | None:
    """
    Verifies user credentials against the database.
    Returns user details dict if valid, otherwise None.
    """
    hashed_input = hash_password(password)

    connection = sqlite3.connect(DB_NAME)
    cursor = connection.cursor()

    # Query user by email and matching password hash
    cursor.execute('''
        SELECT id, name, email, role, camera_ip, password_hash
        FROM users
        WHERE email = ? AND password_hash = ?
    ''', (email, hashed_input))

    user_row = cursor.fetchone()
    connection.close()

    if user_row:
        return {
            "id": user_row[0],
            "name": user_row[1],
            "email": user_row[2],
            "role": user_row[3],
            "camera_ip": user_row[4]
        }
    return None

def login_prompt():
    #CLI Prompt for user authentication.
    print("\n=== SYSTEM LOGIN ===")
    email = input("User (Email): ").strip()
    password = input("Password: ").strip()

    user = verify_credentials(email, password)

    if user:
        print(f"\n[SUCCESS] Authentication successful. Welcome, {user['name']}!")
        print(f"[INFO] Assigned Role: {user['role']}")
        return user
    else:
        print("\n[ERROR] Authentication failed. Invalid email or password.")
        return None

if __name__ == "__main__":
    login_prompt()
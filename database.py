import hashlib
import os

import psycopg2
import psycopg2.errors
from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
FERNET_PHONE_KEY = os.getenv("FERNET_PHONE_KEY")

def get_connection():
    """Opens a new connection to the shared Postgres (Supabase) database."""
    return psycopg2.connect(DATABASE_URL, sslmode="require")

def hash_password(password: str) -> str:
    """Hashes a plaintext password using SHA-256."""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def encrypt_phone(phone_number: str) -> str:
    """Encrypts a phone number (E.164 format) with the shared Fernet key."""
    fernet = Fernet(FERNET_PHONE_KEY.encode('utf-8'))
    return fernet.encrypt(phone_number.encode('utf-8')).decode('utf-8')

def initialize_database():
    #Creates the users table in the shared database if it does not exist.
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            role TEXT NOT NULL,
            camera_ip TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            phone_encrypted TEXT
        )
    ''')

    connection.commit()
    connection.close()
    print("[INFO] Database initialized successfully.")

def seed_users():
    #Populates the database with initial users with hashed passwords and encrypted phone numbers.
    sample_users = [
        ("Admin User", "admin@example.com", "Admin", "192.168.1.100", hash_password("Admin123!"), encrypt_phone("+529851221486")),
        ("Operator User", "operator@example.com", "Operator", "192.168.1.101", hash_password("Operator123!"), encrypt_phone("+10000000002")),
        ("Viewer User", "viewer@example.com", "Viewer", "192.168.1.102", hash_password("Viewer123!"), encrypt_phone("+10000000003"))
    ]

    connection = get_connection()
    cursor = connection.cursor()

    for name, email, role, camera_ip, password_hash, phone_encrypted in sample_users:
        try:
            cursor.execute('''
                INSERT INTO users (name, email, role, camera_ip, password_hash, phone_encrypted)
                VALUES (%s, %s, %s, %s, %s, %s)
            ''', (name, email, role, camera_ip, password_hash, phone_encrypted))
        except psycopg2.errors.UniqueViolation:
            # User already exists (e.g. migrated from an older schema); backfill the phone if missing
            connection.rollback()
            cursor.execute('''
                UPDATE users SET phone_encrypted = %s
                WHERE email = %s AND phone_encrypted IS NULL
            ''', (phone_encrypted, email))

    connection.commit()
    connection.close()
    print("[INFO] Initial users seeded successfully.")

def create_user(name: str, email: str, role: str, camera_ip: str, password: str, phone_number: str) -> bool:
    """Registers a new user. Returns True on success, False if the email already exists."""
    connection = get_connection()
    cursor = connection.cursor()

    try:
        cursor.execute('''
            INSERT INTO users (name, email, role, camera_ip, password_hash, phone_encrypted)
            VALUES (%s, %s, %s, %s, %s, %s)
        ''', (name, email, role, camera_ip, hash_password(password), encrypt_phone(phone_number)))
        connection.commit()
        print(f"[INFO] User '{email}' created successfully.")
        return True
    except psycopg2.errors.UniqueViolation:
        connection.rollback()
        print(f"[ERROR] A user with email '{email}' already exists.")
        return False
    finally:
        connection.close()

def get_user_by_email(email: str) -> dict | None:
    """Fetches a single user's non-sensitive fields by email."""
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT id, name, email, role, camera_ip FROM users WHERE email = %s", (email,))
    row = cursor.fetchone()
    connection.close()

    if row is None:
        return None
    return {"id": row[0], "name": row[1], "email": row[2], "role": row[3], "camera_ip": row[4]}

def update_user_phone(email: str, phone_number: str) -> bool:
    """Encrypts and sets/updates a user's phone number (E.164 format, e.g. +5215512345678)."""
    return _update_user_field(email, "phone_encrypted", encrypt_phone(phone_number), "Phone number")

def update_user_password(email: str, new_password: str) -> bool:
    """Hashes and sets/updates a user's password."""
    return _update_user_field(email, "password_hash", hash_password(new_password), "Password")

def update_user_role(email: str, new_role: str) -> bool:
    """Sets/updates a user's role."""
    return _update_user_field(email, "role", new_role, "Role")

def update_user_camera_ip(email: str, new_camera_ip: str) -> bool:
    """Sets/updates a user's assigned camera IP."""
    return _update_user_field(email, "camera_ip", new_camera_ip, "Camera IP")

def update_user_name(email: str, new_name: str) -> bool:
    """Sets/updates a user's display name."""
    return _update_user_field(email, "name", new_name, "Name")

def _update_user_field(email: str, column: str, value: str, label: str) -> bool:
    #Internal helper: overwrites a single column for the user matching the given email.
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(f"UPDATE users SET {column} = %s WHERE email = %s", (value, email))
    updated = cursor.rowcount > 0

    if updated:
        print(f"[INFO] {label} updated for {email}.")
    else:
        print(f"[WARN] No user found with email: {email}")

    connection.commit()
    connection.close()
    return updated

def fetch_all_users():
    #Retrieves and displays all registered users from the database.
    connection = get_connection()
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
"""
Interactive CLI script to register a new user in the database.
"""

import database

def register_prompt():
    print("\n=== REGISTER NEW USER ===")
    database.initialize_database()

    name = input("Full name: ").strip()
    email = input("Email: ").strip()
    role = input("Role (Admin / Operator / Viewer): ").strip()
    camera_ip = input("Assigned camera IP: ").strip()
    password = input("Password: ").strip()
    phone_number = input("Phone number (E.164 format, e.g. +5215512345678): ").strip()

    if not all([name, email, role, camera_ip, password, phone_number]):
        print("\n[ERROR] All fields are required.")
        return

    if not phone_number.startswith("+"):
        print("\n[ERROR] Phone number must be in E.164 format (start with '+' and country code).")
        return

    database.create_user(name, email, role, camera_ip, password, phone_number)

if __name__ == "__main__":
    register_prompt()

"""
Interactive CLI script to update an existing user's data in the database.
"""

import database

FIELD_MENU = {
    "1": ("Name", database.update_user_name, "New name: "),
    "2": ("Role", database.update_user_role, "New role (Admin / Operator / Viewer): "),
    "3": ("Camera IP", database.update_user_camera_ip, "New camera IP: "),
    "4": ("Password", database.update_user_password, "New password: "),
    "5": ("Phone number", database.update_user_phone, "New phone number (E.164 format, e.g. +5215512345678): "),
}

def update_prompt():
    print("\n=== UPDATE EXISTING USER ===")
    email = input("Email of the user to update: ").strip()

    user = database.get_user_by_email(email)
    if user is None:
        print(f"\n[ERROR] No user found with email: {email}")
        return

    print(f"\nFound user: {user['name']} | Role: {user['role']} | Camera IP: {user['camera_ip']}")
    print("\nWhat do you want to update?")
    for key, (label, _, _) in FIELD_MENU.items():
        print(f"  {key}. {label}")

    choice = input("Option: ").strip()
    if choice not in FIELD_MENU:
        print("\n[ERROR] Invalid option.")
        return

    label, update_fn, prompt_text = FIELD_MENU[choice]
    new_value = input(prompt_text).strip()

    if not new_value:
        print(f"\n[ERROR] {label} cannot be empty.")
        return

    if choice == "5" and not new_value.startswith("+"):
        print("\n[ERROR] Phone number must be in E.164 format (start with '+' and country code).")
        return

    update_fn(email, new_value)

if __name__ == "__main__":
    update_prompt()

import hashlib
import sqlite3

DB_NAME = "users.db"

def hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def demostrate_hashing_process(sample_password):
    print("\n=== MODULE 3: PASSWORD HASHING DEMONSTRATION ===")
    print(f"[1] Original Plaintext Password: '{sample_password}'")

    password_hash = hash_password(sample_password)
    print(f"[2] SHA-256 Calculated Hash    : {password_hash}")

    connection = sqlite3.connect(DB_NAME)
    cursor = connection.cursor()
    cursor.execute("SELECT email, password_hash FROM users LIMIT 1")
    row = cursor.fetchone()
    connection.close()

    if row:
        user_email, stored_hash = row
        print(f"\n[3] Database Sample Entry ({user_email}):")
        print(f"    Stored Password Hash       : {stored_hash}")

        if password_hash == stored_hash:
            print("[STATUS] MATCH: Password matches stored hash.")
        else:
            print("[STATUS] MISMATCH: Passwords do not match.")

if __name__ == "__main__":
    test_pwd = input("Enter a password to test hashing: ").strip()
    if not test_pwd:
        test_pwd = "Admin123!"
    demostrate_hashing_process(test_pwd)
import hashlib
import os
import random
import smtplib
import time
from email.mime.text import MIMEText

import psycopg2
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
SMTP_SENDER   = os.getenv("SMTP_SENDER")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")

MAX_ATTEMPTS = 3
CODE_EXPIRY  = 300  # seconds

def hash_password(password):
    #Hashes a plaintext password using SHA-256.
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def verify_credentials(email, password) -> dict | None:
    """
    Verifies user credentials against the database.
    Returns user details dict if valid, otherwise None.
    """
    hashed_input = hash_password(password)

    connection = psycopg2.connect(DATABASE_URL, sslmode="require")
    cursor = connection.cursor()

    cursor.execute('''
        SELECT id, name, email, role, camera_ip
        FROM users
        WHERE email = %s AND password_hash = %s
    ''', (email, hashed_input))

    user_row = cursor.fetchone()
    connection.close()

    if user_row:
        return {
            "id":        user_row[0],
            "name":      user_row[1],
            "email":     user_row[2],
            "role":      user_row[3],
            "camera_ip": user_row[4],
        }
    return None

def send_otp_email(recipient_email, code):
    #Sends a 6-digit OTP code to the user's registered email via Gmail SMTP.
    try:
        msg = MIMEText(
            f"Your verification code is: {code}\n\n"
            f"This code expires in {CODE_EXPIRY // 60} minutes.\n"
            f"If you did not request this, please ignore this email."
        )
        msg["Subject"] = f"Verification Code: {code}"
        msg["From"]    = SMTP_SENDER
        msg["To"]      = recipient_email

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(SMTP_SENDER, SMTP_PASSWORD)
            server.sendmail(SMTP_SENDER, recipient_email, msg.as_string())

        print(f"\n[MFA] Verification code sent to {recipient_email}")
        return True
    except Exception as error:
        print(f"[ERROR] Could not send email: {error}")
        return False

def login_prompt():
    #CLI Prompt for user authentication with email-based 2FA.
    print("\n=== SYSTEM LOGIN ===")
    email    = input("User (Email): ").strip()
    password = input("Password: ").strip()

    user = verify_credentials(email, password)

    if not user:
        print("\n[ERROR] Authentication failed. Invalid email or password.")
        return None

    print(f"\n[SUCCESS] Password verified. Welcome, {user['name']}!")

    code         = random.randint(100000, 999999)
    generated_at = time.time()

    if not send_otp_email(email, code):
        print("[ERROR] Could not send the 2FA code. Access denied.")
        return None

    attempts = 0
    while attempts < MAX_ATTEMPTS:
        if time.time() - generated_at > CODE_EXPIRY:
            print("\n[ACCESS DENIED] Verification code expired.")
            return None

        entered = input("Enter the 6-digit code sent to your email: ").strip()

        if entered.isdigit() and int(entered) == code:
            print("\n[SUCCESS] Two-factor authentication complete.")
            print(f"[INFO] Assigned Role: {user['role']}")
            return user

        attempts += 1
        print(f"[ERROR] Incorrect code. Attempt {attempts}/{MAX_ATTEMPTS}.")

    print("\n[ACCESS DENIED] Too many incorrect attempts.")
    return None

if __name__ == "__main__":
    login_prompt()

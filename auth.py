import hashlib
import os
import sqlite3

from cryptography.fernet import Fernet
from dotenv import load_dotenv
from twilio.rest import Client
from twilio.base.exceptions import TwilioRestException

load_dotenv()

DB_NAME = "users.db"

TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
TWILIO_VERIFY_SERVICE_SID = os.getenv("TWILIO_VERIFY_SERVICE_SID")
FERNET_PHONE_KEY = os.getenv("FERNET_PHONE_KEY")

twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

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
        SELECT id, name, email, role, camera_ip, phone_encrypted
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
            "camera_ip": user_row[4],
            "phone_encrypted": user_row[5]
        }
    return None

def decrypt_phone(phone_encrypted: str) -> str:
    #Decrypts a user's phone number stored in the database.
    fernet = Fernet(FERNET_PHONE_KEY.encode('utf-8'))
    return fernet.decrypt(phone_encrypted.encode('utf-8')).decode('utf-8')

def otp_request(phone_number) -> bool:
    #Sends a one-time SMS verification code via Twilio Verify.
    try:
        print(f"\n[MFA] Sending verification code via SMS to {phone_number}")
        twilio_client.verify.v2.services(TWILIO_VERIFY_SERVICE_SID).verifications.create(
            to=phone_number, channel='sms'
        )
        return True
    except TwilioRestException as error:
        print(f"[ERROR] Twilio send error (code: {error.code}): {error.msg}")
        return False

def otp_verification(phone_number, entered_code) -> bool:
    #Validates the code entered by the user against Twilio Verify.
    try:
        check = twilio_client.verify.v2.services(TWILIO_VERIFY_SERVICE_SID).verification_checks.create(
            to=phone_number, code=entered_code
        )
        if check.status == "approved":
            return True
        print(f"[ERROR] Incorrect or expired code (status: {check.status})")
        return False
    except TwilioRestException as error:
        print(f"[ERROR] Verification error ({error.code}): {error.msg}")
        return False

def login_prompt():
    #CLI Prompt for user authentication with Twilio 2FA.
    print("\n=== SYSTEM LOGIN ===")
    email = input("User (Email): ").strip()
    password = input("Password: ").strip()

    user = verify_credentials(email, password)

    if not user:
        print("\n[ERROR] Authentication failed. Invalid email or password.")
        return None

    print(f"\n[SUCCESS] Password verified. Welcome, {user['name']}!")

    if not user.get("phone_encrypted"):
        print("[ERROR] No phone number registered for 2FA. Access denied.")
        return None

    try:
        phone_number = decrypt_phone(user["phone_encrypted"])
    except Exception as error:
        print(f"[ERROR] Could not decrypt registered phone number: {error}")
        return None

    if not otp_request(phone_number):
        print("[ERROR] Could not send the 2FA code. Access denied.")
        return None

    otp_code = input("Enter the 6-digit code sent to your phone: ").strip()

    if not otp_verification(phone_number, otp_code):
        print("\n[ACCESS DENIED] Incorrect or expired 2FA code.")
        return None

    print("\n[SUCCESS] Two-factor authentication complete.")
    print(f"[INFO] Assigned Role: {user['role']}")
    return user

if __name__ == "__main__":
    login_prompt()

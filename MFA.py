
import os
import sys
import time
import json
import base64
import hmac
import hashlib
import requests
from dotenv import load_dotenv
from twilio.rest import Client
from twilio.base.exceptions import TwilioRestException
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.exceptions import InvalidSignature
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# =====================================================================
# CARGA DE VARIABLES DE ENTORNO Y CONFIGURACIÓN TWILIO
# =====================================================================
load_dotenv()

ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
VERIFY_SERVICE_SID = os.getenv("TWILIO_VERIFY_SERVICE_SID")

FERNET_PHONE_KEY = os.getenv("FERNET_PHONE_KEY")
REGISTRED_PHONE = os.getenv("REGISTRED_PHONE")

client = Client(ACCOUNT_SID, AUTH_TOKEN)

# =====================================================================
# [MÓDULO 1]: PASSWORD SECURITY (Argon2 + Check Filtraciones)
# =====================================================================
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)

def is_password_leaked(password: str) -> bool:
    """Verifica si la contraseña ha sido filtrada usando k-Anonymity (HIBP API)"""
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]
    try:
        res = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=5)
        if res.status_code == 200:
            hashes_list = (line.split(":") for line in res.text.splitlines())
            for response_suffix, count in hashes_list:
                if response_suffix == suffix:
                    print(f" Alerta: Contraseña filtrada {count} veces en bases de datos públicas.")
                    return True
    except requests.RequestException:
        pass
    return False

# Base de datos simulada del usuario 
user = "admin"
raw_password = "UPY2026_ICA"

hashed_password_db = ph.hash(raw_password) 

# Utilizamos un par de llaves RSA tanto para firmas (Identidad) como para Cifrado Híbrido (Datos)
rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
rsa_public_key = rsa_private_key.public_key()

class UserProfile:
    def __init__(self, username, role):
        self.username = username
        self.role = role
        self.checksum = hashlib.sha256(f"{username}|{role}".encode('utf-8')).hexdigest()
    
    def sign_profile(self, priv_key):
        """Firma el checksum del perfil con RSA para garantizar Autenticidad"""
        return priv_key.sign(
            self.checksum.encode('utf-8'),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )

# Instanciamos el perfil y lo firmamos
profile = UserProfile(user, "Administrator")
profile_signature = profile.sign_profile(rsa_private_key)


class JWTManager:
    def __init__(self, secret_key: bytes):
        self.secret_key = secret_key

    def _b64_encode(self, data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

    def generate_token(self, payload: dict, ttl=300) -> str:
        header = {"alg": "HS256", "typ": "JWT"}
        payload_copy = payload.copy()
        payload_copy["exp"] = int(time.time()) + ttl
        
        h_b64 = self._b64_encode(json.dumps(header).encode('utf-8'))
        p_b64 = self._b64_encode(json.dumps(payload_copy).encode('utf-8'))
        
        signature = hmac.new(self.secret_key, f"{h_b64}.{p_b64}".encode('utf-8'), hashlib.sha256).digest()
        s_b64 = self._b64_encode(signature)
        return f"{h_b64}.{p_b64}.{s_b64}"

jwt_secret = os.urandom(32)
jwt_manager = JWTManager(jwt_secret)


class AuditLogger:
    def __init__(self, master_secret: bytes):
        self.logs = []
        self.last_hash = "0" * 64
        self.master_secret = master_secret

    def log_event(self, action: str, username: str, status: str):
        event = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "action": action, "username": username, "status": status,
            "prev_hash": self.last_hash
        }
        serialized = json.dumps(event, sort_keys=True)
        current_hash = hashlib.sha256(serialized.encode('utf-8')).hexdigest()
        event["current_hash"] = current_hash
        self.last_hash = current_hash
        self.logs.append(event)
        
    def generate_seal(self):
        return hmac.new(self.master_secret, json.dumps(self.logs, sort_keys=True).encode('utf-8'), hashlib.sha256).hexdigest()

logger = AuditLogger(os.urandom(32))


simulated_data = "Financial_report.xml"
session_key = Fernet.generate_key()
fernet_encrypter = Fernet(session_key)
encrypted_data = fernet_encrypter.encrypt(simulated_data.encode('utf-8'))

rsa_session_key = rsa_public_key.encrypt(
    session_key,
    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
)


def get_phone():
    encrypted_phone = Fernet(FERNET_PHONE_KEY.encode('utf-8'))
    phone = encrypted_phone.decrypt(REGISTRED_PHONE.encode('utf-8'))
    return phone.decode('utf-8')

def otp_request(phone_number):
    try:
        print(f"\n[MÓDULO 3] Requesting OTP delivery via SMS to {phone_number}")
        verification = client.verify.v2.services(VERIFY_SERVICE_SID).verifications.create(to=phone_number, channel='sms')
        return True
    except TwilioRestException as error:
        print(f"Twilio send error (code: {error.code}): {error.msg}")
        return False

def otp_verification(phone_number, entered_code):
    try:
        print(f"[MÓDULO 3] Validating code '{entered_code}' with Twilio...")
        verification_check = client.verify.v2.services(VERIFY_SERVICE_SID).verification_checks.create(to=phone_number, code=entered_code)
        if verification_check.status == "approved":
            return True
        else:
            print(f"Incorrect or expired code (state: {verification_check.status})")
            return False
    except TwilioRestException as error:
        print(f"Verification error ({error.code}): {error.msg}")
        return False

# =====================================================================
# FLUJO PRINCIPAL DEL SISTEMA (Integración Final)
# =====================================================================
def start_system():
    print("\n" + "="*60)
    print(" INTEGRATED SECURE IDENTITY MANAGEMENT SYSTEM")
    print("="*60)

    # Revisamos seguridad de contraseña al iniciar (Módulo 1)
    is_password_leaked(raw_password)

    usr_input = input("Enter your username: ").strip()
    if usr_input != user:
        print("The user does not exist.")
        logger.log_event("LOGIN_ATTEMPT", usr_input, "FAILED_USER_NOT_FOUND")
        return

    # Límite de 3 Intentos + Hashing Argon2
    Max_attemps = 3
    autenticated = False

    for attempt in range(1, Max_attemps + 1):
        usr_psw = input("Enter your access password: ")
        
        try:
            # Módulo 1: Verificamos contra el hash de Argon2
            ph.verify(hashed_password_db, usr_psw)
            print(" Correct Password (Verified via Argon2id)")
            autenticated = True
            logger.log_event("LOGIN_PASSWORD", usr_input, "SUCCESS")
            break
        except VerifyMismatchError:
            attemps_left = Max_attemps - attempt
            if attemps_left > 0:
                print(f" Incorrect password. You have {attemps_left} attempt(s) left.")
            else:
                print("\n [SECURITY LOCKOUT]: You have exceeded the limit of 3 failed attempts.")
                print("The program will close for protection.")
                logger.log_event("LOGIN_PASSWORD", usr_input, "LOCKED_OUT")
                sys.exit()

    # Disparo de Twilio (Módulo 3)
    try:
        usr_phone = get_phone()
    except Exception as error:
        print(f"The phone number could not be deciphered: {error}")
        return

    if not otp_request(usr_phone):
        print("The 2FA could not be processed.")
        logger.log_event("2FA_REQUEST", usr_input, "FAILED")
        return
    logger.log_event("2FA_REQUEST", usr_input, "SUCCESS")

    otp_code = input(" Enter the 6-digit code sent to your phone: ").strip()

    if not otp_verification(usr_phone, otp_code):
        print(" [ACCESS DENIED]: Incorrect or expired 2FA code.")
        logger.log_event("2FA_VERIFY", usr_input, "FAILED")
        return
    
    print(" Successful two-factor authentication.")
    logger.log_event("2FA_VERIFY", usr_input, "SUCCESS")

    # Módulo 4: Emisión de Token de Sesión JWT
    token = jwt_manager.generate_token({"sub": profile.username, "role": profile.role})
    print(f"\nSession JWT Token Issued:\n{token}")
    logger.log_event("JWT_ISSUED", usr_input, "SUCCESS")

    # Módulo 2: Verificamos Integridad de Identidad mediante Firma Digital RSA antes de dar acceso
    print("\nVerifying Digital Identity Signature...")
    try:
        rsa_public_key.verify(
            profile_signature,
            profile.checksum.encode('utf-8'),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        print("Identity verified successfully. No tampering detected.")
    except InvalidSignature:
        print("Identity signature verification failed!")
        return

    # Descifrado Híbrido Final (El error anterior `simulated_data` fue arreglado a `encrypted_data`)
    print("\nUnlocking encrypted data vault...")
    recovered_session_key = rsa_private_key.decrypt(
        rsa_session_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    encryption_decryption = Fernet(recovered_session_key)
    
    # CORRECCIÓN DE BUG: Aquí desciframos la variable correcta
    revealed_data = encryption_decryption.decrypt(encrypted_data).decode('utf-8')
    print(f"\nPROTECTED REPORT OBTAINED: '{revealed_data}'")
    
    logger.log_event("DATA_VAULT_ACCESSED", usr_input, "SUCCESS")
    
    # Sello Final del Log de Auditoría (Módulo 5)
    seal = logger.generate_seal()
    print(f"\nAudit Log Sealed with HMAC: {seal[:15]}...")

if __name__ == "__main__":
    start_system()
import base64
import hashlib
import hmac
import json
import os
import sqlite3
import sys
import time
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from dotenv import load_dotenv
import requests
from twilio.base.exceptions import TwilioRestException
from twilio.rest import Client

# =====================================================================
# CONFIGURACIÓN Y VARIABLES DE ENTORNO
# =====================================================================
load_dotenv()

ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
VERIFY_SERVICE_SID = os.getenv("TWILIO_VERIFY_SERVICE_SID")
FERNET_PHONE_KEY = os.getenv("FERNET_PHONE_KEY")
REGISTRED_PHONE = os.getenv("REGISTRED_PHONE")

DB_NAME = "users.db"
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)

# =====================================================================
# INICIALIZACIÓN DE BASE DE DATOS SQLITE
# =====================================================================
def init_db():
    """Crea la base de datos sqlite e inserta un usuario por defecto si no existe."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            role TEXT NOT NULL,
            camera_ip TEXT,
            password_hash TEXT NOT NULL
        )
    ''')
    
    # Creamos/actualizamos usuario 'admin' con hash seguro Argon2id
    raw_password = "UPY2026_ICA"
    hashed = ph.hash(raw_password)
    
    cursor.execute('''
        INSERT INTO users (username, email, name, role, camera_ip, password_hash)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash
    ''', ("admin", "admin@upy.edu.mx", "Administrator", "Administrator", "192.168.1.100", hashed))
    
    conn.commit()
    conn.close()

# =====================================================================
# SEGURIDAD Y HERRAMIENTAS CRIPTOGRÁFICAS
# =====================================================================
def is_password_leaked(password: str) -> bool:
    """Verifica filtraciones de contraseñas mediante HIBP (k-Anonymity)."""
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]
    try:
        res = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=5)
        if res.status_code == 200:
            hashes_list = (line.split(":") for line in res.text.splitlines())
            for response_suffix, count in hashes_list:
                if response_suffix == suffix:
                    print(f"⚠️ Alerta: Contraseña filtrada {count} veces en bases de datos públicas.")
                    return True
    except requests.RequestException:
        pass
    return False

# Claves RSA
rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
rsa_public_key = rsa_private_key.public_key()

class UserProfile:
    def __init__(self, username: str, role: str):
        self.username = username
        self.role = role
        self.checksum = hashlib.sha256(f"{username}|{role}".encode('utf-8')).hexdigest()
    
    def sign_profile(self, priv_key):
        return priv_key.sign(
            self.checksum.encode('utf-8'),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )

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

jwt_manager = JWTManager(os.urandom(32))
logger = AuditLogger(os.urandom(32))

# Cifrado Híbrido para Bóveda de Datos
simulated_data = "Financial_report.xml"
session_key = Fernet.generate_key()
fernet_encrypter = Fernet(session_key)
encrypted_data = fernet_encrypter.encrypt(simulated_data.encode('utf-8'))

rsa_session_key = rsa_public_key.encrypt(
    session_key,
    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
)

# =====================================================================
# INTEGRACIÓN DE TELEFONÍA (TWILIO)
# =====================================================================
def get_phone():
    if not FERNET_PHONE_KEY or not REGISTRED_PHONE:
        raise ValueError("Variables de entorno para teléfono no configuradas.")
    encrypted_phone = Fernet(FERNET_PHONE_KEY.encode('utf-8'))
    phone = encrypted_phone.decrypt(REGISTRED_PHONE.encode('utf-8'))
    return phone.decode('utf-8')

def otp_request(phone_number):
    try:
        client = Client(ACCOUNT_SID, AUTH_TOKEN)
        print(f"\n[2FA] Solicitando código vía SMS a {phone_number}")
        client.verify.v2.services(VERIFY_SERVICE_SID).verifications.create(to=phone_number, channel='sms')
        return True
    except (TwilioRestException, Exception) as error:
        print(f"Error al enviar SMS: {error}")
        return False

def otp_verification(phone_number, entered_code):
    try:
        client = Client(ACCOUNT_SID, AUTH_TOKEN)
        verification_check = client.verify.v2.services(VERIFY_SERVICE_SID).verification_checks.create(to=phone_number, code=entered_code)
        return verification_check.status == "approved"
    except (TwilioRestException, Exception) as error:
        print(f"Error en validación 2FA: {error}")
        return False

# =====================================================================
# CONSULTAS A LA BASE DE DATOS
# =====================================================================
def get_user_from_db(identifier: str) -> dict | None:
    """Busca al usuario por nombre de usuario o por correo electrónico."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id, username, email, name, role, camera_ip, password_hash
        FROM users
        WHERE username = ? OR email = ?
    ''', (identifier, identifier))
    
    row = cursor.fetchone()
    conn.close()
    
    if row:
        return {
            "id": row[0],
            "username": row[1],
            "email": row[2],
            "name": row[3],
            "role": row[4],
            "camera_ip": row[5],
            "password_hash": row[6]
        }
    return None

# =====================================================================
# FLUJO PRINCIPAL DEL SISTEMA
# =====================================================================
def start_system():
    init_db()
    
    print("\n" + "="*60)
    print(" SISTEMA INTEGRADO DE GESTIÓN SEGURA DE IDENTIDAD (SQLITE + 2FA)")
    print("="*60)

    usr_input = input("Ingrese Usuario o Correo Electrónico: ").strip()
    user_record = get_user_from_db(usr_input)

    if not user_record:
        print("❌ El usuario ingresado no existe en la base de datos.")
        logger.log_event("LOGIN_ATTEMPT", usr_input, "FAILED_USER_NOT_FOUND")
        return

    username = user_record["username"]

    # Paso 1: Validación de Contraseña con Argon2
    max_attempts = 3
    authenticated = False

    for attempt in range(1, max_attempts + 1):
        usr_psw = input("Ingrese su contraseña: ").strip()
        
        # Validación opcional contra HIBP
        is_password_leaked(usr_psw)

        try:
            ph.verify(user_record["password_hash"], usr_psw)
            print("✅ Contraseña correcta (Verificada con Argon2id)")
            authenticated = True
            logger.log_event("LOGIN_PASSWORD", username, "SUCCESS")
            break
        except VerifyMismatchError:
            attempts_left = max_attempts - attempt
            if attempts_left > 0:
                print(f"❌ Contraseña incorrecta. Intentos restantes: {attempts_left}")
            else:
                print("\n⛔ [BLOQUEO DE SEGURIDAD]: Excedió el límite de 3 intentos.")
                logger.log_event("LOGIN_PASSWORD", username, "LOCKED_OUT")
                sys.exit()

    if not authenticated:
        return

    # Paso 2: Autenticación de Doble Factor (2FA) con Twilio
    try:
        usr_phone = get_phone()
    except Exception as error:
        print(f"Error al obtener el número registrado: {error}")
        return

    if not otp_request(usr_phone):
        print("No se pudo enviar el código 2FA.")
        logger.log_event("2FA_REQUEST", username, "FAILED")
        return
    logger.log_event("2FA_REQUEST", username, "SUCCESS")

    otp_code = input(" Ingrese el código de 6 dígitos recibido por SMS: ").strip()

    if not otp_verification(usr_phone, otp_code):
        print("⛔ [ACCESO DENEGADO]: Código 2FA inválido o expirado.")
        logger.log_event("2FA_VERIFY", username, "FAILED")
        return
    
    print("✅ Autenticación de dos factores completada exitosamente.")
    logger.log_event("2FA_VERIFY", username, "SUCCESS")

    # Paso 3: Emisión de Token JWT
    token = jwt_manager.generate_token({"sub": username, "role": user_record["role"]})
    print(f"\n🔑 Token JWT Emitido:\n{token}")
    logger.log_event("JWT_ISSUED", username, "SUCCESS")

    # Paso 4: Firma Digital e Integridad con RSA
    profile = UserProfile(username, user_record["role"])
    profile_signature = profile.sign_profile(rsa_private_key)

    print("\nVerificando Firma Digital de Identidad...")
    try:
        rsa_public_key.verify(
            profile_signature,
            profile.checksum.encode('utf-8'),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        print("✅ Identidad comprobada correctamente via RSA.")
    except InvalidSignature:
        print("❌ Fallo en la verificación de firma digital.")
        return

    # Paso 5: Desbloqueo del Cifrado Híbrido
    print("\nDesbloqueando bóveda de datos cifrados...")
    recovered_session_key = rsa_private_key.decrypt(
        rsa_session_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    encryption_decryption = Fernet(recovered_session_key)
    revealed_data = encryption_decryption.decrypt(encrypted_data).decode('utf-8')

    print(f"\n📂 REPORTE PROTEGIDO OBTENIDO: '{revealed_data}'")
    print(f"👤 Bienvenido, {user_record['name']} | Rol: {user_record['role']} | Cámara IP: {user_record['camera_ip']}")
    
    logger.log_event("DATA_VAULT_ACCESSED", username, "SUCCESS")

    # Paso 6: Sellado de Logs de Auditoría
    seal = logger.generate_seal()
    print(f"\n🔒 Registro de auditoría sellado con HMAC: {seal[:20]}...")

if __name__ == "__main__":
    start_system()
# Identity and Access Control Management System

A comprehensive identity management, Role-Based Access Control (RBAC), and real-time IP camera monitoring system. Developed in Python with a cybersecurity-oriented architecture, featuring sensitive data encryption in SQLite, Multi-Factor Authentication (TOTP 2FA), and secure credential hashing.

---

## Project Structure

```text
Proyecto_U1/
│
├── main.py            # Application entry point and primary user interface
├── database.py        # Controller and operations for the SQLite database (usuarios.db)
├── security.py        # Cryptographic logic (bcrypt hashing, AES encryption, TOTP generation)
├── camera.py          # IP Camera integration and streaming rendering module (OpenCV)
├── usuarios.db        # SQLite database file
├── requirements.txt   # Required Python dependencies
└── README.md          # General repository documentation
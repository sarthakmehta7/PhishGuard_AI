from pathlib import Path
import getpass
import secrets

ROOT = Path(__file__).resolve().parents[1]
env_file = ROOT / ".env"

if env_file.exists():
    print(".env already exists; leaving it unchanged.")
    raise SystemExit(0)

username = input("Admin username [admin]: ").strip() or "admin"
password = getpass.getpass("Admin password: ")
if len(password) < 12:
    raise SystemExit("Admin password must be at least 12 characters.")

secret = secrets.token_urlsafe(48)
env_file.write_text(
    "SECRET_KEY=" + secret + "\n"
    "ADMIN_USERNAME=" + username + "\n"
    "ADMIN_PASSWORD=" + password + "\n"
    "SESSION_COOKIE_SECURE=0\n"
    "FLASK_DEBUG=0\n",
    encoding="utf-8",
)
print("Created .env with a generated Flask secret.")

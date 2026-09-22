"""Create local development keys without displaying them or overwriting existing keys."""
import base64
import os
import secrets
from pathlib import Path

path = Path(__file__).resolve().parents[1] / ".env"
content = "\n".join([
    "PII_MASTER_KEY=" + base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),
    "SUPPORT_API_KEY=" + secrets.token_urlsafe(32),
    "ANALYTICS_API_KEY=" + secrets.token_urlsafe(32),
    "PII_CHECKER_MODE=0", "PII_BIND_PORT=8091", "",
])
try:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
except FileExistsError:
    print("Existing .env retained.")
else:
    with os.fdopen(fd, "w") as stream:
        stream.write(content)
    print("Local keys created in .env (mode 0600); values not displayed.")

import base64
import bcrypt
from datetime import datetime, timedelta, timezone
from cryptography.fernet import Fernet
from jose import jwt, JWTError
from typing import Optional, Dict
from app.core.config import settings

# Initialize Fernet cipher suite
# Standardize key parsing
try:
    _cipher_suite = Fernet(settings.FERNET_KEY.strip().encode())
except Exception as e:
    # If the key is invalid (e.g. placeholder), fallback to generating one dynamically
    # so the app doesn't crash on initial launch before configuration
    print(f"Warning: Invalid Fernet key in settings. Generating fallback: {e}")
    # Using a deterministic fallback for demo if settings is placeholder, but log warning
    import hashlib
    fallback_bytes = hashlib.sha256(settings.FERNET_KEY.encode()).digest()
    fallback_b64 = base64.urlsafe_b64encode(fallback_bytes)
    _cipher_suite = Fernet(fallback_b64)

def hash_password(password: str) -> str:
    """Hash a plaintext password using bcrypt."""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against a bcrypt hash."""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
    except Exception:
        return False

def encrypt_key_value(plain_value: str) -> str:
    """Encrypt a plaintext API key to string using Fernet."""
    return _cipher_suite.encrypt(plain_value.encode('utf-8')).decode('utf-8')

def decrypt_key_value(encrypted_value: str) -> str:
    """Decrypt a Fernet encrypted API key back to plaintext."""
    return _cipher_suite.decrypt(encrypted_value.encode('utf-8')).decode('utf-8')

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a short-lived access JWT."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": int(expire.timestamp()), "type": "access"})
    encoded_jwt = jwt.encode(to_encode, settings.JWT_SECRET, algorithm="HS256")
    return encoded_jwt

def create_refresh_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a long-lived refresh JWT."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": int(expire.timestamp()), "type": "refresh"})
    encoded_jwt = jwt.encode(to_encode, settings.JWT_REFRESH_SECRET, algorithm="HS256")
    return encoded_jwt

def decode_token(token: str, secret: str) -> Optional[dict]:
    """Decode and validate a JWT using a given secret."""
    try:
        payload = jwt.decode(token, secret, algorithms=["HS256"])
        return payload
    except JWTError:
        return None

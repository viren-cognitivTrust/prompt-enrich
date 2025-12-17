from datetime import datetime, timedelta, timezone
from typing import Optional
import hashlib
import re
import secrets

from jose import jwt
from passlib.context import CryptContext

from .config import get_settings


settings = get_settings()

pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=settings.PASSWORD_HASH_ROUNDS,
)

PASSWORD_MIN_LENGTH = 12
PASSWORD_POLICY_REGEX = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{%d,}$" % PASSWORD_MIN_LENGTH
)


def normalize_email(email: str) -> str:
    return email.strip().lower()


def email_to_hash(email: str) -> str:
    normalized = normalize_email(email)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def validate_password_strength(password: str) -> None:
    if not PASSWORD_POLICY_REGEX.match(password):
        raise ValueError(
            "Password must be at least 12 characters and include upper, lower, number, and symbol."
        )


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def generate_session_id() -> str:
    # 256 bits of entropy (32 bytes) url-safe
    return secrets.token_urlsafe(32)


def generate_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def create_access_token(
    subject: str,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """
    JWT access token using RS256/ES256 in production.
    For local/dev we may fall back to HS256 but this must not be used in distributed prod.
    """
    exp = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode = {"sub": subject, "exp": exp}
    # NOTE: In production, use asymmetric keys (RS256/ES256) stored in a KMS/HSM.
    encoded_jwt = jwt.encode(
        to_encode,
        settings.SECRET_KEY,
        algorithm="HS256",
    )
    return encoded_jwt



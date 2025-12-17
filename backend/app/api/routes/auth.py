from __future__ import annotations

from datetime import datetime, timedelta, timezone

from bleach import clean as sanitize_html  # defensive; do not use for passwords
from email_validator import EmailNotValidError, validate_email
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_session, get_current_user, get_db_session
from app.core.config import get_settings
from app.core.encryption import decrypt_pii, encrypt_pii
from app.core.logging import log_security_event
from app.core.rate_limit import limiter
from app.core.security import (
    email_to_hash,
    generate_csrf_token,
    generate_session_id,
    get_password_hash,
    normalize_email,
    validate_password_strength,
    verify_password,
)
from app.models import PasswordHistory, Session as DBSession
from app.models import User, UserRole
from app.schemas.auth import AuthResponse, ChangePasswordRequest, MeResponse
from app.schemas.user import UserCreate, UserLogin, UserMasked


settings = get_settings()
router = APIRouter()

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15
PASSWORD_HISTORY_LIMIT = 5


def _mask_email(email: str) -> str:
    """
    Mask email for responses and logs: e.g. j***@example.com
    """
    try:
        v = validate_email(email, check_deliverability=False)
        local, domain = v.local_part, v.domain
    except EmailNotValidError:
        return "***"

    if len(local) <= 1:
        masked_local = "*"
    elif len(local) == 2:
        masked_local = local[0] + "*"
    else:
        masked_local = local[0] + "*" * (len(local) - 2) + local[-1]
    return f"{masked_local}@{domain}"


def _user_to_masked(user: User) -> UserMasked:
    email = decrypt_pii(user.email_key_id, user.email_nonce, user.email_ciphertext)
    return UserMasked(
        id=user.id,
        email_masked=_mask_email(email),
        role=user.role,
        is_active=user.is_active,
        created_at=user.created_at,
    )


@router.post("/register", response_model=AuthResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit(settings.RATE_LIMIT_AUTH)
def register(
    payload: UserCreate,
    request: Request,
    response: Response,
    db: Session = Depends(get_db_session),
) -> AuthResponse:
    normalized_email = normalize_email(payload.email)
    email_hash = email_to_hash(normalized_email)

    if db.query(User).filter(User.email_hash == email_hash).first():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")

    # Enforce password policy
    try:
        validate_password_strength(payload.password)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    # Encrypt email as PII
    key_id, nonce, ciphertext = encrypt_pii(normalized_email)

    password_hash = get_password_hash(payload.password)

    user = User(
        email_hash=email_hash,
        email_key_id=key_id,
        email_nonce=nonce,
        email_ciphertext=ciphertext,
        password_hash=password_hash,
        role=UserRole.user,
        is_active=True,
    )
    db.add(user)
    db.flush()

    # Initialize password history
    history_entry = PasswordHistory(user_id=user.id, password_hash=password_hash)
    db.add(history_entry)

    # Create initial session
    now = datetime.now(timezone.utc)
    absolute_expiry = now + timedelta(hours=settings.SESSION_ABSOLUTE_TIMEOUT_HOURS)
    session_id = generate_session_id()
    db_session = DBSession(
        id=session_id,
        user_id=user.id,
        created_at=now,
        last_accessed_at=now,
        expires_at=absolute_expiry,
        ip_address=str(request.client.host) if request.client else None,
        user_agent=sanitize_html(request.headers.get("user-agent", ""))[:255],
    )
    db.add(db_session)
    db.commit()
    db.refresh(user)

    csrf_token = generate_csrf_token()

    response.set_cookie(
        key=settings.SESSION_COOKIE_NAME,
        value=session_id,
        httponly=True,
        secure=not settings.DEBUG,
        samesite="strict",
        max_age=int(settings.SESSION_ABSOLUTE_TIMEOUT_HOURS * 3600),
        path="/",
    )
    response.set_cookie(
        key=settings.CSRF_COOKIE_NAME,
        value=csrf_token,
        httponly=False,
        secure=not settings.DEBUG,
        samesite="strict",
        path="/",
    )

    log_security_event(
        "user_registered",
        user_id=user.id,
        ip=str(request.client.host) if request.client else None,
    )
    return AuthResponse(user=_user_to_masked(user), csrf_token=csrf_token)


@router.post("/login", response_model=AuthResponse)
@limiter.limit(settings.RATE_LIMIT_AUTH)
def login(
    payload: UserLogin,
    request: Request,
    response: Response,
    db: Session = Depends(get_db_session),
) -> AuthResponse:
    normalized_email = normalize_email(payload.email)
    email_hash = email_to_hash(normalized_email)

    user = db.query(User).filter(User.email_hash == email_hash).first()
    if not user:
        log_security_event(
            "login_failed_unknown_user",
            email_hash=email_hash,
            ip=str(request.client.host) if request.client else None,
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    now = datetime.now(timezone.utc)
    if user.lockout_until and user.lockout_until > now:
        log_security_event(
            "login_attempt_locked_account",
            user_id=user.id,
            ip=str(request.client.host) if request.client else None,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account locked. Please try again later.",
        )

    if not verify_password(payload.password, user.password_hash):
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
            user.lockout_until = now + timedelta(minutes=LOCKOUT_MINUTES)
            log_security_event(
                "account_locked",
                user_id=user.id,
                ip=str(request.client.host) if request.client else None,
            )
        db.commit()
        log_security_event(
            "login_failed_bad_password",
            user_id=user.id,
            ip=str(request.client.host) if request.client else None,
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    # Reset lockout counters
    user.failed_login_attempts = 0
    user.lockout_until = None

    # Create new session (invalidate old ones optionally)
    now = datetime.now(timezone.utc)
    absolute_expiry = now + timedelta(hours=settings.SESSION_ABSOLUTE_TIMEOUT_HOURS)
    session_id = generate_session_id()
    db_session = DBSession(
        id=session_id,
        user_id=user.id,
        created_at=now,
        last_accessed_at=now,
        expires_at=absolute_expiry,
        ip_address=str(request.client.host) if request.client else None,
        user_agent=sanitize_html(request.headers.get("user-agent", ""))[:255],
    )
    db.add(db_session)
    db.commit()
    db.refresh(user)

    csrf_token = generate_csrf_token()

    response.set_cookie(
        key=settings.SESSION_COOKIE_NAME,
        value=session_id,
        httponly=True,
        secure=not settings.DEBUG,
        samesite="strict",
        max_age=int(settings.SESSION_ABSOLUTE_TIMEOUT_HOURS * 3600),
        path="/",
    )
    response.set_cookie(
        key=settings.CSRF_COOKIE_NAME,
        value=csrf_token,
        httponly=False,
        secure=not settings.DEBUG,
        samesite="strict",
        path="/",
    )

    log_security_event(
        "login_success",
        user_id=user.id,
        ip=str(request.client.host) if request.client else None,
    )
    return AuthResponse(user=_user_to_masked(user), csrf_token=csrf_token)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    request: Request,
    response: Response,
    db_session: DBSession = Depends(get_current_session),
    db: Session = Depends(get_db_session),
) -> Response:
    db_session.revoked = True
    db.commit()

    response.delete_cookie(key=settings.SESSION_COOKIE_NAME, path="/")
    response.delete_cookie(key=settings.CSRF_COOKIE_NAME, path="/")

    log_security_event(
        "logout",
        user_id=db_session.user_id,
        session_id=db_session.id,
        ip=str(request.client.host) if request.client else None,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/me", response_model=MeResponse)
def me(
    request: Request,
    response: Response,
    user: User = Depends(get_current_user),
) -> MeResponse:
    csrf_token = generate_csrf_token()
    response.set_cookie(
        key=settings.CSRF_COOKIE_NAME,
        value=csrf_token,
        httponly=False,
        secure=not settings.DEBUG,
        samesite="strict",
        path="/",
    )

    log_security_event(
        "whoami",
        user_id=user.id,
        ip=str(request.client.host) if request.client else None,
    )
    return MeResponse(user=_user_to_masked(user), csrf_token=csrf_token)


@router.post("/change-password", status_code=status.HTTP_204_NO_CONTENT)
def change_password(
    payload: ChangePasswordRequest,
    request: Request,
    response: Response,
    user: User = Depends(get_current_user),
    db_session: DBSession = Depends(get_current_session),
    db: Session = Depends(get_db_session),
) -> Response:
    # Verify current password
    if not verify_password(payload.current_password, user.password_hash):
        log_security_event(
            "password_change_failed_bad_current",
            user_id=user.id,
            ip=str(request.client.host) if request.client else None,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect.",
        )

    # Enforce strength
    try:
        validate_password_strength(payload.new_password)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    # Enforce password history (prevent reuse of last N)
    recent_history = (
        db.query(PasswordHistory)
        .filter(PasswordHistory.user_id == user.id)
        .order_by(PasswordHistory.created_at.desc())
        .limit(PASSWORD_HISTORY_LIMIT)
        .all()
    )
    for entry in recent_history:
        if verify_password(payload.new_password, entry.password_hash):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot reuse a recent password.",
            )

    # Update password and append to history
    new_hash = get_password_hash(payload.new_password)
    user.password_hash = new_hash
    db.add(PasswordHistory(user_id=user.id, password_hash=new_hash))

    # Revoke all existing sessions for this user (including current)
    db.query(DBSession).filter(DBSession.user_id == user.id).update({"revoked": True})
    db.commit()

    # Clear cookies so client must re-authenticate
    response.delete_cookie(key=settings.SESSION_COOKIE_NAME, path="/")
    response.delete_cookie(key=settings.CSRF_COOKIE_NAME, path="/")

    log_security_event(
        "password_changed",
        user_id=user.id,
        session_id=db_session.id,
        ip=str(request.client.host) if request.client else None,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)



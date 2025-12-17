from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Generator, Iterable, Optional

from fastapi import Cookie, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.logging import log_security_event
from app.db.session import get_db
from app.models import Session as DBSession
from app.models import User, UserRole


settings = get_settings()


def get_db_session() -> Generator[Session, None, None]:
    yield from get_db()


def _is_session_expired(db_session: DBSession) -> bool:
    now = datetime.now(timezone.utc)
    if db_session.expires_at <= now:
        return True
    idle_timeout = timedelta(minutes=settings.SESSION_IDLE_TIMEOUT_MINUTES)
    if now - db_session.last_accessed_at > idle_timeout:
        return True
    return False


def get_current_session(
    request: Request,
    db: Session = Depends(get_db_session),
    session_id: Optional[str] = Cookie(default=None, alias="session_id"),
) -> DBSession:
    if not session_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    db_session = db.get(DBSession, session_id)
    if not db_session or db_session.revoked:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    if _is_session_expired(db_session):
        db_session.revoked = True
        db.commit()
        log_security_event(
            "session_expired",
            session_id=session_id,
            user_id=db_session.user_id,
            ip=str(request.client.host) if request.client else None,
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired")

    # Update last accessed time for idle timeout
    db_session.last_accessed_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(db_session)
    return db_session


def get_current_user(
    request: Request,
    db_session: DBSession = Depends(get_current_session),
    db: Session = Depends(get_db_session),
) -> User:
    user = db.get(User, db_session.user_id)
    if not user or not user.is_active:
        log_security_event(
            "inactive_or_missing_user_session",
            session_id=db_session.id,
            user_id=db_session.user_id,
            ip=str(request.client.host) if request.client else None,
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Inactive account")
    return user


def require_roles(*roles: Iterable[UserRole]):
    allowed_roles = set(roles)

    def dependency(user: User = Depends(get_current_user)) -> User:
        if user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return user

    return dependency


def get_current_active_user(user: User = Depends(get_current_user)) -> User:
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive account",
        )
    return user


def get_current_admin(user: User = Depends(get_current_user)) -> User:
    if user.role != UserRole.admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )
    return user



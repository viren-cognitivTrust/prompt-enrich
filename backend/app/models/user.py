from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    Integer,
    LargeBinary,
    String,
)
from sqlalchemy.orm import relationship

from app.db.base import Base
from app.models.enums import UserRole


class User(Base):
    __tablename__ = "users"

    id = Column(
        String,
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    # Authentication identity (hash of normalized email)
    email_hash = Column(String(64), unique=True, nullable=False, index=True)

    # Encrypted PII email
    email_key_id = Column(String(128), nullable=False)
    email_nonce = Column(LargeBinary, nullable=False)
    email_ciphertext = Column(LargeBinary, nullable=False)

    password_hash = Column(String(255), nullable=False)
    role = Column(Enum(UserRole), nullable=False, default=UserRole.user)
    is_active = Column(Boolean, default=True, nullable=False)

    # Account lockout
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    lockout_until = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )

    password_history = relationship(
        "PasswordHistory",
        back_populates="user",
        cascade="all, delete-orphan",
    )
    sessions = relationship(
        "Session",
        back_populates="user",
        cascade="all, delete-orphan",
    )
    items = relationship(
        "Item",
        back_populates="owner",
        cascade="all, delete-orphan",
    )



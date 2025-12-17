from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, Field

from app.models.enums import UserRole


class UserBase(BaseModel):
    email: EmailStr = Field(...)


class UserCreate(UserBase):
    password: str = Field(
        ...,
        min_length=12,
        max_length=128,
        description="At least 12 chars, including upper, lower, number, and symbol.",
    )


class UserRead(BaseModel):
    id: str
    email: EmailStr
    role: UserRole
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class UserInDB(UserRead):
    password_hash: str


class UserLogin(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=12, max_length=128)


class UserMasked(BaseModel):
    id: str
    email_masked: str
    role: UserRole
    is_active: bool
    created_at: datetime



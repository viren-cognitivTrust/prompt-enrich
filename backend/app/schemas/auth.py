from __future__ import annotations

from pydantic import BaseModel, Field

from app.schemas.user import UserMasked


class AuthResponse(BaseModel):
    user: UserMasked
    csrf_token: str


class MeResponse(BaseModel):
    user: UserMasked
    csrf_token: str


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(..., min_length=12, max_length=128)
    new_password: str = Field(..., min_length=12, max_length=128)




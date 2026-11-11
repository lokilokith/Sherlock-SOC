from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=256)


class AuthenticatedUser(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str
    role: str


class ManagedUser(BaseModel):
    username: str
    email: str | None = None
    role: str
    active: bool
    created_at: datetime | None = None
    last_login_at: datetime | None = None


class CreateUserRequest(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    email: str | None = Field(default=None, max_length=255)
    password: str = Field(min_length=12, max_length=256)
    role: str = Field(default="analyst", pattern="^analyst$")


class UpdateUserRequest(BaseModel):
    email: str | None = Field(default=None, max_length=255)
    role: str = Field(pattern="^(admin|analyst)$")
    active: bool = True


class ChangePasswordRequest(BaseModel):
    password: str = Field(min_length=12, max_length=256)

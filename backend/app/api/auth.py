"""Auth endpoints: /auth/register and /auth/login."""

import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import auth_utils
from app.deps import get_db
from app.models.user import User, UserRole

router = APIRouter()

# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    full_name: str
    role: Optional[str] = "INVESTIGATOR"

    @field_validator("password")
    @classmethod
    def password_min_length(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("password must be at least 8 characters")
        return v

    @field_validator("role")
    @classmethod
    def role_valid(cls, v: Optional[str]) -> str:
        if v is None:
            return "INVESTIGATOR"
        if v not in ("INVESTIGATOR", "AUDITOR"):
            raise ValueError("role must be INVESTIGATOR or AUDITOR")
        return v


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: uuid.UUID
    role: str


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("/register", response_model=TokenResponse)
async def register(body: RegisterRequest, db: AsyncSession = Depends(get_db)) -> TokenResponse:
    """Create a new user account and return a JWT."""
    # Check for duplicate email
    result = await db.execute(select(User).where(User.email == body.email))
    if result.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Email already registered"
        )

    role_val = body.role if body.role else "INVESTIGATOR"
    try:
        role_enum = UserRole(role_val)
    except (ValueError, KeyError):
        role_enum = UserRole.INVESTIGATOR

    user = User(
        id=uuid.uuid4(),
        email=body.email,
        password_hash=auth_utils.hash_password(body.password),
        full_name=body.full_name,
        role=role_enum,
        created_at=datetime.now(timezone.utc),
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    token = auth_utils.create_access_token({"sub": str(user.id)})
    role_str = user.role.value if hasattr(user.role, "value") else str(user.role)
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        user_id=user.id,
        role=role_str,
    )


@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest, db: AsyncSession = Depends(get_db)) -> TokenResponse:
    """Authenticate and return a JWT."""
    result = await db.execute(select(User).where(User.email == body.email))
    user: Optional[User] = result.scalar_one_or_none()

    if user is None or not auth_utils.verify_password(body.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
        )

    token = auth_utils.create_access_token({"sub": str(user.id)})
    role_str = user.role.value if hasattr(user.role, "value") else str(user.role)
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        user_id=user.id,
        role=role_str,
    )


# ---------------------------------------------------------------------------
# Current user / directory (used for custody transfers)
# ---------------------------------------------------------------------------

from app.deps import get_current_user  # noqa: E402


class UserOut(BaseModel):
    id: uuid.UUID
    email: str
    full_name: str
    role: str


def _user_out(u: User) -> UserOut:
    return UserOut(
        id=u.id,
        email=u.email,
        full_name=u.full_name,
        role=u.role.value if hasattr(u.role, "value") else str(u.role),
    )


@router.get("/me", response_model=UserOut)
async def me(current_user: User = Depends(get_current_user)) -> UserOut:
    return _user_out(current_user)


@router.get("/users", response_model=list[UserOut])
async def list_users(
    db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)
) -> list[UserOut]:
    rows = (await db.execute(select(User).order_by(User.full_name))).scalars()
    return [_user_out(u) for u in rows]

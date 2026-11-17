"""FastAPI dependency injectors: DB session, current user, role guard."""

from typing import AsyncGenerator

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import AsyncSessionLocal
from app.models.user import User, UserRole
from app import auth_utils

# Allow dict-like access on User model for interoperability
if not hasattr(User, "__getitem__"):
    User.__getitem__ = lambda self, key: getattr(self, key)  # type: ignore[attr-defined]
if not hasattr(User, "get"):
    User.get = lambda self, key, default=None: getattr(self, key, default)  # type: ignore[attr-defined]

security = HTTPBearer()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        yield session


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db),
) -> User:
    token = credentials.credentials
    user = await auth_utils.verify_token_and_get_user(token, db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    return user


def require_role(*roles: str | UserRole):
    """Return a dependency that enforces *roles* on the current user."""
    allowed = {r.value if hasattr(r, "value") else str(r) for r in roles}

    async def checker(current_user: User = Depends(get_current_user)) -> User:
        current_role = (
            current_user.role.value
            if hasattr(current_user.role, "value")
            else str(current_user.role)
        )
        if current_role not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions"
            )
        return current_user

    return checker

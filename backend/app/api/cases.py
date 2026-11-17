"""Cases CRUD endpoints."""

import uuid
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.deps import get_current_user, get_db, require_role
from app.models.case import Case, CaseStatus
from app.models.user import User, UserRole

router = APIRouter()

# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class CaseCreate(BaseModel):
    title: str = Field(..., max_length=500)
    description: Optional[str] = None


class CaseUpdate(BaseModel):
    title: Optional[str] = Field(None, max_length=500)
    description: Optional[str] = None
    status: Optional[CaseStatus] = None


class CaseResponse(BaseModel):
    id: uuid.UUID
    title: str
    description: Optional[str] = None
    created_by: uuid.UUID
    status: CaseStatus
    created_at: datetime

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post(
    "",
    response_model=CaseResponse,
    status_code=status.HTTP_201_CREATED,
    include_in_schema=True,
)
@router.post(
    "/",
    response_model=CaseResponse,
    status_code=status.HTTP_201_CREATED,
    include_in_schema=False,
)
async def create_case(
    body: CaseCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.INVESTIGATOR)),
) -> CaseResponse:
    """Create a new case (INVESTIGATOR only)."""
    case = Case(
        id=uuid.uuid4(),
        title=body.title,
        description=body.description,
        created_by=current_user.id,
        status=CaseStatus.OPEN,
        created_at=datetime.now(timezone.utc),
    )
    db.add(case)
    await db.commit()
    await db.refresh(case)
    return CaseResponse.model_validate(case)


@router.get("", response_model=List[CaseResponse], include_in_schema=True)
@router.get("/", response_model=List[CaseResponse], include_in_schema=False)
async def list_cases(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> List[CaseResponse]:
    """List all cases (any authenticated user)."""
    result = await db.execute(select(Case).order_by(Case.created_at.desc()))
    cases = result.scalars().all()
    return [CaseResponse.model_validate(c) for c in cases]


@router.get("/{case_id}", response_model=CaseResponse)
async def get_case(
    case_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> CaseResponse:
    """Get a single case by ID (any authenticated user)."""
    result = await db.execute(select(Case).where(Case.id == case_id))
    case = result.scalar_one_or_none()
    if case is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")
    return CaseResponse.model_validate(case)


@router.patch("/{case_id}", response_model=CaseResponse)
async def update_case(
    case_id: uuid.UUID,
    body: CaseUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.INVESTIGATOR)),
) -> CaseResponse:
    """Update case fields (INVESTIGATOR only)."""
    result = await db.execute(select(Case).where(Case.id == case_id))
    case = result.scalar_one_or_none()
    if case is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")

    if body.title is not None:
        case.title = body.title
    if body.description is not None:
        case.description = body.description
    if body.status is not None:
        case.status = body.status

    await db.commit()
    await db.refresh(case)
    return CaseResponse.model_validate(case)


@router.delete("/{case_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_case(
    case_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.INVESTIGATOR)),
) -> None:
    """Soft-delete a case by archiving it (INVESTIGATOR only)."""
    result = await db.execute(select(Case).where(Case.id == case_id))
    case = result.scalar_one_or_none()
    if case is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")

    # Soft delete: set status to ARCHIVED
    case.status = CaseStatus.ARCHIVED
    await db.commit()

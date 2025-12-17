from __future__ import annotations

from typing import List

import bleach
from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_active_user, get_db_session
from app.core.logging import log_security_event
from app.core.rate_limit import limiter
from app.models import Item, User, UserRole
from app.schemas.item import ItemCreate, ItemRead, ItemUpdate


router = APIRouter()


def _sanitize_content(content: str | None) -> str | None:
    if content is None:
        return None
    # Strict sanitization: allow only basic formatting tags, strip scripts.
    return bleach.clean(
        content,
        tags=["b", "i", "strong", "em", "ul", "ol", "li", "p", "br"],
        attributes={},
        strip=True,
    )


@router.get("/", response_model=List[ItemRead])
@limiter.limit("100/minute")
def list_items(
    *,
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_active_user),
    skip: int = Query(0, ge=0, le=10_000),
    limit: int = Query(20, ge=1, le=100),
) -> List[ItemRead]:
    query = db.query(Item)
    if current_user.role != UserRole.admin:
        query = query.filter(Item.owner_id == current_user.id)
    items = query.offset(skip).limit(limit).all()
    return items


@router.post("/", response_model=ItemRead, status_code=status.HTTP_201_CREATED)
@limiter.limit("50/minute")
def create_item(
    *,
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_active_user),
    payload: ItemCreate,
) -> ItemRead:
    sanitized_content = _sanitize_content(payload.content)
    item = Item(
        owner_id=current_user.id,
        title=payload.title.strip(),
        content=sanitized_content,
    )
    db.add(item)
    db.commit()
    db.refresh(item)
    return item


@router.get("/{item_id}", response_model=ItemRead)
@limiter.limit("100/minute")
def get_item(
    *,
    item_id: int = Path(..., ge=1),
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_active_user),
) -> ItemRead:
    item = db.get(Item, item_id)
    if not item:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Item not found")
    if item.owner_id != current_user.id and current_user.role != UserRole.admin:
        log_security_event(
            "unauthorized_item_access",
            user_id=current_user.id,
            item_id=item_id,
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not allowed")
    return item


@router.put("/{item_id}", response_model=ItemRead)
@limiter.limit("50/minute")
def update_item(
    *,
    item_id: int = Path(..., ge=1),
    payload: ItemUpdate,
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_active_user),
) -> ItemRead:
    item = db.get(Item, item_id)
    if not item:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Item not found")
    if item.owner_id != current_user.id and current_user.role != UserRole.admin:
        log_security_event(
            "unauthorized_item_update",
            user_id=current_user.id,
            item_id=item_id,
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not allowed")

    if payload.title is not None:
        item.title = payload.title.strip()
    if payload.content is not None:
        item.content = _sanitize_content(payload.content)

    db.commit()
    db.refresh(item)
    return item


@router.delete("/{item_id}", status_code=status.HTTP_204_NO_CONTENT)
@limiter.limit("50/minute")
def delete_item(
    *,
    item_id: int = Path(..., ge=1),
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_active_user),
) -> None:
    item = db.get(Item, item_id)
    if not item:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Item not found")
    if item.owner_id != current_user.id and current_user.role != UserRole.admin:
        log_security_event(
            "unauthorized_item_delete",
            user_id=current_user.id,
            item_id=item_id,
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not allowed")

    db.delete(item)
    db.commit()
    return None



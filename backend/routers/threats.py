import json
import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.auth import get_current_user
from core.database import get_db
from schemas.threat import ThreatSummary, PaginatedThreatsResponse
from models.threat import ThreatModel

logger = logging.getLogger(__name__)

router = APIRouter()


def _safe_json_loads(value: str | None) -> list | None:
    if not value:
        return None
    try:
        return json.loads(value)
    except Exception:
        return None


@router.get("/threats", response_model=PaginatedThreatsResponse)
async def list_threats(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    result = await db.execute(
        select(ThreatModel).offset(offset).limit(limit).order_by(ThreatModel.created_at.desc())
    )
    items = result.scalars().all()
    count_result = await db.execute(select(ThreatModel))
    total = len(count_result.scalars().all())

    payload = []
    for item in items:
        payload.append(
            ThreatSummary(
                id=item.id,
                file_id=item.file_id,
                name=item.name,
                type=item.type,
                severity=item.severity,
                status=item.status,
                confidence=item.confidence,
                yara_matches=_safe_json_loads(item.yara_matches),
                sandbox_behavior=_safe_json_loads(item.sandbox_behavior),
            )
        )
    logger.info("Listed threats count=%d total=%d user=%s", len(payload), total, current_user)
    return PaginatedThreatsResponse(total=total, limit=limit, offset=offset, items=payload)

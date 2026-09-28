import json
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.auth import get_current_user
from core.database import get_db
from schemas.threat import ThreatSummary, ReportExportResponse
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


@router.get("/reports/export", response_model=ReportExportResponse)
async def export_report(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    result = await db.execute(select(ThreatModel).order_by(ThreatModel.created_at.desc()))
    threats = result.scalars().all()
    total = len(threats)

    by_severity: dict[str, int] = {}
    by_type: dict[str, int] = {}
    for t in threats:
        if t.severity:
            by_severity[t.severity] = by_severity.get(t.severity, 0) + 1
        if t.type:
            by_type[t.type] = by_type.get(t.type, 0) + 1

    items = []
    for t in threats:
        items.append(
            ThreatSummary(
                id=t.id,
                file_id=t.file_id,
                name=t.name,
                type=t.type,
                severity=t.severity,
                status=t.status,
                confidence=t.confidence,
                yara_matches=_safe_json_loads(t.yara_matches),
                sandbox_behavior=_safe_json_loads(t.sandbox_behavior),
            )
        )

    logger.info("Exported report total=%d user=%s", total, current_user)
    return ReportExportResponse(
        generated_at=datetime.now(timezone.utc).isoformat(),
        summary={"total": total, "by_severity": by_severity, "by_type": by_type},
        threats=items,
    )

import logging
import os
import shutil

from fastapi import APIRouter, HTTPException, Depends, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings
from core.auth import get_current_user
from core.database import get_db
from core.limiter import limiter
from schemas.threat import ThreatSummary
from models.threat import ThreatModel

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/threats/{threat_id}/quarantine")
@limiter.limit(f"{settings.RATE_LIMIT_PER_MINUTE}/minute")
async def quarantine_threat(
    request: Request,
    threat_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    result = await db.execute(select(ThreatModel).where(ThreatModel.id == threat_id))
    threat = result.scalars().first()
    if not threat:
        raise HTTPException(status_code=404, detail="威胁记录不存在")
    if threat.status == "quarantined":
        return {"status": "quarantined", "message": "威胁已处于隔离状态"}

    threat.status = "quarantined"
    threat.version = (threat.version or 1) + 1
    await db.flush()

    if threat.path and os.path.exists(threat.path):
        base = os.path.basename(threat.path)
        quarantine_path = os.path.join(settings.QUARANTINE_DIR, f"{base}.quarantined")
        await asyncio.to_thread(shutil.move, threat.path, quarantine_path)
        threat.path = quarantine_path
        await db.flush()

    logger.info("Threat quarantined id=%s user=%s", threat_id, current_user)
    return {"status": "quarantined"}


@router.post("/threats/{threat_id}/restore")
@limiter.limit(f"{settings.RATE_LIMIT_PER_MINUTE}/minute")
async def restore_threat(
    request: Request,
    threat_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    result = await db.execute(select(ThreatModel).where(ThreatModel.id == threat_id))
    threat = result.scalars().first()
    if not threat:
        raise HTTPException(status_code=404, detail="威胁记录不存在")
    if threat.status != "quarantined":
        raise HTTPException(status_code=400, detail="仅隔离状态的威胁可以恢复")
    if not threat.path or not os.path.exists(threat.path):
        raise HTTPException(status_code=404, detail="隔离文件不存在，无法恢复")

    base = os.path.basename(threat.path)
    if base.endswith(".quarantined"):
        base = base[: -len(".quarantined")]
    restored_path = os.path.join(settings.UPLOAD_DIR, base)
    await asyncio.to_thread(shutil.move, threat.path, restored_path)

    threat.status = "detected"
    threat.path = restored_path
    await db.flush()

    logger.info("Threat restored id=%s user=%s", threat_id, current_user)
    return {"status": "restored"}


@router.post("/threats/{threat_id}/permanently_delete")
@limiter.limit(f"{settings.RATE_LIMIT_PER_MINUTE}/minute")
async def permanently_delete_threat(
    request: Request,
    threat_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    result = await db.execute(select(ThreatModel).where(ThreatModel.id == threat_id))
    threat = result.scalars().first()
    if not threat:
        raise HTTPException(status_code=404, detail="威胁记录不存在")

    if threat.path and os.path.exists(threat.path):
        await asyncio.to_thread(os.remove, threat.path)

    threat.status = "cleaned"
    threat.path = ""
    await db.flush()

    logger.info("Threat permanently deleted id=%s user=%s", threat_id, current_user)
    return {"status": "deleted"}


@router.post("/threats/{threat_id}/clean")
@limiter.limit(f"{settings.RATE_LIMIT_PER_MINUTE}/minute")
async def clean_threat(
    request: Request,
    threat_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    result = await db.execute(select(ThreatModel).where(ThreatModel.id == threat_id))
    threat = result.scalars().first()
    if not threat:
        raise HTTPException(status_code=404, detail="威胁记录不存在")
    if threat.status == "cleaned":
        return {"status": "cleaned", "message": "威胁已处于清除状态"}

    threat.status = "cleaned"
    threat.version = (threat.version or 1) + 1
    await db.flush()

    logger.info("Threat cleaned id=%s user=%s", threat_id, current_user)
    return {"status": "cleaned"}

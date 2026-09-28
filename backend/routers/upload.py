import asyncio
import logging
import os
import uuid

from fastapi import APIRouter, UploadFile, File, HTTPException, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings
from core.auth import get_current_user
from core.database import get_db
from core.limiter import limiter
from schemas.threat import ThreatSummary, ScanUploadResponse
from models.threat import ThreatModel

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/scan/upload", response_model=ScanUploadResponse)
@limiter.limit(f"{settings.RATE_LIMIT_PER_MINUTE}/minute")
async def scan_upload(
    request: Request,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    content = await asyncio.to_thread(lambda: file.file.read(settings.MAX_FILE_SIZE + 1))
    if len(content) > settings.MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail="文件大小超出限制")

    if len(content) == 0:
        raise HTTPException(status_code=400, detail="空文件不允许上传")

    original_filename = os.path.basename(file.filename) if file.filename else "unknown"
    ext = os.path.splitext(original_filename)[1]
    file_id = uuid.uuid4().hex
    stored_name = f"{file_id}{ext}"
    stored_path = os.path.join(settings.UPLOAD_DIR, stored_name)

    await asyncio.to_thread(lambda: os.makedirs(settings.UPLOAD_DIR, exist_ok=True))
    with open(stored_path, "wb") as f:
        f.write(content)

    try:
        from ml_engine import predict_file
        result = await asyncio.to_thread(predict_file, stored_path)

        if result.get("prediction") == 1 and result.get("probability", 0) > 0.6:
            severity = (
                "critical"
                if result["probability"] > 0.8
                else "high"
                if result["probability"] > 0.6
                else "medium"
            )
            record = ThreatModel(
                id=str(uuid.uuid4()),
                file_id=file_id,
                name=original_filename,
                type="PE Malware",
                severity=severity,
                path=stored_path,
                status="detected",
                confidence=round(result["probability"] * 100, 2),
                yara_matches=result.get("yara_matches"),
                sandbox_behavior=result.get("sandbox_behavior"),
                version=1,
            )
            db.add(record)
            await db.flush()
            logger.info(
                "Threat detected file=%s severity=%s confidence=%s user=%s",
                original_filename,
                severity,
                record.confidence,
                current_user,
            )
            return ScanUploadResponse(
                status="threat_detected",
                threat=ThreatSummary(
                    id=record.id,
                    file_id=record.file_id,
                    name=record.name,
                    type=record.type,
                    severity=record.severity,
                    status=record.status,
                    confidence=record.confidence,
                    yara_matches=record.yara_matches,
                    sandbox_behavior=record.sandbox_behavior,
                ),
            )

        return ScanUploadResponse(status="safe")
    except Exception as exc:
        logger.error("Model inference failed user=%s: %s", current_user, exc, exc_info=True)
        raise HTTPException(status_code=500, detail="模型推理失败") from exc
    finally:
        if os.path.exists(stored_path):
            await asyncio.to_thread(os.remove, stored_path)

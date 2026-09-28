from datetime import datetime, timezone
from typing import List, Optional
import json

from sqlalchemy import select, func
from sqlalchemy.orm import Session

from models.threat import ThreatModel
from schemas.threat import ThreatCreate, ThreatUpdate


def _safe_json_loads(value: Optional[str]) -> Optional[list]:
    if not value:
        return None
    try:
        return json.loads(value)
    except Exception:
        return None


def _safe_json_dumps(value: Optional[list]) -> Optional[str]:
    if value is None:
        return None
    return json.dumps(value)


class ThreatRepository:
    def __init__(self, session: Session):
        self.session = session

    def list_threats(self, limit: int = 100, offset: int = 0) -> tuple[list[ThreatModel], int]:
        items = (
            self.session.query(ThreatModel)
            .order_by(ThreatModel.created_at.desc())
            .limit(limit)
            .offset(offset)
            .all()
        )
        total = self.session.query(func.count(ThreatModel.id)).scalar() or 0
        return list(items), total

    def get(self, threat_id: str) -> Optional[ThreatModel]:
        return self.session.query(ThreatModel).filter(ThreatModel.id == threat_id).first()

    def create(self, payload: ThreatCreate) -> ThreatModel:
        threat = ThreatModel(
            id=payload.id,
            file_id=payload.file_id,
            name=payload.name,
            type=payload.type,
            severity=payload.severity,
            path=payload.path,
            status=payload.status,
            confidence=payload.confidence,
            created_at=datetime.now(timezone.utc).isoformat(),
            version=1,
            yara_matches=_safe_json_dumps(payload.yara_matches),
            sandbox_behavior=_safe_json_dumps(payload.sandbox_behavior),
        )
        self.session.add(threat)
        self.session.commit()
        self.session.refresh(threat)
        return threat

    def update_status(self, threat_id: str, payload: ThreatUpdate) -> Optional[ThreatModel]:
        threat = self.get(threat_id)
        if not threat:
            return None
        if payload.status is not None:
            threat.status = payload.status
        if payload.path is not None:
            threat.path = payload.path
        threat.version = (threat.version or 1) + 1
        self.session.commit()
        self.session.refresh(threat)
        return threat

    def update_path(self, threat_id: str, path: str) -> Optional[ThreatModel]:
        threat = self.get(threat_id)
        if not threat:
            return None
        threat.path = path
        self.session.commit()
        self.session.refresh(threat)
        return threat

    def delete(self, threat_id: str) -> bool:
        threat = self.get(threat_id)
        if not threat:
            return False
        self.session.delete(threat)
        self.session.commit()
        return True

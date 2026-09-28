from pydantic import BaseModel
from typing import Optional, List


class ThreatBase(BaseModel):
    name: Optional[str] = None
    type: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    confidence: Optional[float] = None
    yara_matches: Optional[List[str]] = None
    sandbox_behavior: Optional[List[str]] = None


class ThreatCreate(ThreatBase):
    id: str
    file_id: Optional[str] = None
    path: Optional[str] = None


class ThreatUpdate(BaseModel):
    status: Optional[str] = None
    path: Optional[str] = None
    version: Optional[int] = None


class ThreatSummary(ThreatBase):
    id: str
    file_id: Optional[str] = None

    class Config:
        from_attributes = True


class PaginatedThreatsResponse(BaseModel):
    total: int
    limit: int
    offset: int
    items: List[ThreatSummary]


class ScanUploadResponse(BaseModel):
    status: str
    threat: Optional[ThreatSummary] = None


class ReportExportResponse(BaseModel):
    generated_at: str
    summary: dict
    threats: List[ThreatSummary]

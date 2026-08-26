from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field, HttpUrl, field_validator


class CaseStatus(str, Enum):
    QUEUED = "queued"
    ANALYZING = "analyzing"
    COMPLETE = "complete"
    FAILED = "failed"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class SourceImage(BaseModel):
    """An immutable object-store reference; image content is deliberately absent."""

    object_key: str = Field(pattern=r"^evidence/[a-zA-Z0-9_./-]+$")
    original_name: str = Field(min_length=1, max_length=255)
    sha256: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    size_bytes: int = Field(gt=0, le=214748364800)
    media_type: str = Field(default="application/octet-stream", max_length=100)
    signed_download_url: HttpUrl

    @field_validator("original_name")
    @classmethod
    def reject_path_components(cls, value: str) -> str:
        if "/" in value or "\\" in value or value in {".", ".."}:
            raise ValueError("original_name must not contain a path")
        return value


class AnalysisRequest(BaseModel):
    case_id: str = Field(pattern=r"^case_[a-zA-Z0-9_-]{8,80}$")
    image: SourceImage
    filesystem_offset: int = Field(default=0, ge=0)


class MacTimes(BaseModel):
    created_at: datetime | None = None
    modified_at: datetime | None = None
    accessed_at: datetime | None = None
    changed_at: datetime | None = None
    deleted_at: datetime | None = None


class FileRecord(BaseModel):
    record_id: str
    path: str
    name: str
    parent_path: str
    entry_type: Literal["file", "directory", "link", "other"]
    extension: str | None = None
    size_bytes: int = Field(ge=0)
    inode: str | None = None
    allocation_state: Literal["allocated", "deleted", "unknown"]
    mac_times: MacTimes
    signature: str | None = None
    signature_matches_extension: bool | None = None


class Finding(BaseModel):
    finding_id: str
    file_record_id: str | None = None
    severity: Severity
    category: Literal["signature", "extension", "metadata", "recovery", "timeline"]
    title: str
    rationale: str


class TimelineEvent(BaseModel):
    event_id: str
    file_record_id: str | None = None
    event_type: Literal["created", "modified", "accessed", "changed", "deleted"]
    occurred_at: datetime
    path: str
    source: str


class AnalysisResult(BaseModel):
    case_id: str
    filesystem_type: str | None = None
    files: list[FileRecord] = []
    findings: list[Finding] = []
    timeline: list[TimelineEvent] = []
    parser_warnings: list[str] = []

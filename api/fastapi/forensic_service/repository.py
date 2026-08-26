from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .models import AnalysisRequest, AnalysisResult, CaseStatus


SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS cases (
    case_id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    filesystem_type TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    error_message TEXT
);

CREATE TABLE IF NOT EXISTS evidence_images (
    case_id TEXT PRIMARY KEY REFERENCES cases(case_id) ON DELETE CASCADE,
    object_key TEXT NOT NULL UNIQUE,
    original_name TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    media_type TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS file_records (
    record_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    path TEXT NOT NULL,
    parent_path TEXT NOT NULL,
    entry_type TEXT NOT NULL,
    allocation_state TEXT NOT NULL,
    payload TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    file_record_id TEXT,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    payload TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS timeline_events (
    event_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    file_record_id TEXT,
    occurred_at TEXT NOT NULL,
    event_type TEXT NOT NULL,
    path TEXT NOT NULL,
    payload TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_files_case_path ON file_records(case_id, path);
CREATE INDEX IF NOT EXISTS idx_findings_case_severity ON findings(case_id, severity);
CREATE INDEX IF NOT EXISTS idx_timeline_case_time ON timeline_events(case_id, occurred_at);
"""


class CaseRepository:
    """SQLite stores derived forensic records only; it never receives disk-image bytes."""

    def __init__(self, database_path: str) -> None:
        self.database_path = database_path

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        return connection

    def initialize(self) -> None:
        Path(self.database_path).parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(SCHEMA)

    def queue_case(self, request: AnalysisRequest) -> None:
        now = datetime.now(timezone.utc).isoformat()
        image = request.image
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO cases(case_id, status, created_at, updated_at) VALUES (?, ?, ?, ?)",
                (request.case_id, CaseStatus.QUEUED.value, now, now),
            )
            connection.execute(
                """INSERT INTO evidence_images
                (case_id, object_key, original_name, sha256, size_bytes, media_type)
                VALUES (?, ?, ?, ?, ?, ?)""",
                (request.case_id, image.object_key, image.original_name, image.sha256.lower(), image.size_bytes, image.media_type),
            )

    def set_status(self, case_id: str, status: CaseStatus, error_message: str | None = None) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as connection:
            connection.execute(
                "UPDATE cases SET status = ?, error_message = ?, updated_at = ? WHERE case_id = ?",
                (status.value, error_message, now, case_id),
            )

    def save_result(self, result: AnalysisResult) -> None:
        with self._connect() as connection:
            connection.execute("DELETE FROM file_records WHERE case_id = ?", (result.case_id,))
            connection.execute("DELETE FROM findings WHERE case_id = ?", (result.case_id,))
            connection.execute("DELETE FROM timeline_events WHERE case_id = ?", (result.case_id,))
            connection.execute(
                "UPDATE cases SET status = ?, filesystem_type = ?, updated_at = ? WHERE case_id = ?",
                (CaseStatus.COMPLETE.value, result.filesystem_type, datetime.now(timezone.utc).isoformat(), result.case_id),
            )
            connection.executemany(
                """INSERT INTO file_records(record_id, case_id, path, parent_path, entry_type, allocation_state, payload)
                VALUES (?, ?, ?, ?, ?, ?, ?)""",
                [
                    (file.record_id, result.case_id, file.path, file.parent_path, file.entry_type, file.allocation_state, file.model_dump_json())
                    for file in result.files
                ],
            )
            connection.executemany(
                """INSERT INTO findings(finding_id, case_id, file_record_id, severity, category, title, payload)
                VALUES (?, ?, ?, ?, ?, ?, ?)""",
                [
                    (finding.finding_id, result.case_id, finding.file_record_id, finding.severity.value, finding.category, finding.title, finding.model_dump_json())
                    for finding in result.findings
                ],
            )
            connection.executemany(
                """INSERT INTO timeline_events(event_id, case_id, file_record_id, occurred_at, event_type, path, payload)
                VALUES (?, ?, ?, ?, ?, ?, ?)""",
                [
                    (event.event_id, result.case_id, event.file_record_id, event.occurred_at.isoformat(), event.event_type, event.path, event.model_dump_json())
                    for event in result.timeline
                ],
            )

    def get_case_workspace(self, case_id: str) -> dict | None:
        with self._connect() as connection:
            case = connection.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,)).fetchone()
            if not case:
                return None
            return {
                "case": dict(case),
                "files": [json.loads(row["payload"]) for row in connection.execute("SELECT payload FROM file_records WHERE case_id = ? ORDER BY path", (case_id,))],
                "findings": [json.loads(row["payload"]) for row in connection.execute("SELECT payload FROM findings WHERE case_id = ? ORDER BY severity DESC, title", (case_id,))],
                "timeline": [json.loads(row["payload"]) for row in connection.execute("SELECT payload FROM timeline_events WHERE case_id = ? ORDER BY occurred_at", (case_id,))],
            }

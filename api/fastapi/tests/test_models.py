from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from forensic_service.models import AnalysisRequest, MacTimes, SourceImage
from forensic_service.repository import CaseRepository


def source_image() -> SourceImage:
    return SourceImage(
        object_key="evidence/case_12345678/disk.img",
        original_name="disk.img",
        sha256="a" * 64,
        size_bytes=4096,
        signed_download_url="https://evidence.example.test/object",
    )


def test_source_image_rejects_path_in_original_name() -> None:
    with pytest.raises(ValidationError):
        SourceImage(
            object_key="evidence/case_12345678/disk.img",
            original_name="../disk.img",
            sha256="a" * 64,
            size_bytes=4096,
            signed_download_url="https://evidence.example.test/object",
        )


def test_repository_persists_object_reference_without_evidence_bytes(tmp_path) -> None:
    repository = CaseRepository(str(tmp_path / "case-results.sqlite3"))
    repository.initialize()
    request = AnalysisRequest(case_id="case_12345678", image=source_image())
    repository.queue_case(request)
    workspace = repository.get_case_workspace(request.case_id)
    assert workspace is not None
    assert workspace["case"]["status"] == "queued"
    assert "content" not in workspace["case"]
    assert "object_key" not in workspace["case"]

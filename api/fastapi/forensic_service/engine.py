from __future__ import annotations

import hashlib
import json
import os
import resource
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlparse

import httpx

from .models import AnalysisRequest, AnalysisResult

MAX_EVIDENCE_BYTES = 200 * 1024 * 1024 * 1024
MAX_PARSER_SECONDS = 12 * 60
MAX_PARSER_MEMORY_BYTES = 768 * 1024 * 1024


class EvidenceValidationError(RuntimeError):
    pass


def _verify_download_host(signed_download_url: str) -> None:
    expected_host = os.environ.get("FORENSIC_STORAGE_HOST")
    host = urlparse(signed_download_url).hostname
    if expected_host and host != expected_host:
        raise EvidenceValidationError("Signed evidence URL host is not approved")
    if not expected_host:
        raise EvidenceValidationError("FORENSIC_STORAGE_HOST must be configured for analysis workers")


def _download_evidence(request: AnalysisRequest, destination: Path) -> None:
    _verify_download_host(str(request.image.signed_download_url))
    digest = hashlib.sha256()
    received = 0
    with httpx.stream("GET", str(request.image.signed_download_url), follow_redirects=False, timeout=httpx.Timeout(60.0, read=60.0)) as response:
        response.raise_for_status()
        with destination.open("xb") as output:
            for chunk in response.iter_bytes(chunk_size=1024 * 1024):
                received += len(chunk)
                if received > min(request.image.size_bytes, MAX_EVIDENCE_BYTES):
                    raise EvidenceValidationError("Evidence image exceeds the configured size limit")
                digest.update(chunk)
                output.write(chunk)
    if received != request.image.size_bytes:
        raise EvidenceValidationError("Downloaded evidence size does not match submitted intake metadata")
    if digest.hexdigest().lower() != request.image.sha256.lower():
        raise EvidenceValidationError("Downloaded evidence digest does not match submitted intake metadata")


def _resource_limits() -> None:
    resource.setrlimit(resource.RLIMIT_CPU, (MAX_PARSER_SECONDS, MAX_PARSER_SECONDS + 5))
    resource.setrlimit(resource.RLIMIT_AS, (MAX_PARSER_MEMORY_BYTES, MAX_PARSER_MEMORY_BYTES))
    os.umask(0o077)


def run_native_analysis(request: AnalysisRequest) -> AnalysisResult:
    parser_binary = os.environ.get("FORENSIC_PARSER_BIN", "forensicfs-parser")
    with tempfile.TemporaryDirectory(prefix="forensicfs-") as work_directory:
        image_path = Path(work_directory) / "evidence.img"
        _download_evidence(request, image_path)
        completed = subprocess.run(
            [parser_binary, "--image", str(image_path), "--case-id", request.case_id, "--offset", str(request.filesystem_offset)],
            check=False,
            capture_output=True,
            text=True,
            timeout=MAX_PARSER_SECONDS,
            shell=False,
            cwd=work_directory,
            env={"PATH": os.environ.get("PATH", ""), "LANG": "C.UTF-8"},
            preexec_fn=_resource_limits,
        )
        if completed.returncode != 0:
            raise RuntimeError(f"Native parser failed ({completed.returncode}): {completed.stderr.strip()[:2000]}")
        if len(completed.stdout) > 32 * 1024 * 1024:
            raise RuntimeError("Native parser output exceeds the result size limit")
        return AnalysisResult.model_validate(json.loads(completed.stdout))

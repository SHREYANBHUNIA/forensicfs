# Analysis Service API

The Python service defined here is the trusted boundary between an analysis job and the native parser. It accepts only a signed evidence reference and case/job identifiers, downloads to ephemeral worker storage, verifies the SHA-256 digest, invokes the native process without a shell, and returns structured results.

## No-Cost API Option

ForensicFS includes its own **self-hosted FastAPI worker** under `api/fastapi/`; no paid third-party forensic API or API key is required. In local development, start it on `http://127.0.0.1:8001` with the native parser on the worker path. The dashboard server uses that local endpoint by default and can be configured with `FORENSIC_ANALYSIS_URL` only when the worker is moved to a separate environment.

The worker remains intentionally separate from the dashboard runtime because native image processing needs Python, the C++ parser, and forensic libraries that should not run in the web application container.

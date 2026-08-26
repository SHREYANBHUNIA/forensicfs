# ForensicFS

ForensicFS is a **digital file-system investigation workspace**. It keeps the interactive case dashboard in this web application while defining an isolated analysis-service boundary for untrusted disk images. The dashboard persists case metadata, evidence references, derived findings, and timeline events; the original image bytes belong in restricted object storage and are never placed in database rows.

## Architecture

| Area | Responsibility | Runtime boundary |
|---|---|---|
| `dashboard/` and `client/` | React investigation workspace, case navigation, directory and timeline views | Managed web application |
| `server/` | Authenticated case API, result persistence, and service handoff contracts | Managed web application |
| `api/fastapi/` | Python FastAPI boundary that validates analysis requests and executes the native worker | Isolated analysis worker environment |
| `image-parser/` | C++ executable and build instructions | Isolated analysis worker environment |
| `filesystem/`, `metadata/`, `recovery/`, `timeline/`, `signatures/`, `analysis/` | Native analysis domains and structured-output contracts | C++ native worker source |

## Evidence Handling

Each disk image is retained as an encrypted object-store asset addressed by an opaque key. The database stores only its key, original filename, size, SHA-256 digest, media type, and analysis state. A signed, short-lived download URL should be minted only inside the analysis worker, which must enforce size limits, an allow-list of expected image types, a non-privileged account, an execution timeout, and read-only evidence access.

> **Deployment note:** the dashboard’s managed runtime is intentionally not used to execute the Python service or the C++ parser. The native worker is designed to run in a separately provisioned environment that supports Python, a C++ runtime, and forensic libraries. The web application communicates through a narrow job contract and never treats uploaded image bytes as database content.

## Development Areas

| Directory | Purpose |
|---|---|
| `image-parser/` | C++ binary and CMake project |
| `filesystem/` | Filesystem traversal adapters |
| `metadata/` | MAC timestamp and metadata normalization |
| `recovery/` | Deleted-entry recovery and confidence handling |
| `timeline/` | Timeline assembly and event ordering |
| `signatures/` | Signature and extension consistency checks |
| `analysis/` | Cross-cutting findings and severity rules |
| `api/` | Python FastAPI service boundary |
| `dashboard/` | Dashboard feature documentation and interaction contract |
| `tests/` | Cross-layer contract fixtures and native/API tests |

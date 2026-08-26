# GitHub Deployment Guide

ForensicFS can be exported to a GitHub repository and deployed from a GitHub-connected hosting provider. The repository contains **two distinct workloads** that should be deployed separately: the React/TypeScript investigation dashboard and the Python/C++ forensic-analysis worker.

| Workload | Directory | Build and start command | Deployment requirement |
|---|---|---|---|
| Web dashboard and API | Repository root | `pnpm install --frozen-lockfile && pnpm build` then `pnpm start` | A Node.js service with the application OAuth, database, and storage environment variables. |
| Analysis worker | `api/fastapi/` | Install `requirements.txt`; start `uvicorn forensic_service.main:app` | A Python/Linux service with the compiled `forensicfs-parser` binary and Sleuth Kit libraries. |

> The FastAPI/C++ worker is deliberately **not** a static-web deployment. It must run separately from the dashboard because it handles disk images, needs native forensic libraries, and should retain its restricted evidence-access policy.

## GitHub-Connected Deployment Checklist

1. Import the private repository into a Node-capable hosting service for the dashboard. Configure the build command as `pnpm install --frozen-lockfile && pnpm build` and the start command as `pnpm start`.
2. Deploy the FastAPI worker to a separate Python/Linux environment. Build the C++ parser from `image-parser/` with CMake and make its executable available through `FORENSIC_PARSER_BIN`.
3. Configure the dashboard service with the worker’s private HTTPS base URL as `FORENSIC_ANALYSIS_URL`. Do not commit this URL, authentication secrets, OAuth configuration, or object-storage credentials to GitHub.
4. Give the worker access only to signed evidence URLs and configure `FORENSIC_STORAGE_HOST` to the expected object-storage hostname.

For an easier path for the dashboard alone, ForensicFS can also be published through its managed hosting with custom-domain support. GitHub export remains useful for external CI/CD, code review, and hosting flexibility.

# Run the No-Cost Analysis API

The included FastAPI service is the no-cost analysis API for local development and self-hosting. It uses the project’s C++ parser; it does not require a paid API account or a third-party API key.

```bash
cd /home/ubuntu/forensicfs/api/fastapi
PYTHONPATH=. FORENSIC_STORAGE_HOST=<your-storage-host> FORENSIC_PARSER_BIN=/home/ubuntu/forensicfs/image-parser/build/forensicfs-parser uvicorn forensic_service.main:app --host 127.0.0.1 --port 8001
```

The dashboard server defaults to `http://127.0.0.1:8001` outside production. To deploy the worker elsewhere, set the server-only `FORENSIC_ANALYSIS_URL` environment variable to its private HTTPS base URL.

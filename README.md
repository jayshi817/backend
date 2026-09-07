# ZINHOST — Render-ready

ZINHOST is a FastAPI + Docker web hosting panel with user/admin dashboards, file upload, direct run/stop/restart, console logs, quotas and persistent `/data` storage.

## Render deployment

**Important:** Deploy this repository as a **Docker** web service. Do not select the Python runtime or use `pip install -r requirements.txt` as the Render Build Command.

The repository root must contain:

```text
Dockerfile
requirements.txt
render.yaml
app/
  main.py
  static/
    index.html
    app.js
```

### Existing Render service

If the current service is already configured as Python and its log says `Using Python version ...` or `pip install -r requirements.txt`, that service is using the wrong runtime. Create/reconfigure it as a Docker web service using the repository root and `Dockerfile`.

### Port

Do **not** hard-code a Render port in the dashboard. Render provides the `PORT` environment variable. The Dockerfile starts Uvicorn on `0.0.0.0:${PORT}` (default 8000 only for local use).

### Environment variables

```text
ADMIN_USERNAME=loqi
ADMIN_PASSWORD=CHANGE_ME
DATA_DIR=/data
MAX_TOTAL_BOTS=10
DEFAULT_MAX_BOTS=1
DEFAULT_RAM_MB=512
DEFAULT_DISK_MB=1536
```

Change `ADMIN_PASSWORD` before making the service public.

### Persistence

Mount a Render persistent disk at `/data` if your Render plan supports persistent disks. Without a persistent disk, SQLite data and uploaded bot files are not guaranteed to survive a new instance/deploy.

## Security note

Uploaded Python runs in the same container as the web API. This is a personal/trusted-user prototype, not a hardened public multi-tenant hosting platform. For untrusted users, isolate workloads in separate containers/VMs with resource and network controls.

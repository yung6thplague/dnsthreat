"""DNS Threat Blocker & Sinkhole Web Application.

FastAPI entrypoint handling:
1. /admin: SOC Telemetry Dashboard with metrics, Top 5 IoCs, and audit logs.
2. /api/stats: Live JSON telemetry for dashboard updates.
3. Catch-all /{path:path} & /: Intercepts all redirected DNS traffic,
   logs telemetry to SQLite WAL, and presents user_blocked.html landing page.
"""

from contextlib import asynccontextmanager
from typing import Any, Dict, Optional
from fastapi import Body, FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from agent.classifier import DomainClassifier
from app.config import APP_DESCRIPTION, APP_TITLE, APP_VERSION, TEMPLATES_DIR
from app.database import (
    add_ioc_entry,
    get_admin_metrics,
    get_ioc_entries,
    init_db,
    log_intercepted_access,
    unblock_ioc,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan context manager: initializes database and tables on startup."""
    init_db()
    yield


app = FastAPI(
    title=APP_TITLE,
    description=APP_DESCRIPTION,
    version=APP_VERSION,
    lifespan=lifespan
)

# Initialize Jinja2 Templates
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def extract_client_ip(request: Request) -> str:
    """Extracts client IP considering reverse proxies or direct DNS redirection."""
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    if request.client and request.client.host:
        return request.client.host
    return "127.0.0.1"


def extract_target_domain(request: Request) -> str:
    """Extracts the original requested domain from the HTTP 'Host' header."""
    host = request.headers.get("host", "").strip()
    if not host:
        return "unspecified-sinkhole-target"
    # Remove port if present (e.g. evil-domain.com:80 -> evil-domain.com)
    return host.split(":")[0].strip().lower()


@app.get("/health", response_class=JSONResponse, tags=["Health"])
async def health_check():
    """Health check endpoint for Unbound watchdog and container monitoring."""
    return {"status": "healthy", "service": "dns_threat_blocker", "version": APP_VERSION}


@app.get("/admin", response_class=HTMLResponse, tags=["Admin"])
async def admin_dashboard(request: Request):
    """SOC Admin Telemetry Dashboard.

    Renders admin_dashboard.html with:
    - Total absolute blocks
    - Top 5 most requested domains
    - Last 10 audit logs
    - Additional threat statistics
    """
    metrics = get_admin_metrics()
    return templates.TemplateResponse(
        request=request,
        name="admin_dashboard.html",
        context={
            "app_title": APP_TITLE,
            "metrics": metrics,
            "total_blocks": metrics["total_blocks"],
            "unique_domains": metrics["unique_domains"],
            "unique_clients": metrics["unique_clients"],
            "total_iocs": metrics["total_iocs"],
            "top_domains": metrics["top_domains"],
            "recent_logs": metrics["recent_logs"]
        }
    )


@app.get("/api/stats", response_class=JSONResponse, tags=["Telemetry API"])
async def api_stats():
    """Provides real-time JSON statistics for dynamic dashboard updates."""
    metrics = get_admin_metrics()
    return metrics


# Initialize ML Classifier instance
ml_classifier = DomainClassifier()


@app.get("/api/iocs", response_class=JSONResponse, tags=["IoC Management"])
async def api_list_iocs(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    search: Optional[str] = Query(None)
):
    """Lists registered IoCs with pagination and optional substring search."""
    iocs = get_ioc_entries(limit=limit, offset=offset, search=search)
    return {"total": len(iocs), "limit": limit, "offset": offset, "iocs": iocs}


@app.post("/api/ioc/unblock", response_class=JSONResponse, tags=["IoC Management"])
async def api_unblock_ioc(payload: Dict[str, Any] = Body(...)):
    """Unblocks an IoC domain (Rollback action from SOC Dashboard).

    Body format: {"domain": "example.com", "add_to_allowlist": true}
    Removes domain from ioc_entries and appends it to allowlist.txt.
    """
    domain = payload.get("domain", "").strip()
    if not domain:
        raise HTTPException(status_code=400, detail="O campo 'domain' é obrigatório.")

    add_to_allowlist = payload.get("add_to_allowlist", True)
    result = unblock_ioc(domain=domain, add_to_allowlist=add_to_allowlist)
    return result


@app.post("/api/ml/analyze", response_class=JSONResponse, tags=["Machine Learning"])
async def api_ml_analyze(payload: Dict[str, Any] = Body(...)):
    """Analyzes a domain using the DGA / Machine Learning Classifier.

    Body format: {"domain": "suspicious-string.xyz"}
    Returns risk score, classification verdict, confidence, and explanatory signals.
    """
    domain = payload.get("domain", "").strip()
    if not domain:
        raise HTTPException(status_code=400, detail="O campo 'domain' é obrigatório.")

    prediction = ml_classifier.predict(domain)
    return prediction.to_dict()


async def handle_sinkhole_interception(request: Request, path: str = "") -> HTMLResponse:
    """Central handler for intercepted traffic.

    Extracts original domain, client IP, user agent, logs the attempt to access_logs
    in SQLite (WAL mode), and displays the user_blocked.html security landing page.
    """
    domain = extract_target_domain(request)
    client_ip = extract_client_ip(request)
    user_agent = request.headers.get("user-agent", "Unknown HTTP Client")

    # Record security telemetry event in SQLite
    log_id = log_intercepted_access(
        domain_requested=domain,
        client_ip=client_ip,
        user_agent=user_agent
    )

    from datetime import datetime, timezone
    utc_timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    return templates.TemplateResponse(
        request=request,
        name="user_blocked.html",
        context={
            "domain": domain,
            "client_ip": client_ip,
            "user_agent": user_agent,
            "timestamp": utc_timestamp,
            "log_id": log_id,
            "path": path,
            "app_title": APP_TITLE
        },
        status_code=200
    )


# 1. Root route sinkhole handler
@app.api_route("/", methods=["GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS"], response_class=HTMLResponse)
async def catch_root(request: Request):
    return await handle_sinkhole_interception(request, path="")


# 2. Catch-all wildcard sinkhole handler (/{path:path})
@app.api_route("/{path:path}", methods=["GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS"], response_class=HTMLResponse)
async def catch_all_paths(request: Request, path: str):
    return await handle_sinkhole_interception(request, path=path)

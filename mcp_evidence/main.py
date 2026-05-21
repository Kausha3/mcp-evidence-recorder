import hashlib
import io
import json
import time
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Optional

import httpx
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from .alerts import send_slack_alert
from .auth import require_configured_token
from .config import get_settings
from .evidence import build_evidence_bundle, events_to_csv
from .models import AuditEventIn
from .policy import PolicyEngine, extract_mcp_metadata
from .redaction import detect_risks, redact
from .store import AuditStore


settings = get_settings()


def require_admin_auth(request: Request) -> None:
    require_configured_token(request, settings.admin_token)


def require_proxy_auth(request: Request) -> None:
    require_configured_token(request, settings.proxy_token)


@lru_cache(maxsize=1)
def get_store() -> AuditStore:
    return AuditStore(settings.database_path)


@lru_cache(maxsize=1)
def get_policy_engine() -> PolicyEngine:
    return PolicyEngine(settings.policy_path)


app = FastAPI(title=settings.app_name, version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
STATIC_DIR = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self';",
    )
    return response


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    with (STATIC_DIR / "index.html").open("r", encoding="utf-8") as handle:
        return handle.read()


@app.get("/health")
async def health() -> Dict[str, Any]:
    chain = get_store().verify_chain()
    return {
        "ok": chain.ok,
        "service": settings.app_name,
        "environment": settings.environment,
        "target_mcp_url": settings.target_mcp_url,
        "admin_auth_enabled": bool(settings.admin_token),
        "proxy_auth_enabled": bool(settings.proxy_token),
    }


@app.api_route("/mcp", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
@app.api_route("/mcp/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def proxy_mcp(
    request: Request,
    path: str = "",
    _auth: None = Depends(require_proxy_auth),
) -> Response:
    started = time.perf_counter()
    raw_body = await request.body()
    if len(raw_body) > settings.max_body_bytes:
        raise HTTPException(status_code=413, detail="request body exceeds MAX_BODY_BYTES")

    request_json: Any = None
    if raw_body:
        try:
            request_json = json.loads(raw_body)
        except json.JSONDecodeError:
            request_json = {"raw": raw_body.decode("utf-8", errors="replace")}

    metadata = extract_mcp_metadata(request_json)
    policy = get_policy_engine().decide(
        request_body=request_json,
        method=metadata["method"],
        tool_name=metadata["tool_name"],
    )

    user_id = request.headers.get("x-user-id")
    session_id = request.headers.get("x-session-id") or _jsonrpc_id(request_json)
    client_name = request.headers.get("x-client-name") or request.headers.get("user-agent")
    upstream_url = _upstream_url(path)

    if not policy.allowed:
        response_body = {
            "jsonrpc": "2.0",
            "id": _jsonrpc_id(request_json),
            "error": {"code": -32001, "message": policy.reason, "data": {"rule_id": policy.rule_id}},
        }
        get_store().insert_event(
            AuditEventIn(
                direction="proxy",
                method=metadata["method"],
                tool_name=metadata["tool_name"],
                user_id=user_id,
                session_id=session_id,
                client_name=client_name,
                upstream_url=upstream_url,
                status_code=403,
                latency_ms=_elapsed_ms(started),
                policy_decision="deny",
                policy_reason=policy.reason,
                request_body=redact(request_json),
                response_body=response_body,
                risks=detect_risks(request_json),
                request_size_bytes=len(raw_body),
                response_size_bytes=len(json.dumps(response_body)),
                request_sha256=_sha256(raw_body),
                response_sha256=_sha256_json(response_body),
            )
        )
        return JSONResponse(status_code=403, content=response_body)

    response_status = 502
    response_body: Any = None
    response_headers: Dict[str, str] = {}
    response_bytes = b""
    try:
        async with httpx.AsyncClient(timeout=settings.request_timeout_seconds) as client:
            upstream = await client.request(
                request.method,
                upstream_url,
                content=raw_body,
                headers=_forward_headers(request),
                params=request.query_params,
            )
        response_status = upstream.status_code
        response_headers = {
            key: value
            for key, value in upstream.headers.items()
            if key.lower() in {"content-type", "cache-control"}
        }
        response_bytes = upstream.content
        try:
            response_body = upstream.json()
        except ValueError:
            response_body = {"raw": response_bytes.decode("utf-8", errors="replace")}
    except httpx.HTTPError as exc:
        response_body = {"error": "upstream_error", "detail": str(exc)}
        response_bytes = json.dumps(response_body).encode("utf-8")

    risks = sorted(set(detect_risks(request_json) + detect_risks(response_body)))
    get_store().insert_event(
        AuditEventIn(
            direction="proxy",
            method=metadata["method"],
            tool_name=metadata["tool_name"],
            user_id=user_id,
            session_id=session_id,
            client_name=client_name,
            upstream_url=upstream_url,
            status_code=response_status,
            latency_ms=_elapsed_ms(started),
            policy_decision="allow",
            policy_reason=policy.reason,
            request_body=redact(request_json),
            response_body=redact(response_body),
            risks=risks,
            request_size_bytes=len(raw_body),
            response_size_bytes=len(response_bytes),
            request_sha256=_sha256(raw_body),
            response_sha256=_sha256(response_bytes),
        )
    )
    await send_slack_alert(
        settings.slack_webhook_url,
        risks,
        f"{metadata['method'] or request.method} {metadata['tool_name'] or ''} session={session_id}",
    )
    return Response(content=response_bytes, status_code=response_status, headers=response_headers)


@app.get("/api/events")
async def list_events(
    _auth: None = Depends(require_admin_auth),
    limit: int = Query(default=100, ge=1, le=1000),
    session_id: Optional[str] = None,
    tool_name: Optional[str] = None,
    risk: Optional[str] = None,
    q: Optional[str] = None,
) -> Dict[str, Any]:
    events = get_store().list_events(
        limit=limit,
        session_id=session_id,
        tool_name=tool_name,
        risk=risk,
        q=q,
    )
    return {"events": events}


@app.get("/api/events/{event_id}")
async def get_event(event_id: int, _auth: None = Depends(require_admin_auth)) -> Dict[str, Any]:
    try:
        return get_store().get_event(event_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="event not found")


@app.get("/api/sessions")
async def sessions(
    _auth: None = Depends(require_admin_auth),
    limit: int = Query(default=100, ge=1, le=1000),
) -> Dict[str, Any]:
    return {"sessions": get_store().sessions(limit=limit)}


@app.get("/api/verify")
async def verify(_auth: None = Depends(require_admin_auth)) -> Dict[str, Any]:
    return _model_to_dict(get_store().verify_chain())


@app.get("/api/stats")
async def stats(_auth: None = Depends(require_admin_auth)) -> Dict[str, Any]:
    chain = get_store().verify_chain()
    return {
        "stats": get_store().stats(),
        "chain": _model_to_dict(chain),
    }


@app.get("/metrics", response_class=PlainTextResponse)
async def metrics(_auth: None = Depends(require_admin_auth)) -> str:
    stats_payload = get_store().stats()
    chain = get_store().verify_chain()
    lines = [
        "# HELP mcp_evidence_events_total Total audit events recorded.",
        "# TYPE mcp_evidence_events_total counter",
        f"mcp_evidence_events_total {stats_payload['total_events']}",
        "# HELP mcp_evidence_denied_events_total Total denied MCP events.",
        "# TYPE mcp_evidence_denied_events_total counter",
        f"mcp_evidence_denied_events_total {stats_payload['denied_events']}",
        "# HELP mcp_evidence_risky_events_total Total events with detected risks.",
        "# TYPE mcp_evidence_risky_events_total counter",
        f"mcp_evidence_risky_events_total {stats_payload['risky_events']}",
        "# HELP mcp_evidence_sessions Total distinct recorded sessions.",
        "# TYPE mcp_evidence_sessions gauge",
        f"mcp_evidence_sessions {stats_payload['sessions']}",
        "# HELP mcp_evidence_chain_verified Whether the audit hash chain verifies.",
        "# TYPE mcp_evidence_chain_verified gauge",
        f"mcp_evidence_chain_verified {1 if chain.ok else 0}",
        "# HELP mcp_evidence_avg_latency_ms Average proxied request latency in milliseconds.",
        "# TYPE mcp_evidence_avg_latency_ms gauge",
        f"mcp_evidence_avg_latency_ms {stats_payload['avg_latency_ms']}",
    ]
    return "\n".join(lines) + "\n"


@app.post("/api/policies/reload")
async def reload_policies(_auth: None = Depends(require_admin_auth)) -> Dict[str, Any]:
    get_policy_engine().reload()
    return {"ok": True, "rules": len(get_policy_engine().rules)}


@app.get("/api/evidence/export")
async def export_evidence(
    _auth: None = Depends(require_admin_auth),
    format: str = Query(default="json", pattern="^(json|csv|bundle)$"),
    session_id: Optional[str] = None,
) -> Response:
    events = get_store().export_events(session_id=session_id)
    chain = _model_to_dict(get_store().verify_chain())
    if format == "json":
        return JSONResponse(content={"events": events, "chain": chain})
    if format == "bundle":
        bundle = build_evidence_bundle(
            events=events,
            chain=chain,
            policy_path=settings.policy_path,
            session_id=session_id,
            service_name=settings.app_name,
        )
        return Response(
            content=bundle,
            media_type="application/zip",
            headers={"Content-Disposition": "attachment; filename=mcp-evidence-bundle.zip"},
        )

    return StreamingResponse(
        iter([events_to_csv(events)]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=mcp-evidence.csv"},
    )


def _upstream_url(path: str) -> str:
    if path:
        return f"{settings.target_mcp_url}/{path.lstrip('/')}"
    return settings.target_mcp_url


def _forward_headers(request: Request) -> Dict[str, str]:
    blocked = {"host", "content-length", "connection"}
    return {key: value for key, value in request.headers.items() if key.lower() not in blocked}


def _jsonrpc_id(body: Any) -> Optional[str]:
    if isinstance(body, dict) and body.get("id") is not None:
        return str(body["id"])
    return None


def _elapsed_ms(started: float) -> int:
    return int((time.perf_counter() - started) * 1000)


def _model_to_dict(model: Any) -> Dict[str, Any]:
    if hasattr(model, "model_dump"):
        return model.model_dump()
    return model.dict()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_json(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return _sha256(encoded)

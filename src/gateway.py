"""LLM Guard Gateway — reverse proxy that inspects inbound requests and outbound
responses with the guard pipeline, blocks/redacts per policy, and audits attacks.

Offline-first: the only outbound network call is forwarding to the configured
upstream. Streaming responses are buffered-then-scanned (the gateway will not
release outbound bytes it has not inspected); document this latency trade-off.
"""

from __future__ import annotations

import json
import logging
import uuid
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from src import textio
from src.audit import AuditLog
from src.config import GatewayConfig, load_config
from src.guards.base import GuardContext, registry
from src.owasp_gaps import RUNTIME_GAPS
from src.pipeline import GuardPipeline
from src.schema import Direction, GuardDecision

logger = logging.getLogger(__name__)

# === Constants ===
HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "host", "content-length",
}
MGMT_PREFIX = "/_guard"  # management endpoints; kept off the proxied path space
BLOCK_MESSAGE = {"error": "blocked by LLM Guard Gateway", "detail": "policy violation"}
PROXY_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]


class GatewayState:
    def __init__(self, config: GatewayConfig) -> None:
        self.config = config
        self.pipeline = GuardPipeline(config)
        self.audit = AuditLog(config.audit)
        self.active = 0
        self.ready = False
        self.client: httpx.AsyncClient | None = None


def create_app(config: GatewayConfig | None = None) -> FastAPI:
    config = config or load_config()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        state = GatewayState(config)
        state.audit.record_gaps()
        state.client = httpx.AsyncClient(timeout=config.upstream_timeout_s)
        _log_gaps()
        _warmup(state)
        state.ready = True
        app.state.gw = state
        try:
            yield
        finally:
            await state.client.aclose()
            state.audit.close()

    app = FastAPI(title="LLM Guard Gateway", version="1.0.0", lifespan=lifespan)

    @app.get(MGMT_PREFIX + "/health")
    async def health() -> dict:
        return {"status": "ok"}

    @app.get(MGMT_PREFIX + "/ready")
    async def ready(request: Request) -> JSONResponse:
        gw: GatewayState = request.app.state.gw
        return JSONResponse({"ready": gw.ready}, status_code=200 if gw.ready else 503)

    @app.get(MGMT_PREFIX + "/owasp")
    async def owasp() -> dict:
        guards = [
            {"guard_id": gid, "owasp_id": cls.owasp_id, "direction": cls.direction.value}
            for gid, cls in sorted(registry().items())
        ]
        return {"guards": guards, "runtime_gaps": [g.model_dump() for g in RUNTIME_GAPS]}

    @app.api_route("/{path:path}", methods=PROXY_METHODS)
    async def proxy(request: Request, path: str) -> Response:
        return await _handle(request, path)

    return app


async def _handle(request: Request, path: str) -> Response:
    gw: GatewayState = request.app.state.gw
    config = gw.config
    request_id = uuid.uuid4().hex

    body = await request.body()
    if len(body) > config.max_body_bytes:
        return JSONResponse({"error": "request too large", "request_id": request_id}, status_code=413)

    payload = _try_json(body, request.headers.get("content-type", ""))
    in_text = textio.extract_request_text(payload, config.request_text_field) or _safe_decode(body)
    client_ip = request.client.host if request.client else None
    session_id = request.headers.get("x-session-id")

    gw.active += 1
    try:
        in_ctx = GuardContext(
            request_id=request_id,
            direction=Direction.INBOUND,
            text=in_text or "",
            headers=dict(request.headers),
            payload=payload if isinstance(payload, dict) else None,
            client_ip=client_ip,
            session_id=session_id,
            meta={"active_requests": gw.active},
        )
        in_decision = gw.pipeline.run(Direction.INBOUND, in_ctx)
        gw.audit.record(in_decision, in_ctx)
        if in_decision.final_decision == GuardDecision.BLOCK:
            return JSONResponse(
                {**BLOCK_MESSAGE, "request_id": request_id, "blocked_by": in_decision.blocked_by, "stage": "request"},
                status_code=403,
            )

        upstream_url = _build_upstream_url(config.upstream_url, path, request.url.query)
        fwd_headers = {k: v for k, v in request.headers.items() if k.lower() not in HOP_BY_HOP}
        try:
            up = await gw.client.request(request.method, upstream_url, content=body, headers=fwd_headers)
        except httpx.ConnectError:
            return JSONResponse({"error": "upstream unreachable", "request_id": request_id}, status_code=502)
        except httpx.TimeoutException:
            return JSONResponse({"error": "upstream timeout", "request_id": request_id}, status_code=504)

        return _inspect_response(gw, request_id, client_ip, session_id, up)
    finally:
        gw.active -= 1


def _inspect_response(
    gw: GatewayState, request_id: str, client_ip, session_id, up: httpx.Response
) -> Response:
    config = gw.config
    up_body = up.content
    up_ct = up.headers.get("content-type", "")
    out_payload = _try_json(up_body, up_ct)
    out_text = textio.extract_response_text(out_payload, config.response_text_field) or _safe_decode(up_body)

    out_ctx = GuardContext(
        request_id=request_id,
        direction=Direction.OUTBOUND,
        text=out_text or "",
        headers=dict(up.headers),
        payload=out_payload if isinstance(out_payload, dict) else None,
        client_ip=client_ip,
        session_id=session_id,
    )
    out_decision = gw.pipeline.run(Direction.OUTBOUND, out_ctx)
    gw.audit.record(out_decision, out_ctx)

    resp_headers = {k: v for k, v in up.headers.items() if k.lower() not in HOP_BY_HOP}

    if out_decision.final_decision == GuardDecision.BLOCK:
        return JSONResponse(
            {**BLOCK_MESSAGE, "request_id": request_id, "blocked_by": out_decision.blocked_by, "stage": "response"},
            status_code=403,
        )

    if out_decision.final_decision == GuardDecision.REDACT and out_decision.redacted_text is not None:
        if isinstance(out_payload, dict):
            new_payload = textio.inject_response_text(out_payload, out_decision.redacted_text, config.response_text_field)
            return JSONResponse(new_payload, status_code=up.status_code)
        return Response(content=out_decision.redacted_text, status_code=up.status_code, media_type=up_ct or "text/plain")

    return Response(content=up_body, status_code=up.status_code, headers=resp_headers, media_type=up_ct or None)


def _build_upstream_url(base: str, path: str, query: str) -> str:
    base = base.rstrip("/")
    url = f"{base}/{path}" if path else base
    return f"{url}?{query}" if query else url


def _try_json(body: bytes, content_type: str):
    if not body:
        return None
    if "json" not in content_type.lower():
        return None
    try:
        return json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


def _safe_decode(body: bytes) -> str:
    return body.decode("utf-8", errors="replace") if body else ""


def _log_gaps() -> None:
    ids = ", ".join(g.owasp_id for g in RUNTIME_GAPS)
    logger.info("OWASP runtime gaps (not defended at the proxy): %s — see /_guard/owasp", ids)


def _warmup(state: GatewayState) -> None:
    """Best-effort: prime inbound guards (loads the LLM01 detector) so the first real
    request isn't slow. Never fails startup — the injection guard lazy-loads anyway."""
    try:
        ctx = GuardContext(request_id="warmup", direction=Direction.INBOUND, text="hello")
        state.pipeline.run(Direction.INBOUND, ctx)
    except Exception as exc:  # warmup is optional; record and continue
        logger.warning("warmup incomplete (guards will lazy-load): %s", exc)

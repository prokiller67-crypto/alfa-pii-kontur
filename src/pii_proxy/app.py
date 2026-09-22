from __future__ import annotations

import hmac
import ipaddress
import json
import logging
import os
import time
from contextlib import asynccontextmanager
from dataclasses import replace
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, Response
from prometheus_client import CollectorRegistry, Counter, Histogram, generate_latest, multiprocess
from pydantic import BaseModel, ConfigDict, Field, StrictStr

from .detector import Detector, Kind
from .service import Policy, Processor, ServiceError
from .vault import CapacityError, MemoryStore, RedisStore, UpstashStore, Vault, load_key

logger = logging.getLogger("pii_proxy.audit")


class ProcessRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    payload: StrictStr = Field(max_length=1_000_000)
    payload_id: StrictStr = Field(min_length=1, max_length=256)


class MaskRequest(ProcessRequest):
    mode: str = Field(default="token", pattern="^(shape|token|partial)$")


class ProcessResponse(BaseModel):
    result: str


def load_policies() -> dict[str, tuple[Policy, str]]:
    path = os.environ.get("PII_POLICIES_FILE")
    if not path:
        return {}
    raw = json.loads(Path(path).read_text())
    result = {}
    for tenant, entry in raw.items():
        mode = entry.get("mode", "shape")
        if mode not in {"shape", "token", "partial"}:
            raise ValueError("invalid_policy_mode")
        result[tenant] = (Policy(
            tenant=tenant, enabled=entry.get("enabled", True),
            types=frozenset(Kind(t) for t in entry.get("types", list(Kind))),
            restore=entry.get("restore", True), mode=mode, min_types=max(1, entry.get("min_types", 1)),
            requires={Kind(k): frozenset(Kind(v) for v in values) for k, values in entry.get("requires", {}).items()},
        ), os.environ.get(entry["api_key_env"], ""))
    return result


class BodyLimit:
    def __init__(self, app, max_bytes: int = 8_000_000):
        self.app, self.max_bytes = app, max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        size = 0
        async def limited_receive():
            nonlocal size
            message = await receive()
            size += len(message.get("body", b""))
            if size > self.max_bytes:
                from starlette.exceptions import HTTPException
                raise HTTPException(413, "request_too_large")
            return message
        await self.app(scope, limited_receive, send)


def create_app(processor: Processor | None = None, *, policies: dict | None = None,
               local_demo: bool | None = None) -> FastAPI:
    supplied = processor is not None
    local_demo = os.environ.get("PII_LOCAL_DEMO", "1") == "1" if local_demo is None else local_demo
    checker_mode = os.environ.get("PII_CHECKER_MODE", "0") == "1"
    allowed_ips = [ipaddress.ip_network(v.strip()) for v in os.environ.get("PII_CHECKER_CIDRS", "").split(",") if v.strip()]
    configured = load_policies() if policies is None else policies
    registry = CollectorRegistry()
    requests = Counter("pii_requests_total", "Requests by bounded outcome", ["operation", "status"], registry=registry)
    latency = Histogram("pii_request_seconds", "End-to-end handler time", ["operation"], registry=registry,
                        buckets=(.001, .005, .01, .025, .05, .1, .25, .5, 1, 2, 5, 10))
    entities = Counter("pii_entity_types_total", "Detected entity types, without values", ["type"], registry=registry)
    chars = Counter("pii_input_characters_total", "Characters processed; NOT an exact token count", registry=registry)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if not supplied:
            logger.setLevel(logging.INFO)
            if not logger.handlers:
                handler = logging.StreamHandler()
                handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
                logger.addHandler(handler)
            logger.propagate = False
        if app.state.processor is None:
            redis_url = os.environ.get("PII_REDIS_URL")
            upstash_url = os.environ.get("UPSTASH_REDIS_REST_URL")
            if redis_url:
                store = RedisStore(redis_url)
            elif upstash_url:
                store = UpstashStore(upstash_url, os.environ.get("UPSTASH_REDIS_REST_TOKEN", ""))
            elif os.environ.get("VERCEL"):
                raise ValueError("shared_store_required_on_vercel")
            else:
                store = MemoryStore()
            vault = Vault(store, load_key(required=bool(redis_url or upstash_url) or checker_mode),
                          ttl=int(os.environ.get("PII_TTL_SECONDS", "1800")))
            detector = Detector(use_ner=os.environ.get("PII_NER", "1") == "1")
            app.state.processor = Processor(detector, vault)
        yield
        if not supplied:
            await app.state.processor.vault.store.close()

    app = FastAPI(title="Alfa PII Proxy", version="0.1.0", lifespan=lifespan)
    app.add_middleware(BodyLimit)
    app.state.processor = processor
    app.state.inflight = 0

    @app.exception_handler(RequestValidationError)
    async def validation_error(_request: Request, _error: RequestValidationError):
        # FastAPI's default response can echo the original input; do not expose it.
        return JSONResponse({"error": "invalid_request"}, status_code=422)

    def authorize(request: Request) -> Policy:
        host = request.client.host if request.client else ""
        system = request.headers.get("x-system-id", "")
        if system:
            entry = configured.get(system)
            key = request.headers.get("x-api-key", "")
            if not entry or not entry[1] or not hmac.compare_digest(key, entry[1]):
                raise ServiceError(401, "unauthorized")
            if not entry[0].enabled:
                raise ServiceError(403, "system_disabled")
            return entry[0]
        if local_demo and host in {"127.0.0.1", "::1", "testclient"}:
            # Reverse-proxied traffic must not become an anonymous local client.
            if "forwarded" not in request.headers and "x-forwarded-for" not in request.headers:
                return Policy("local-demo")
        if checker_mode and request.url.path == "/process":
            if allowed_ips and not any(ipaddress.ip_address(host) in network for network in allowed_ips):
                raise ServiceError(403, "checker_ip_denied")
            return Policy("checker", mode=os.environ.get("PII_CHECKER_MASK", "shape"))
        raise ServiceError(401, "unauthorized")

    async def execute(request: Request, body: ProcessRequest, action: str, mode: str | None = None):
        start = time.perf_counter()
        operation, status = "rejected", 500
        acquired = False
        found_types: list[str] = []
        try:
            policy = authorize(request)
            if mode is not None and mode != policy.mode:
                if policy.tenant != "local-demo":
                    raise ServiceError(403, "mode_is_configured_by_system_policy")
                policy = replace(policy, mode=mode)
            if app.state.inflight >= 64:
                raise ServiceError(429, "busy_retry")
            app.state.inflight += 1
            acquired = True
            handler = app.state.processor
            if action == "restore":
                # Explicit API includes selected mode so the immutable policy matches the session.
                result = await handler.restore(body.payload, body.payload_id, policy)
            else:
                result = await handler.process(body.payload, body.payload_id, policy, mask_only=action == "mask")
            operation, status = result["operation"], 200
            found_types = result["types"]
            for kind in result["types"]:
                entities.labels(kind).inc()
            chars.inc(len(body.payload))
            if action == "process":
                return JSONResponse({"result": result["result"]})
            return JSONResponse({**result, "latency_ms": round((time.perf_counter() - start) * 1000, 2)})
        except ServiceError as exc:
            status = exc.status
            return JSONResponse({"error": exc.code}, status_code=status,
                                headers={"Retry-After": "1"} if status in {429, 503} else None)
        except CapacityError:
            status = 429
            return JSONResponse({"error": "state_capacity_retry"}, status_code=429, headers={"Retry-After": "1"})
        except Exception as exc:
            # Fail closed. Never fall back to sending unprocessed input; never log exception/input repr.
            status = 503
            logger.error("pii_error exception_type=%s", type(exc).__name__)
            return JSONResponse({"error": "processing_unavailable"}, status_code=503, headers={"Retry-After": "1"})
        finally:
            if acquired:
                app.state.inflight -= 1
            elapsed = time.perf_counter() - start
            requests.labels(operation, str(status)).inc()
            latency.labels(operation).observe(elapsed)
            logger.info("pii_request operation=%s status=%s types=%s duration_ms=%.2f",
                        operation, status, ",".join(found_types), elapsed * 1000)

    @app.post("/process", response_model=ProcessResponse)
    async def process(body: ProcessRequest, request: Request):
        return await execute(request, body, "process")

    @app.post("/v1/mask")
    async def mask_route(body: MaskRequest, request: Request):
        return await execute(request, body, "mask", body.mode)

    @app.post("/v1/restore")
    async def restore_route(body: MaskRequest, request: Request):
        return await execute(request, body, "restore", body.mode)

    @app.get("/healthz")
    async def health():
        return {"status": "ok"}

    @app.get("/readyz")
    async def ready():
        try:
            if app.state.processor and await app.state.processor.vault.store.ping():
                return {"status": "ready"}
        except Exception:
            pass
        return JSONResponse({"status": "not_ready"}, status_code=503)

    @app.get("/metrics")
    async def metrics(request: Request):
        try:
            authorize(request)
        except ServiceError as exc:
            return JSONResponse({"error": exc.code}, status_code=exc.status)
        scrape_registry = registry
        if os.environ.get("PROMETHEUS_MULTIPROC_DIR"):
            scrape_registry = CollectorRegistry()
            multiprocess.MultiProcessCollector(scrape_registry)
        return Response(generate_latest(scrape_registry), media_type="text/plain; version=0.0.4")

    @app.get("/", include_in_schema=False)
    async def index():
        return FileResponse(Path(__file__).parent / "static" / "index.html")

    return app


app = create_app()

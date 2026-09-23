from __future__ import annotations

import asyncio
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
from .vault import CapacityError, MemoryStore, RedisStore, Vault, load_key

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
        return await self.app(scope, limited_receive, send)


class AccessControl:
    def __init__(self, policies: dict | None, local_demo: bool | None):
        self.local_demo = os.environ.get("PII_LOCAL_DEMO", "1") == "1" if local_demo is None else local_demo
        self.checker_mode = os.environ.get("PII_CHECKER_MODE", "0") == "1"
        self.allowed_ips = [ipaddress.ip_network(v.strip()) for v in os.environ.get("PII_CHECKER_CIDRS", "").split(",") if v.strip()]
        self.configured = load_policies() if policies is None else policies

    def _system_policy(self, system: str, key: str) -> Policy:
        entry = self.configured.get(system)
        if not entry or not entry[1] or not hmac.compare_digest(key, entry[1]):
            raise ServiceError(401, "unauthorized")
        if not entry[0].enabled:
            raise ServiceError(403, "system_disabled")
        return entry[0]

    def authorize(self, request: Request) -> Policy:
        system = request.headers.get("x-system-id", "")
        if system:
            return self._system_policy(system, request.headers.get("x-api-key", ""))
        host = request.client.host if request.client else ""
        if self.local_demo and host in {"127.0.0.1", "::1", "testclient"}:
            # Reverse-proxied traffic must not become an anonymous local client.
            if "forwarded" not in request.headers and "x-forwarded-for" not in request.headers:
                return Policy("local-demo")
        if self.checker_mode and request.url.path == "/process":
            return self._checker_policy(host)
        raise ServiceError(401, "unauthorized")

    def _checker_policy(self, host: str) -> Policy:
        if self.allowed_ips and not any(ipaddress.ip_address(host) in network for network in self.allowed_ips):
            raise ServiceError(403, "checker_ip_denied")
        return Policy("checker", mode=os.environ.get("PII_CHECKER_MASK", "partial"))


class Telemetry:
    def __init__(self):
        self.registry = CollectorRegistry()
        self.requests = Counter("pii_requests_total", "Requests by bounded outcome", ["operation", "status"], registry=self.registry)
        self.latency = Histogram("pii_request_seconds", "End-to-end handler time", ["operation"], registry=self.registry,
                                 buckets=(.001, .005, .01, .025, .05, .1, .25, .5, 1, 2, 5, 10))
        self.entities = Counter("pii_entity_types_total", "Detected entity types, without values", ["type"], registry=self.registry)
        self.chars = Counter("pii_input_characters_total", "Characters processed; NOT an exact token count", registry=self.registry)

    def add_result(self, kinds: list[str], length: int) -> None:
        for kind in kinds:
            self.entities.labels(kind).inc()
        self.chars.inc(length)

    def observe(self, operation: str, status: int, kinds: list[str], elapsed: float) -> None:
        self.requests.labels(operation, str(status)).inc()
        self.latency.labels(operation).observe(elapsed)
        logger.info("pii_request operation=%s status=%s types=%s duration_ms=%.2f",
                    operation, status, ",".join(kinds), elapsed * 1000)

    def scrape(self) -> bytes:
        registry = self.registry
        if os.environ.get("PROMETHEUS_MULTIPROC_DIR"):
            registry = CollectorRegistry()
            multiprocess.MultiProcessCollector(registry)
        return generate_latest(registry)


def error_response(status: int, code: str) -> JSONResponse:
    headers = {"Retry-After": "1"} if status in {429, 503} else None
    return JSONResponse({"error": code}, status_code=status, headers=headers)


class RequestExecutor:
    def __init__(self, app: FastAPI, request_timeout: float):
        self.app, self.request_timeout = app, request_timeout

    def _policy(self, request: Request, mode: str | None) -> Policy:
        policy = self.app.state.access.authorize(request)
        if mode is not None and mode != policy.mode:
            if policy.tenant != "local-demo":
                raise ServiceError(403, "mode_is_configured_by_system_policy")
            policy = replace(policy, mode=mode)
        return policy

    async def _call(self, body: ProcessRequest, action: str, policy: Policy) -> dict:
        handler = self.app.state.processor
        if action == "restore":
            return await handler.restore(body.payload, body.payload_id, policy)
        return await handler.process(body.payload, body.payload_id, policy, mask_only=action == "mask")

    async def execute(self, request: Request, body: ProcessRequest, action: str, mode: str | None = None):
        start = time.perf_counter()
        operation, status = "rejected", 500
        acquired = False
        found_types: list[str] = []
        try:
            policy = self._policy(request, mode)
            if self.app.state.inflight >= 64:
                raise ServiceError(429, "busy_retry")
            self.app.state.inflight += 1
            acquired = True
            # Includes both database calls and a stale-connection retry.
            async with asyncio.timeout(self.request_timeout):
                result = await self._call(body, action, policy)
            operation, status = result["operation"], 200
            found_types = result["types"]
            self.app.state.telemetry.add_result(found_types, len(body.payload))
            if action == "process":
                return JSONResponse({"result": result["result"]})
            return JSONResponse({**result, "latency_ms": round((time.perf_counter() - start) * 1000, 2)})
        except ServiceError as exc:
            status = exc.status
            return error_response(status, exc.code)
        except CapacityError:
            status = 429
            return error_response(status, "state_capacity_retry")
        except TimeoutError:
            status = 429
            return error_response(status, "processing_deadline_retry")
        except Exception as exc:
            # Fail closed. Never return unprocessed input or log exception/input repr.
            status = 503
            logger.error("pii_error exception_type=%s", type(exc).__name__, exc_info=False)
            return error_response(status, "processing_unavailable")
        finally:
            if acquired:
                self.app.state.inflight -= 1
            self.app.state.telemetry.observe(operation, status, found_types, time.perf_counter() - start)


def _configure_audit_logger() -> None:
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
        logger.addHandler(handler)
    logger.propagate = False


def _create_store(redis_url: str | None, database_url: str | None):
    if redis_url:
        return RedisStore(redis_url)
    if database_url:
        from .postgres import PostgresStore
        return PostgresStore(database_url)
    if os.environ.get("VERCEL"):
        raise ValueError("shared_store_required_on_vercel")
    return MemoryStore()


def _create_processor(checker_mode: bool) -> Processor:
    redis_url, database_url = os.environ.get("PII_REDIS_URL"), os.environ.get("DATABASE_URL")
    store = _create_store(redis_url, database_url)
    vault = Vault(store, load_key(required=bool(redis_url or database_url) or checker_mode),
                  ttl=int(os.environ.get("PII_TTL_SECONDS", "1800")))
    detector = Detector(use_ner=os.environ.get("PII_NER", "1") == "1")
    return Processor(detector, vault)


@asynccontextmanager
async def lifespan(app: FastAPI):
    if not app.state.supplied:
        _configure_audit_logger()
    if app.state.processor is None:
        app.state.processor = _create_processor(app.state.access.checker_mode)
    try:
        yield
    finally:
        if not app.state.supplied:
            await app.state.processor.vault.store.close()


async def validation_error(_request: Request, _error: RequestValidationError):
    # Do not echo the original input in validation responses.
    return JSONResponse({"error": "invalid_request"}, status_code=422)


async def process(body: ProcessRequest, request: Request):
    return await request.app.state.executor.execute(request, body, "process")


async def mask_route(body: MaskRequest, request: Request):
    return await request.app.state.executor.execute(request, body, "mask", body.mode)


async def restore_route(body: MaskRequest, request: Request):
    return await request.app.state.executor.execute(request, body, "restore", body.mode)


async def health():
    return {"status": "ok"}


async def ready(request: Request):
    try:
        processor = request.app.state.processor
        if processor and await processor.vault.store.ping():
            return {"status": "ready"}
    except Exception as exc:
        logger.warning("pii_ready_failure exception_type=%s", type(exc).__name__, exc_info=False)
    return JSONResponse({"status": "not_ready"}, status_code=503)


async def metrics(request: Request):
    try:
        request.app.state.access.authorize(request)
    except ServiceError as exc:
        return JSONResponse({"error": exc.code}, status_code=exc.status)
    return Response(request.app.state.telemetry.scrape(), media_type="text/plain; version=0.0.4")


async def index():
    return FileResponse(Path(__file__).parent / "static" / "index.html")


def create_app(processor: Processor | None = None, *, policies: dict | None = None,
               local_demo: bool | None = None, request_timeout: float = 7.0) -> FastAPI:
    app = FastAPI(title="Alfa PII Proxy", version="0.1.0", lifespan=lifespan)
    app.add_middleware(BodyLimit)
    app.state.processor = processor
    app.state.supplied = processor is not None
    app.state.inflight = 0
    app.state.access = AccessControl(policies, local_demo)
    app.state.telemetry = Telemetry()
    app.state.executor = RequestExecutor(app, request_timeout)
    app.add_exception_handler(RequestValidationError, validation_error)
    app.add_api_route("/process", process, methods=["POST"], response_model=ProcessResponse)
    app.add_api_route("/v1/mask", mask_route, methods=["POST"])
    app.add_api_route("/v1/restore", restore_route, methods=["POST"])
    app.add_api_route("/healthz", health, methods=["GET"])
    app.add_api_route("/readyz", ready, methods=["GET"])
    app.add_api_route("/metrics", metrics, methods=["GET"])
    app.add_api_route("/", index, methods=["GET"], include_in_schema=False)
    return app


app = create_app()

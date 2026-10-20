"""FastAPI Cloud Run Webhook Microservice for UC-03 (Triggered by SecOps SOAR Playbook).

Exposes:
  - `POST /api/v1/soar/verify-user` (Primary SOAR Playbook HTTP Action / IDE Custom Action endpoint)
  - `POST /api/v1/verify-activity`  (Alias endpoint referenced in global architecture diagram)
  - `GET /healthz`                  (Cloud Run readiness/liveness probe)

Includes a zero-dependency stdlib ASGI/HTTP & TestClient fallback when `fastapi`/`uvicorn`
are not installed in the local Python environment, ensuring 100% testability everywhere.
"""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from typing import Any, Callable, Dict, Optional, Tuple

from .agent import (
    FORENSIC_GROUND_TRUTH_DB,
    discover_live_open_case_id,
    load_tenant_context,
    run_soar_hitl_verification_pipeline,
)

SCENARIO_USER_MAP: Dict[str, str] = {
    "A": "dev@empresa.com",
    "SCENARIO_A": "dev@empresa.com",
    "VERIFIED_BENIGN": "dev@empresa.com",
    "B": "cfo@empresa.com",
    "SCENARIO_B": "cfo@empresa.com",
    "COMPROMISED_ACCOUNT": "cfo@empresa.com",
    "C": "admin-ops@empresa.com",
    "SCENARIO_C": "admin-ops@empresa.com",
    "PROMPT_INJECTION": "admin-ops@empresa.com",
}


def process_soar_verify_request(payload: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    """Core handler that validates the SOAR Playbook payload and runs the 4-stage ADK pipeline."""
    if not isinstance(payload, dict):
        return 400, {"error": "Invalid JSON payload: expected object"}

    soar_context = dict(payload.get("soar_context") or {})
    entity_to_verify = dict(payload.get("entity_to_verify") or {})
    execution_mode = str(payload.get("execution_mode", "SYNC_DEMO")).strip()
    is_live = execution_mode.upper() in ("LIVE", "LIVE_SECOPS")

    # Allow scenario shortcut ("A", "B", "C") if provided in payload
    scenario_key = str(payload.get("scenario", "")).upper().strip()
    if scenario_key in SCENARIO_USER_MAP and not is_live:
        mapped_email = SCENARIO_USER_MAP[scenario_key]
        entity_to_verify.setdefault("user_email", mapped_email)
        if not soar_context.get("case_id") or str(soar_context.get("case_id")).startswith("["):
            soar_context["case_id"] = FORENSIC_GROUND_TRUTH_DB[mapped_email]["case_id"]

    if is_live:
        tenant_ctx = load_tenant_context()
        if not soar_context or str(soar_context.get("project_id", "")).startswith(
            ("tu-", "your-", "gcp-secops-demo")
        ):
            soar_context.setdefault(
                "project_id", tenant_ctx.get("project_id", "your-gcp-project-id")
            )
            soar_context.setdefault(
                "customer_id",
                tenant_ctx.get("customer_id", "00000000-0000-0000-0000-000000000000"),
            )
            soar_context.setdefault("region", tenant_ctx.get("region", "us"))
        if (
            not soar_context.get("case_id")
            or str(soar_context.get("case_id")).upper() == "AUTO"
            or str(soar_context.get("case_id")).startswith("[")
            or str(soar_context.get("case_id")) in ("1041", "1042", "1043")
        ):
            soar_context["case_id"] = discover_live_open_case_id()
        if (
            not entity_to_verify.get("user_email")
            or str(entity_to_verify.get("user_email")).startswith("[")
            or str(entity_to_verify.get("user_email")).endswith("@empresa.com")
        ):
            entity_to_verify["user_email"] = "admin@wsexample.org"

    if not soar_context:
        soar_context = {
            "project_id": "gcp-secops-demo-project",
            "customer_id": "c0a80101-secops-demo-uuid",
            "region": "us",
            "case_id": "1042",
            "alert_id": "al_77821b_mass_exfil",
            "alert_name": "Anomalous Mass Cloud Storage & Confidential File Exfiltration",
            "rule_id": "ru_9921_rclone_exfiltration",
        }

    if not entity_to_verify:
        entity_to_verify = {
            "user_email": "cfo@empresa.com",
            "hostname": "WIN-FINANCE-09",
            "source_ip": "185.220.101.45",
        }

    normalized_payload = {
        "soar_context": soar_context,
        "entity_to_verify": entity_to_verify,
        "execution_mode": execution_mode,
    }
    simulated_reply = payload.get("simulated_user_reply")

    result = run_soar_hitl_verification_pipeline(
        soar_payload=normalized_payload,
        simulated_user_reply=simulated_reply,
        live_mode=is_live,
    )
    return 200, result


def process_healthz() -> Tuple[int, Dict[str, Any]]:
    """Health check response for Cloud Run and SOAR webhook connectivity tests."""
    return 200, {
        "status": "ok",
        "service": "uc03-soar-hitl-verifier",
        "trigger": "Google Cloud SecOps SOAR Playbook",
        "endpoints": ["/api/v1/soar/verify-user", "/api/v1/verify-activity", "/healthz"],
    }


# ---------------------------------------------------------------------------
# FastAPI Definition (with transparent stdlib shim if FastAPI is not installed)
# ---------------------------------------------------------------------------
try:
    from fastapi import FastAPI, HTTPException, Request
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel, Field
    FASTAPI_AVAILABLE = True

    class SoarContextModel(BaseModel):
        project_id: str = Field(default="tu-gcp-project-id")
        customer_id: str = Field(default="tu-chronicle-customer-uuid")
        region: str = Field(default="us")
        case_id: str = Field(default="[Case.Id]")
        alert_id: str = Field(default="[Alert.Identifier]")
        alert_name: Optional[str] = Field(default="[Alert.Name]")
        rule_id: Optional[str] = Field(default="[Alert.RuleId]")

    class EntityToVerifyModel(BaseModel):
        user_email: str = Field(default="[Entity.Identifier]")
        hostname: Optional[str] = Field(default="[Alert.PrincipalHostname]")
        source_ip: Optional[str] = Field(default="[Alert.PrincipalIp]")

    class SoarVerifyUserRequest(BaseModel):
        soar_context: SoarContextModel = Field(default_factory=SoarContextModel)
        entity_to_verify: EntityToVerifyModel = Field(default_factory=EntityToVerifyModel)
        execution_mode: str = Field(default="SYNC_DEMO")
        simulated_user_reply: Optional[str] = Field(default=None)
        scenario: Optional[str] = Field(default=None)

    app = FastAPI(
        title="UC-03: SecOps SOAR Playbook -> ADK Autonomous HITL Verifier",
        description=(
            "Cloud Run webhook microservice invoked by a Google Cloud SecOps SOAR Playbook "
            "to interview an employee, filter Prompt Injection with Model Armor, cross-check "
            "their alibi against real-time UDM telemetry, and return the SOAR ScriptResult."
        ),
        version="1.0.0",
    )

    @app.get("/healthz")
    async def healthz_endpoint() -> Dict[str, Any]:
        _, body = process_healthz()
        return body

    @app.post("/api/v1/soar/verify-user")
    @app.post("/api/v1/verify-activity")
    async def verify_user_endpoint(request_body: SoarVerifyUserRequest) -> JSONResponse:
        payload = (
            request_body.model_dump()
            if hasattr(request_body, "model_dump")
            else request_body.dict()
        )
        status_code, response_dict = process_soar_verify_request(payload)
        if status_code >= 400:
            raise HTTPException(status_code=status_code, detail=response_dict)
        return JSONResponse(status_code=status_code, content=response_dict)

except ImportError:
    FASTAPI_AVAILABLE = False

    class _MockHTTPResponse:
        """Response object matching `httpx.Response` / `fastapi.testclient.TestClient`."""

        def __init__(self, status_code: int, body: Dict[str, Any]) -> None:
            self.status_code = status_code
            self._body = body
            self.text = json.dumps(body, ensure_ascii=False)
            self.headers = {"content-type": "application/json"}

        def json(self) -> Dict[str, Any]:
            return self._body

    class _FallbackFastAPIApp:
        """Drop-in FastAPI-compatible application object for environments without `fastapi`."""

        def __init__(self, title: str, version: str = "1.0.0") -> None:
            self.title = title
            self.version = version
            self.routes = [
                {"path": "/healthz", "methods": ["GET"]},
                {"path": "/api/v1/soar/verify-user", "methods": ["POST"]},
                {"path": "/api/v1/verify-activity", "methods": ["POST"]},
            ]

        def dispatch(
            self, method: str, path: str, json_body: Optional[Dict[str, Any]] = None
        ) -> _MockHTTPResponse:
            clean_path = path.split("?")[0].rstrip("/") or "/"
            method_upper = method.upper()
            if method_upper == "GET" and clean_path == "/healthz":
                code, data = process_healthz()
                return _MockHTTPResponse(code, data)
            if method_upper == "POST" and clean_path in (
                "/api/v1/soar/verify-user",
                "/api/v1/verify-activity",
            ):
                code, data = process_soar_verify_request(json_body or {})
                return _MockHTTPResponse(code, data)
            return _MockHTTPResponse(404, {"detail": f"Not Found: {method_upper} {clean_path}"})

        async def __call__(self, scope: Dict[str, Any], receive: Callable[..., Any], send: Callable[..., Any]) -> None:
            """ASGI 3.0 interface compatibility."""
            if scope.get("type") != "http":
                return
            method = scope.get("method", "GET")
            path = scope.get("path", "/")
            body_bytes = b""
            while True:
                message = await receive()
                body_bytes += message.get("body", b"")
                if not message.get("more_body", False):
                    break
            payload = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
            resp = self.dispatch(method, path, payload)
            raw = resp.text.encode("utf-8")
            await send(
                {
                    "type": "http.response.start",
                    "status": resp.status_code,
                    "headers": [[b"content-type", b"application/json"]],
                }
            )
            await send({"type": "http.response.body", "body": raw})

    app = _FallbackFastAPIApp(  # type: ignore[assignment]
        title="UC-03: SecOps SOAR Playbook -> ADK Autonomous HITL Verifier",
        version="1.0.0",
    )


class SOARWebhookTestClient:
    """In-process HTTP test client compatible with `fastapi.testclient.TestClient(app)`."""

    def __init__(self, target_app: Any = None) -> None:
        self.app = target_app or app

    def get(self, path: str, headers: Optional[Dict[str, str]] = None) -> Any:
        if FASTAPI_AVAILABLE:
            from fastapi.testclient import TestClient
            return TestClient(self.app).get(path, headers=headers)
        return self.app.dispatch("GET", path)

    def post(
        self,
        path: str,
        json: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Any:
        if FASTAPI_AVAILABLE:
            from fastapi.testclient import TestClient
            return TestClient(self.app).post(path, json=json, headers=headers)
        return self.app.dispatch("POST", path, json_body=json)


def get_test_client() -> SOARWebhookTestClient:
    """Returns a TestClient instance for testing the SOAR Playbook webhook endpoints."""
    return SOARWebhookTestClient(app)


# ---------------------------------------------------------------------------
# Standalone HTTP Server Runner (uvicorn or stdlib HTTPServer fallback)
# ---------------------------------------------------------------------------
class _StdlibSOARWebhookHandler(BaseHTTPRequestHandler):
    """Stdlib HTTP request handler used when running `python3 -m uc03_soar_hitl_verifier.server`."""

    def do_GET(self) -> None:  # noqa: N802
        if self.path.rstrip("/") == "/healthz":
            code, body = process_healthz()
        else:
            code, body = 404, {"detail": "Not Found"}
        self._write_json(code, body)

    def do_POST(self) -> None:  # noqa: N802
        if self.path.rstrip("/") in ("/api/v1/soar/verify-user", "/api/v1/verify-activity"):
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length) if length > 0 else b"{}"
            try:
                payload = json.loads(raw.decode("utf-8"))
            except Exception as exc:
                self._write_json(400, {"detail": f"Invalid JSON: {exc}"})
                return
            code, body = process_soar_verify_request(payload)
            self._write_json(code, body)
        else:
            self._write_json(404, {"detail": "Not Found"})

    def _write_json(self, status_code: int, body: Dict[str, Any]) -> None:
        encoded = json.dumps(body, indent=2, ensure_ascii=False).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return


def run_server(host: str = "0.0.0.0", port: int = 8080) -> None:
    """Starts the SOAR Playbook Webhook server using uvicorn (if installed) or HTTPServer."""
    try:
        import uvicorn
        if FASTAPI_AVAILABLE:
            uvicorn.run(app, host=host, port=port)
            return
    except ImportError:
        pass

    httpd = HTTPServer((host, port), _StdlibSOARWebhookHandler)
    print(
        f"[UC-03 SOAR Webhook Server] Listening on http://{host}:{port}/api/v1/soar/verify-user"
    )
    httpd.serve_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Run the UC-03 SecOps SOAR Playbook -> ADK Autonomous HITL Verifier Server"
    )
    parser.add_argument("--host", default=os.environ.get("HOST", "0.0.0.0"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8080")))
    args = parser.parse_args()
    run_server(host=args.host, port=args.port)

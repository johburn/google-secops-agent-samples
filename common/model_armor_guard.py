"""Google Cloud Model Armor & Heuristic Prompt Injection Guardrail for ADK Agents.

Provides:
- `inspect_user_input(text: str) -> dict`: Inspects untrusted user chat responses,
  CTI feeds, or case comments for Prompt Injection and Jailbreak attempts
  (e.g., `ignore previous instructions`, `system override`, `verdict=BENIGN`,
  `system prompt`, etc.), with optional live integration against the Google Cloud
  Model Armor REST API (`sanitizeUserPrompt`).
- `before_model_callback(callback_context, llm_request)`: ADK-compatible callback
  that intercepts every incoming prompt before it reaches the Gemini model,
  records the inspection result in `callback_context.state`, and blocks
  adversarial inputs immediately.
- `inspect_reference_list_candidate(entity: str, entity_type: str = "") -> dict`:
  Anti-Poisoning guardrail for UC-02 ensuring external public IPs or Tier-0
  privileged accounts are never silently added to SecOps exclusion Reference Lists.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from .mcp_client import get_access_token, load_tenant_context

# ============================================================================
# Adversarial Prompt Injection & Jailbreak Signatures
# ============================================================================

ADVERSARIAL_PATTERNS: List[Tuple[str, re.Pattern[str]]] = [
    (
        "INSTRUCTION_OVERRIDE",
        re.compile(
            r"\b(ignore|disregard|forget|bypass|override)\b.{0,40}\b(previous|prior|all|above|system|earlier)?\s*(instructions?|prompts?|rules?|directives?|guardrails?)\b",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "SPANISH_INSTRUCTION_OVERRIDE",
        re.compile(
            r"\b(ignora|olvida|omite|descarta|anula)\b.{0,40}\b(instrucciones|reglas|directivas|previas|anteriores|sistema)\b",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "SYSTEM_OVERRIDE_COMMAND",
        re.compile(
            r"\b(system\s+override|admin\s+override|developer\s+mode|jailbreak|sudo\s+mode|god\s+mode|new\s+system\s+prompt)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "SYSTEM_PROMPT_EXTRACTION",
        re.compile(
            r"\b(reveal|print|show|output|repeat|dump)\b.{0,30}\b(system\s+prompt|hidden\s+instructions|secret\s+instructions|initial\s+prompt)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "VERDICT_MANIPULATION",
        re.compile(
            r"(verdict\s*[:=]\s*[\"']?(VERIFIED_BENIGN|BENIGN|SAFE|FALSE_POSITIVE|NOT_MALICIOUS)[\"']?|mark\s+as\s+benign|return\s+verdict|close_benign_case|execute_bulk_close_case)",
            re.IGNORECASE,
        ),
    ),
    (
        "ROLEPLAY_HIJACK",
        re.compile(
            r"\b(you\s+are\s+now\s+a|act\s+as\s+an?\s+unrestricted|pretend\s+to\s+be\s+system)\b",
            re.IGNORECASE,
        ),
    ),
]


def _call_google_cloud_model_armor_api(text: str) -> Optional[Dict[str, Any]]:
    """Calls Google Cloud Model Armor REST API if `MODEL_ARMOR_TEMPLATE_ID` is configured."""
    template_id = os.environ.get("MODEL_ARMOR_TEMPLATE_ID")
    if not template_id:
        return None

    token = get_access_token()
    if not token:
        return None

    ctx = load_tenant_context()
    project_id = os.environ.get("GCP_PROJECT_ID", ctx["project_id"])
    location = os.environ.get("MODEL_ARMOR_LOCATION", "us-central1")
    url = (
        f"https://modelarmor.{location}.rep.googleapis.com/v1/"
        f"projects/{project_id}/locations/{location}/templates/{template_id}:sanitizeUserPrompt"
    )

    payload = json.dumps({"userPromptData": {"text": text}}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        match_state = (
            body.get("sanitizationResult", {})
            .get("filterMatchState", "NO_MATCH_FOUND")
        )
        detected = match_state == "MATCH_FOUND"
        return {
            "safe": not detected,
            "prompt_injection_detected": detected,
            "verdict": "PROMPT_INJECTION_DETECTED" if detected else "SAFE",
            "inspection_status": (
                "BLOCKED (Google Cloud Model Armor Match Found)"
                if detected
                else "PASSED (No Prompt Injection Detected)"
            ),
            "matched_patterns": ["MODEL_ARMOR_API_FILTER_MATCH"] if detected else [],
            "risk_score": 0.99 if detected else 0.01,
            "sanitized_text": "[BLOCKED BY GOOGLE CLOUD MODEL ARMOR]" if detected else text,
            "engine": "google_cloud_model_armor_api",
            "raw_api_response": body,
        }
    except Exception:
        return None


def inspect_user_input(
    text: str,
    use_remote_api: Optional[bool] = None,
) -> Dict[str, Any]:
    """Inspects a user prompt or chat message for Prompt Injection and Jailbreak patterns.

    Args:
        text: Untrusted text from chat user, CTI report, or SOAR case comment.
        use_remote_api: If True (or if `MODEL_ARMOR_TEMPLATE_ID` is set), attempts
            to call the live Google Cloud Model Armor REST API first before
            falling back to deterministic pattern inspection.

    Returns:
        Dictionary with keys:
        - `safe`: bool
        - `prompt_injection_detected`: bool
        - `verdict`: `"SAFE"` or `"PROMPT_INJECTION_DETECTED"`
        - `inspection_status`: Human-readable status string for SOAR Case Wall
        - `matched_patterns`: List of matched rule names
        - `risk_score`: float between 0.0 and 1.0
        - `sanitized_text`: Original text if safe, or redacted block notice
        - `engine`: Inspection engine identifier
    """
    raw_text = text or ""

    if use_remote_api or (use_remote_api is None and os.environ.get("MODEL_ARMOR_TEMPLATE_ID")):
        remote_res = _call_google_cloud_model_armor_api(raw_text)
        if remote_res is not None:
            return remote_res

    matched: List[str] = []
    for label, pattern in ADVERSARIAL_PATTERNS:
        if pattern.search(raw_text):
            matched.append(label)

    detected = len(matched) > 0
    risk_score = min(1.0, 0.85 + 0.05 * len(matched)) if detected else 0.02

    return {
        "safe": not detected,
        "prompt_injection_detected": detected,
        "verdict": "PROMPT_INJECTION_DETECTED" if detected else "SAFE",
        "inspection_status": (
            f"BLOCKED (Prompt Injection Detected: {', '.join(matched)})"
            if detected
            else "PASSED (No Prompt Injection Detected)"
        ),
        "matched_patterns": matched,
        "risk_score": round(risk_score, 2),
        "sanitized_text": (
            "[REDACTED BY MODEL ARMOR: Adversarial Prompt Injection Attempt Blocked]"
            if detected
            else raw_text
        ),
        "engine": "local_heuristic_model_armor_guard",
    }


def _extract_text_from_llm_request(llm_request: Any) -> str:
    """Extracts user text from an ADK `LlmRequest` object, dict, or string."""
    if llm_request is None:
        return ""
    if isinstance(llm_request, str):
        return llm_request
    if isinstance(llm_request, dict):
        if "text" in llm_request:
            return str(llm_request["text"])
        contents = llm_request.get("contents", [])
    else:
        contents = getattr(llm_request, "contents", None) or []

    chunks: List[str] = []
    for content in contents:
        if isinstance(content, str):
            chunks.append(content)
            continue
        role = (
            content.get("role", "user")
            if isinstance(content, dict)
            else getattr(content, "role", "user")
        )
        if role not in ("user", None):
            continue
        parts = (
            content.get("parts", [])
            if isinstance(content, dict)
            else getattr(content, "parts", None) or []
        )
        for part in parts:
            if isinstance(part, str):
                chunks.append(part)
            elif isinstance(part, dict) and "text" in part:
                chunks.append(str(part["text"]))
            elif hasattr(part, "text") and part.text:
                chunks.append(str(part.text))
    return "\n".join(chunks)


def before_model_callback(
    callback_context: Any,
    llm_request: Any,
) -> Optional[Any]:
    """Google ADK `before_model_callback` enforcing Model Armor Prompt Injection defense.

    If `inspect_user_input` detects a Prompt Injection or Jailbreak attempt:
    1. Records the finding in `callback_context.state["model_armor_inspection"]`.
    2. Short-circuits the model call by returning an `LlmResponse` (or dict
       when running outside ADK runtime) instructing immediate escalation to
       `CRITICAL` and `COMPROMISED_ACCOUNT`.
    If the input is safe, returns `None` so the ADK agent proceeds normally.
    """
    user_text = _extract_text_from_llm_request(llm_request)
    inspection = inspect_user_input(user_text)

    # Record inspection metadata in ADK session state if available
    if callback_context is not None:
        state = getattr(callback_context, "state", None)
        if isinstance(state, dict):
            state["model_armor_inspection"] = inspection
            state["prompt_injection_detected"] = inspection["prompt_injection_detected"]

    if not inspection["prompt_injection_detected"]:
        return None

    blocked_payload = {
        "verdict": "COMPROMISED_ACCOUNT",
        "disposition": "PROMPT_INJECTION_BLOCKED",
        "prompt_injection_detected": True,
        "matched_patterns": inspection["matched_patterns"],
        "recommended_playbook_branch": "EXECUTE_IDENTITY_CONTAINMENT",
        "message": (
            "🚨 ALERTA DE SEGURIDAD (Model Armor): Se interceptó y bloqueó un intento "
            f"de Prompt Injection ({', '.join(inspection['matched_patterns'])}). "
            "La ejecución del LLM fue cancelada preventivamente y el caso se escala a CRITICAL."
        ),
    }

    try:
        from google.adk.models.llm_response import LlmResponse
        from google.genai import types

        return LlmResponse(
            content=types.Content(
                role="model",
                parts=[types.Part.from_text(text=json.dumps(blocked_payload))],
            )
        )
    except Exception:
        return blocked_payload


def inspect_reference_list_candidate(
    entity: str,
    entity_type: str = "",
) -> Dict[str, Any]:
    """Anti-Poisoning guardrail for UC-02 Reference List tuning.

    Prohibits automatically adding external public IP addresses or Tier-0
    privileged accounts (`domain_admin`, `tier0`, `root`, `krbtgt`, `dc01`) to
    an exclusion Reference List without an explicit `[!WARNING]` to the human engineer.
    """
    candidate = entity.strip()
    reasons: List[str] = []

    # Check if candidate is an IP address and whether it is outside RFC 1918 internal ranges
    try:
        ip_obj = ipaddress.ip_address(candidate)
        rfc1918_networks = (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("127.0.0.0/8"),
        )
        is_internal_rfc1918 = any(
            isinstance(ip_obj, ipaddress.IPv4Address) and ip_obj in net
            for net in rfc1918_networks
        )
        if not is_internal_rfc1918:
            reasons.append(
                f"External public IP address detected ({candidate}). Auto-allowlisting public IPs is prohibited."
            )
    except ValueError:
        pass

    tier0_keywords = ("tier0", "tier-0", "domain_admin", "enterprise_admin", "krbtgt", "dc01", "root")
    if any(kw in candidate.lower() for kw in tier0_keywords) or "PUBLIC_IP" in entity_type.upper():
        reasons.append(
            f"Tier-0 privileged account or critical asset detected ({candidate})."
        )

    if reasons:
        return {
            "allowed_auto_exclusion": False,
            "entity": candidate,
            "warning_alert": (
                f"> [!WARNING]\n"
                f"> **Anti-Poisoning Guardrail Triggered for `{candidate}`**: "
                + " ".join(reasons)
                + " Requiere aprobación manual explícita del Detection Engineer."
            ),
            "reasons": reasons,
        }

    return {
        "allowed_auto_exclusion": True,
        "entity": candidate,
        "warning_alert": None,
        "reasons": [],
    }

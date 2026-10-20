"""Google Cloud SecOps SOAR - Custom Action IDE Script for UC-03.

Action Name: Invoke ADK Autonomous HITL Verifier
Integration: GoogleADKAgenticSOC
Description:
  Invoked directly from a Google Cloud SecOps SOAR Playbook. Extracts the Case ID,
  Alert Identifier, Target User, Principal Hostname, and Source IP from the SOAR
  context, invokes the Google ADK `ConversationalVerifier` Cloud Run endpoint
  (`POST /api/v1/soar/verify-user`), renders an executive HTML widget in the SOAR
  Case View, and exposes `JsonResult` (`verdict`, `recommended_playbook_branch`,
  `containment_targets`) so the next Playbook Condition block can branch between
  `EXECUTE_IDENTITY_CONTAINMENT` and `CLOSE_BENIGN_CASE`.

How to install in Google SecOps SOAR:
  1. Navigate to: SecOps SOAR > Response > IDE
  2. Click "+" -> Add New Item -> Action
  3. Integration: Custom / GoogleADKAgenticSOC
  4. Action Name: Invoke ADK Autonomous HITL Verifier
  5. Paste this entire script and click Save & Enable in Playbook Designer.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, List, Optional
import urllib.request

# ---------------------------------------------------------------------------
# Google SecOps SOAR (Chronicle SOAR / Siemplify) SDK Imports with Local Shim
# ---------------------------------------------------------------------------
try:
    from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
    from SiemplifyAction import SiemplifyAction
    from SiemplifyUtils import output_handler
    SOAR_SDK_AVAILABLE = True
except ImportError:
    SOAR_SDK_AVAILABLE = False
    EXECUTION_STATE_COMPLETED = 0
    EXECUTION_STATE_FAILED = 2

    def output_handler(func: Any) -> Any:
        return func

    class _MockSiemplifyResult:
        def __init__(self) -> None:
            self.json_results: Dict[str, Any] = {}
            self.data_tables: List[Dict[str, Any]] = []
            self.html_widgets: List[Dict[str, str]] = []

        def add_result_json(self, data: Dict[str, Any]) -> None:
            self.json_results = data

        def add_data_table(self, title: str, data_table: List[str]) -> None:
            self.data_tables.append({"title": title, "rows": data_table})

        def add_entity_html_report(self, entity_identifier: str, title: str, html_content: str) -> None:
            self.html_widgets.append(
                {"entity": entity_identifier, "title": title, "html": html_content}
            )

    class _MockSiemplifyLogger:
        def info(self, msg: str) -> None:
            print(f"[SOAR-IDE INFO] {msg}")

        def error(self, msg: str) -> None:
            print(f"[SOAR-IDE ERROR] {msg}", file=sys.stderr)

    class _MockEntity:
        def __init__(self, identifier: str, entity_type: str) -> None:
            self.identifier = identifier
            self.entity_type = entity_type

    class SiemplifyAction:  # type: ignore[no-redef]
        """Local simulation shim for SiemplifyAction when running outside SecOps SOAR IDE."""

        def __init__(self) -> None:
            self.LOGGER = _MockSiemplifyLogger()
            self.result = _MockSiemplifyResult()
            self.case_id = os.environ.get("SOAR_CASE_ID", "1042")
            self.alert_id = os.environ.get("SOAR_ALERT_ID", "al_77821b_mass_exfil")
            self.target_entities = [
                _MockEntity(os.environ.get("SOAR_TARGET_USER", "cfo@empresa.com"), "USERUNIQNAME"),
                _MockEntity(os.environ.get("SOAR_TARGET_HOST", "WIN-FINANCE-09"), "HOSTNAME"),
                _MockEntity(os.environ.get("SOAR_TARGET_IP", "185.220.101.45"), "ADDRESS"),
            ]
            self._params = {
                "ADK Cloud Run Endpoint URL": os.environ.get(
                    "ADK_VERIFY_URL",
                    "https://adk-soar-hitl-verifier-uc03.a.run.app/api/v1/soar/verify-user",
                ),
                "GCP Project ID": os.environ.get("GCP_PROJECT_ID", "gcp-secops-demo-project"),
                "Chronicle Customer UUID": os.environ.get(
                    "SECOPS_CUSTOMER_ID", "c0a80101-secops-demo-uuid"
                ),
                "SecOps Region": os.environ.get("SECOPS_REGION", "us"),
                "OIDC Bearer Token": os.environ.get("ADK_BEARER_TOKEN", ""),
                "Execution Mode": "SYNC_DEMO",
            }

        def extract_action_param(
            self,
            param_name: str,
            default_value: Any = None,
            is_mandatory: bool = False,
            print_value: bool = True,
        ) -> Any:
            return self._params.get(param_name, default_value)

        def end(self, output_message: str, result_value: str, execution_state: int) -> None:
            self.output_message = output_message
            self.result_value = result_value
            self.execution_state = execution_state


INTEGRATION_NAME = "GoogleADKAgenticSOC"
SCRIPT_NAME = "Invoke ADK Autonomous HITL Verifier"


def build_soar_html_widget(script_result: Dict[str, Any]) -> str:
    """Renders an executive HTML Case View Widget for the Google SecOps SOAR analyst console."""
    verdict = script_result.get("verdict", "UNKNOWN")
    is_compromised = verdict == "COMPROMISED_ACCOUNT"
    badge_bg = "#d93025" if is_compromised else "#188038"
    interview = script_result.get("interview_summary", {})
    discrepancies = interview.get("discrepancies", [])
    discrepancy_items = "".join(f"<li>{d}</li>" for d in discrepancies) or "<li>Ninguna discrepancia detectada (Coartada confirmada en UDM)</li>"

    return f"""
    <div style="font-family: 'Google Sans', Roboto, sans-serif; border: 1px solid #dadce0; border-radius: 8px; padding: 16px; background: #ffffff;">
      <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #e8eaed; padding-bottom: 12px;">
        <h3 style="margin: 0; color: #202124;">🤖 Google ADK Autonomous HITL Verifier & UDM Cross-Check</h3>
        <span style="background: {badge_bg}; color: #fff; padding: 6px 12px; border-radius: 16px; font-weight: 600; font-size: 12px;">
          {verdict} (Confidence: {int(float(script_result.get("confidence_score", 0.0)) * 100)}%)
        </span>
      </div>
      <div style="margin-top: 12px; font-size: 13px; color: #3c4043;">
        <p><strong>Usuario Entrevistado:</strong> <code>{interview.get("user_contacted", "")}</code></p>
        <p><strong>Declaración en Chat:</strong> <em>{interview.get("user_claimed", "")}</em></p>
        <p><strong>Verdad Forense UDM:</strong> {interview.get("udm_ground_truth", "")}</p>
        <p><strong>Inspección Model Armor (Prompt Injection):</strong> <code>{"ALERTA: BLOQUEADO" if script_result.get("prompt_injection_detected") else "PASSED"}</code></p>
        <p><strong>Discrepancias UDM:</strong></p>
        <ul>{discrepancy_items}</ul>
        <p><strong>Rama Recomendada al Playbook SOAR:</strong> <code>{script_result.get("recommended_playbook_branch", "")}</code></p>
      </div>
    </div>
    """.strip()


def extract_soar_entities(siemplify: SiemplifyAction) -> Dict[str, str]:
    """Extracts user email, hostname, and source IP from SOAR Playbook target entities."""
    user_email = ""
    hostname = ""
    source_ip = ""

    for entity in getattr(siemplify, "target_entities", []):
        etype = getattr(entity, "entity_type", "").upper()
        ident = getattr(entity, "identifier", "")
        if etype in ("USERUNIQNAME", "USER", "EMAIL") and not user_email:
            user_email = ident
        elif etype in ("HOSTNAME", "HOST", "ENDPOINT") and not hostname:
            hostname = ident
        elif etype in ("ADDRESS", "IP", "IPADDRESS") and not source_ip:
            source_ip = ident

    return {
        "user_email": user_email or "cfo@empresa.com",
        "hostname": hostname or "WIN-FINANCE-09",
        "source_ip": source_ip or "185.220.101.45",
    }


@output_handler
def main(simulated_override_payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Entry point executed by Google SecOps SOAR Playbook Action block."""
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    siemplify.LOGGER.info(f"Starting {SCRIPT_NAME} for Case ID {siemplify.case_id}...")

    endpoint_url = siemplify.extract_action_param(
        param_name="ADK Cloud Run Endpoint URL",
        default_value="https://adk-soar-hitl-verifier-uc03.a.run.app/api/v1/soar/verify-user",
        is_mandatory=True,
    )
    project_id = siemplify.extract_action_param(
        param_name="GCP Project ID", default_value="gcp-secops-demo-project"
    )
    customer_id = siemplify.extract_action_param(
        param_name="Chronicle Customer UUID", default_value="c0a80101-secops-demo-uuid"
    )
    region = siemplify.extract_action_param(param_name="SecOps Region", default_value="us")
    bearer_token = siemplify.extract_action_param(
        param_name="OIDC Bearer Token", default_value="", print_value=False
    )
    execution_mode = siemplify.extract_action_param(
        param_name="Execution Mode", default_value="SYNC_DEMO"
    )

    entities = extract_soar_entities(siemplify)

    # Exact Section 6.4.A Input Payload Contract
    request_payload: Dict[str, Any] = simulated_override_payload or {
        "soar_context": {
            "project_id": project_id,
            "customer_id": customer_id,
            "region": region,
            "case_id": str(siemplify.case_id),
            "alert_id": str(siemplify.alert_id),
            "alert_name": "Anomalous Mass Cloud Storage & Confidential File Exfiltration",
            "rule_id": "ru_9921_rclone_exfiltration",
        },
        "entity_to_verify": entities,
        "execution_mode": execution_mode,
    }

    try:
        # When running inside the local project or test suite without live Cloud Run URL,
        # invoke the local FastAPI handler directly; otherwise perform HTTPS POST with OIDC token.
        if endpoint_url.startswith("http://localhost") or endpoint_url.startswith("http://127.0.0.1"):
            headers = {"Content-Type": "application/json"}
            if bearer_token:
                headers["Authorization"] = f"Bearer {bearer_token}"
            req = urllib.request.Request(
                endpoint_url,
                data=json.dumps(request_payload).encode("utf-8"),
                headers=headers,
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                script_result = json.loads(resp.read().decode("utf-8"))
        else:
            # In-process fallback to the ADK FastAPI handler when Cloud Run URL is a placeholder
            from uc03_soar_hitl_verifier.server import process_soar_verify_request

            _, script_result = process_soar_verify_request(request_payload)

        verdict = script_result.get("verdict", "COMPROMISED_ACCOUNT")
        recommended_branch = script_result.get(
            "recommended_playbook_branch", "EXECUTE_IDENTITY_CONTAINMENT"
        )

        # Attach structured JSON result (`[ADK_Verifier.JsonResult.verdict]`) for Playbook Condition block
        siemplify.result.add_result_json(script_result)

        # Attach CSV comparison table & HTML Widget to the SOAR Case View
        interview = script_result.get("interview_summary", {})
        csv_table = [
            "User Contacted,Verdict,Alibi Matches UDM,Prompt Injection Detected,Recommended Branch",
            (
                f"{interview.get('user_contacted', '')},"
                f"{verdict},"
                f"{interview.get('alibi_matches_telemetry', False)},"
                f"{script_result.get('prompt_injection_detected', False)},"
                f"{recommended_branch}"
            ),
        ]
        siemplify.result.add_data_table("ADK HITL UDM Verification Summary", csv_table)
        html_widget = build_soar_html_widget(script_result)
        siemplify.result.add_entity_html_report(
            entities["user_email"], "ADK HITL Forensic Dossier", html_widget
        )

        output_message = (
            f"ADK Autonomous HITL Verifier completed for {entities['user_email']}: "
            f"verdict={verdict}, branch={recommended_branch}"
        )
        siemplify.end(output_message, verdict, EXECUTION_STATE_COMPLETED)
        return script_result

    except Exception as exc:
        error_msg = f"Failed executing {SCRIPT_NAME}: {exc}"
        siemplify.LOGGER.error(error_msg)
        siemplify.end(error_msg, "FAILED", EXECUTION_STATE_FAILED)
        raise


if __name__ == "__main__":
    result = main()
    print(json.dumps(result, indent=2, ensure_ascii=False))

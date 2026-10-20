"""Live Google Cloud SecOps E2E Verification Suite.

Executes live integration tests against the configured Google Cloud SecOps SIEM & SOAR
Remote MCP endpoint (`https://chronicle.us.rep.googleapis.com/mcp`) loaded dynamically
via `load_tenant_context()` from `secops_tenant.json` or environment variables.

Verifies:
1. Live MCP JSON-RPC connectivity (`common/mcp_client.py`) and dynamic tenant configuration (`secops_tenant.json`).
2. UC-01 (`uc01_purple_team_agent`) live execution: `validate_rule` self-correction loop,
   `create_rule`, `get_rule` (`alertingEnabled` omitted boolean -> `False`), `list_rule_detections`,
   and CLI `python3 -m uc01_purple_team_agent.demo_cli --live --json-only`.
3. UC-02 (`uc02_rule_doctor_agent`) live execution: `list_rules`, `list_rule_errors`,
   `validate_rule`, `create_rule`, closed SOAR cases discovered dynamically via `list_cases`,
   Reference List `%authorized_ci_cd_runners` update (`get_reference_list` / `update_reference_list`),
   and Anti-Poisoning Guardrail enforcement.
4. UC-03 (`uc03_soar_hitl_verifier`) live execution: `python3 -m uc03_soar_hitl_verifier.demo_simulator --live`,
   `POST /api/v1/soar/verify-user` with `execution_mode: "LIVE_SECOPS"` against an open SOAR Case
   discovered dynamically via `list_cases`, and direct verification via `list_case_comments`
   confirming the forensic dossier comment is persisted on the real SOAR Case Wall.
"""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))


class TestLiveSecOpsCommonClient(unittest.TestCase):
    """Verifies live tenant configuration and JSON-RPC MCP client against the configured SecOps tenant."""

    def test_live_tenant_config_and_access_token(self) -> None:
        from common.mcp_client import get_access_token, load_tenant_context

        ctx = load_tenant_context()
        self.assertTrue(ctx.get("project_id"))
        self.assertNotIn(
            ctx["project_id"],
            ("your-gcp-project-id", "tu-gcp-project-id", "<YOUR_GCP_PROJECT_ID>"),
        )
        self.assertTrue(ctx.get("customer_id"))
        self.assertNotIn(
            ctx["customer_id"],
            (
                "00000000-0000-0000-0000-000000000000",
                "tu-chronicle-customer-uuid",
                "<YOUR_CHRONICLE_CUSTOMER_UUID>",
            ),
        )
        self.assertEqual(ctx["region"], "us")
        self.assertTrue(ctx.get("mcp_endpoint", "").startswith("https://"))
        self.assertTrue(ctx.get("account"))

        token = get_access_token()
        self.assertIsNotNone(token)
        self.assertTrue(
            str(token).startswith("ya29."),
            "Expected live OAuth2 access token starting with ya29.",
        )

    def test_live_mcp_tools_list_and_core_calls(self) -> None:
        from common.mcp_client import call_secops_mcp_tool, list_secops_mcp_tools

        tools = list_secops_mcp_tools()
        self.assertGreaterEqual(len(tools), 50)
        tool_names = {t.get("name") for t in tools}
        for expected_tool in (
            "list_rules",
            "get_rule",
            "validate_rule",
            "create_rule",
            "list_rule_errors",
            "list_cases",
            "get_case",
            "list_case_comments",
            "create_case_comment",
            "get_reference_list",
            "update_reference_list",
            "udm_search",
        ):
            self.assertIn(expected_tool, tool_names)

        rules_resp = call_secops_mcp_tool("list_rules", {"pageSize": 5})
        self.assertFalse(rules_resp.get("isError"))
        self.assertGreater(len(rules_resp.get("rules", [])), 0)


class TestLiveUC01PurpleTeam(unittest.TestCase):
    """Verifies UC-01 (`uc01_purple_team_agent`) live execution on the configured SecOps tenant."""

    def test_uc01_live_demo_cli_and_backend_rule_verification(self) -> None:
        from common.mcp_client import call_secops_mcp_tool

        proc = subprocess.run(
            [sys.executable, "-m", "uc01_purple_team_agent.demo_cli", "--live", "--json-only"],
            cwd=str(ROOT_DIR),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, f"UC-01 --live failed:\n{proc.stderr}")

        contract = json.loads(proc.stdout.strip())
        self.assertEqual(contract["use_case"], "UC-01_Autonomous_Purple_Team")
        self.assertEqual(contract["synthetic_events_generated"], 3)
        self.assertTrue(contract["verified_gap"])

        gen_rule = contract["generated_rule"]
        self.assertEqual(gen_rule["rule_name"], "rundll32_comsvcs_lsass_memory_dump")
        self.assertTrue(gen_rule["syntax_validated"])
        self.assertEqual(gen_rule["historical_noise_72h"], 0)
        self.assertIs(gen_rule["alerting_enabled"], False)

        deployed_rule_id = gen_rule["deployed_rule_id"]
        self.assertTrue(deployed_rule_id.startswith("ru_"))

        # Verify directly against the live SecOps MCP endpoint via get_rule
        live_rule = call_secops_mcp_tool("get_rule", {"ruleId": deployed_rule_id})
        self.assertFalse(live_rule.get("isError"))
        self.assertIn(deployed_rule_id, live_rule.get("name", ""))
        self.assertEqual(live_rule.get("displayName"), "rundll32_comsvcs_lsass_memory_dump")
        self.assertEqual(live_rule.get("compilationState"), "SUCCEEDED")
        self.assertFalse(bool(live_rule.get("alertingEnabled", False)))


class TestLiveUC02RuleDoctor(unittest.TestCase):
    """Verifies UC-02 (`uc02_rule_doctor_agent`) live execution on the configured SecOps tenant."""

    def test_uc02_live_demo_cli_and_reference_list_verification(self) -> None:
        from common.mcp_client import call_secops_mcp_tool

        proc = subprocess.run(
            [sys.executable, "-m", "uc02_rule_doctor_agent.demo_cli", "--live", "--json"],
            cwd=str(ROOT_DIR),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, f"UC-02 --live --json failed:\n{proc.stderr}")

        payload = json.loads(proc.stdout.strip())
        self.assertEqual(payload["use_case"], "UC-02_SecOps_Health_and_Rule_Optimization_Doctor")
        self.assertTrue(payload["live_mode"])

        # Branch A live verification
        branch_a = payload["branch_a_timeout_auditor"]
        self.assertGreaterEqual(branch_a["total_rules_scanned"], 1)
        self.assertGreaterEqual(branch_a["timeout_errors_found"], 1)
        opt_rule = branch_a["optimized_rules"][0]
        self.assertEqual(opt_rule["validation"]["compilationState"], "SUCCEEDED")
        self.assertTrue(opt_rule["deployment"]["ruleId"].startswith("ru_"))

        # Branch B live verification
        branch_b = payload["branch_b_fp_reference_list_tuner"]
        self.assertGreaterEqual(branch_b["closed_cases_analyzed"], 1)
        cluster = branch_b["repetitive_fp_clusters"][0]
        self.assertEqual(cluster["entity_value"], "build-runner-04")
        self.assertGreaterEqual(len(cluster["sample_case_ids"]), 1)
        for sample_cid in cluster["sample_case_ids"]:
            self.assertTrue(str(sample_cid).strip())
        self.assertIn("build-runner-04", branch_b["reference_list_after"])
        self.assertEqual(branch_b["validation"]["compilationState"], "SUCCEEDED")
        self.assertTrue(branch_b["deployment"]["ruleId"].startswith("ru_"))

        # Verify Anti-Poisoning Guardrail blocked public IP and Tier-0 entity
        guard_test = payload["anti_poisoning_guardrail_test"]
        self.assertEqual(guard_test["result_status"], "BLOCKED_BY_ANTI_POISONING_GUARDRAIL")
        self.assertFalse(guard_test["reference_list_modified"])
        self.assertEqual(len(guard_test["blocked_entries"]), 2)

        # Directly verify Reference List in the live SecOps tenant via MCP get_reference_list
        live_ref = call_secops_mcp_tool("get_reference_list", {"name": "authorized_ci_cd_runners"})
        self.assertFalse(live_ref.get("isError"))
        entries = [
            e.get("value", "") if isinstance(e, dict) else str(e)
            for e in live_ref.get("entries", [])
        ]
        self.assertIn("build-runner-04", entries)
        self.assertNotIn("185.220.101.45", entries)
        self.assertNotIn("adm-tier0-domainadmin", entries)


class TestLiveUC03SoarHitlVerifier(unittest.TestCase):
    """Verifies UC-03 (`uc03_soar_hitl_verifier`) live SOAR & SIEM execution on the configured SecOps tenant."""

    def test_uc03_live_demo_simulator_cli(self) -> None:
        proc = subprocess.run(
            [sys.executable, "-m", "uc03_soar_hitl_verifier.demo_simulator", "--live"],
            cwd=str(ROOT_DIR),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, f"UC-03 --live failed:\n{proc.stderr}")
        self.assertIn("COMPROMISED_ACCOUNT", proc.stdout)
        self.assertRegex(proc.stdout, r"cases/\d+/caseComments/")

    def test_uc03_live_webhook_post_and_case_wall_comment_verification(self) -> None:
        from common.mcp_client import call_secops_mcp_tool, load_tenant_context
        from uc03_soar_hitl_verifier.agent import discover_live_open_case_id
        from uc03_soar_hitl_verifier.server import get_test_client

        tenant_ctx = load_tenant_context()
        discovered_case_id = discover_live_open_case_id()
        self.assertTrue(discovered_case_id)

        client = get_test_client()
        payload = {
            "soar_context": {
                "project_id": tenant_ctx["project_id"],
                "customer_id": tenant_ctx["customer_id"],
                "region": tenant_ctx["region"],
                "case_id": "AUTO",
                "alert_id": "de_8f0c82e7-81c9-4e11-8892-1b80b63e7b11",
                "alert_name": "SCC: BigQuery Exfiltration to Google Drive with DLP Context",
                "rule_id": "ru_scc_bq_exfil",
            },
            "entity_to_verify": {
                "user_email": "admin@wsexample.org",
                "hostname": "AD.prod.mycompany.com",
                "source_ip": "104.132.138.65",
            },
            "execution_mode": "LIVE_SECOPS",
        }
        resp = client.post("/api/v1/soar/verify-user", json=payload)
        self.assertEqual(resp.status_code, 200)
        res = resp.json()

        resolved_cid = res["case_id"]
        self.assertEqual(resolved_cid, discovered_case_id)
        self.assertEqual(res["verdict"], "COMPROMISED_ACCOUNT")
        self.assertEqual(res["disposition"], "TRUE_POSITIVE")
        self.assertFalse(res["interview_summary"]["alibi_matches_telemetry"])
        self.assertTrue(res["soar_actions_taken_by_agent"]["case_comment_posted"])
        self.assertEqual(res["recommended_playbook_branch"], "EXECUTE_IDENTITY_CONTAINMENT")

        # Verify via live `list_case_comments` on the SecOps MCP server
        # that the forensic dossier was genuinely written to the discovered case's Case Wall
        live_comments_resp = call_secops_mcp_tool(
            "list_case_comments", {"caseId": resolved_cid}
        )
        self.assertFalse(live_comments_resp.get("isError"))
        case_comments = live_comments_resp.get("caseComments", [])
        self.assertGreater(len(case_comments), 0)

        matching_dossiers = [
            c
            for c in case_comments
            if "ADK Autonomous User Verification & UDM Cross-Check Dossier" in c.get("comment", "")
            and "admin@wsexample.org" in c.get("comment", "")
        ]
        self.assertGreater(
            len(matching_dossiers),
            0,
            f"Expected forensic dossier comment in live SOAR Case #{resolved_cid} Case Wall",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)

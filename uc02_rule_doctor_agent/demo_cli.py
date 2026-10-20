"""Executable CLI Demo for UC-02: SecOps Health & Rule Optimization Doctor.

Run with:
    python3 -m uc02_rule_doctor_agent.demo_cli
    python3 -m uc02_rule_doctor_agent.demo_cli --live
    python3 -m uc02_rule_doctor_agent.demo_cli --live --json
    python3 -m uc02_rule_doctor_agent.demo_cli --json

Demonstrates:
- Branch A (`RuleHealthAuditorAgent`): Auditing `list_rules` and `list_rule_errors`, diagnosing
  YARA-L timeout anti-patterns, rewriting optimized YARA-L 2.0 with before/after unified diff,
  validating via `validate_rule`, and deploying via `create_rule`.
- Branch B (`FalsePositiveTunerAgent`): Mining `list_cases` and `list_case_comments` across closed
  SOAR FP cases for `suspicious_powershell_download`, updating Reference List `%authorized_ci_cd_runners`
  with `build-runner-04` via `update_reference_list`, linking the Reference List in YARA-L 2.0 with
  before/after diff, validating via `validate_rule`, and deploying via `create_rule`.
- Anti-Poisoning Safety Guardrail test: Attempting to exclude external public IP
  `185.220.101.45` and Tier-0 account `adm-tier0-domainadmin` and verifying they are
  blocked with explicit `[!WARNING]` alerts.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, Optional

from .agent import (
    FalsePositiveTunerAgent,
    RuleHealthAuditorAgent,
    is_mock_mode,
    load_tenant_context,
    reset_mock_state,
    root_agent,
    run_branch_a_timeout_doctor,
    run_branch_b_fp_tuner,
    update_reference_list,
)


def _print_banner(title: str) -> None:
    line = "=" * 88
    print(f"\n{line}\n{title}\n{line}")


def run_demo(
    output_json_only: bool = False,
    live_mode: Optional[bool] = None,
) -> Dict[str, Any]:
    """Executes the end-to-end UC-02 SecOps Rule Doctor demonstration."""
    use_live = not is_mock_mode(live_mode)
    if not use_live:
        reset_mock_state()

    tenant = load_tenant_context()

    # 1. Execute Branch A: YARA-L Timeout Auditor & Optimizer
    branch_a_result = run_branch_a_timeout_doctor(
        auto_deploy=True,
        live_mode=use_live,
    )

    # 2. Execute Branch B: SOAR Closed Case FP Miner & Reference List Tuner
    branch_b_result = run_branch_b_fp_tuner(
        min_fp_threshold=5,
        reference_list_name="authorized_ci_cd_runners",
        auto_apply=True,
        live_mode=use_live,
    )

    # 3. Explicit Anti-Poisoning Guardrail Test (Public IP + Tier-0 Account)
    poison_test_inputs = ["185.220.101.45", "adm-tier0-domainadmin", "build-runner-05"]
    poison_attempt_result = update_reference_list(
        name="authorized_ci_cd_runners",
        entries=poison_test_inputs,
        force_override=False,
        live_mode=use_live,
    )

    summary_payload: Dict[str, Any] = {
        "use_case": "UC-02_SecOps_Health_and_Rule_Optimization_Doctor",
        "live_mode": use_live,
        "tenant": tenant,
        "adk_coordinator_agent": root_agent.name,
        "sub_agents": [RuleHealthAuditorAgent.name, FalsePositiveTunerAgent.name],
        "branch_a_timeout_auditor": branch_a_result,
        "branch_b_fp_reference_list_tuner": branch_b_result,
        "anti_poisoning_guardrail_test": {
            "attempted_entries": poison_test_inputs,
            "result_status": poison_attempt_result["status"],
            "reference_list_modified": poison_attempt_result["updated"],
            "warnings": poison_attempt_result["guardrail"]["warnings"],
            "blocked_entries": poison_attempt_result["guardrail"]["blocked_entries"],
        },
    }

    if output_json_only:
        print(json.dumps(summary_payload, indent=2, ensure_ascii=False))
        return summary_payload

    _print_banner(
        "🩺 UC-02: SecOps Health & Rule Optimization Doctor (Google ADK + SecOps MCP)"
    )
    print(f"Coordinator Agent : {root_agent.name} ({root_agent.model})")
    print(
        f"Sub-Agents        : 1) {RuleHealthAuditorAgent.name} | 2) {FalsePositiveTunerAgent.name}"
    )
    print(
        f"Execution Mode    : {'LIVE Google Cloud SecOps Remote MCP (' + str(tenant.get('mcp_endpoint', 'https://chronicle.us.rep.googleapis.com/mcp')) + ')' if use_live else 'SECOPS_MOCK_MODE (Self-Contained Deterministic Demo)'}"
    )
    if use_live:
        print(
            f"SecOps Tenant     : project={tenant.get('project_id')} | "
            f"customer_id={tenant.get('customer_id')} | region={tenant.get('region')}"
        )
    print(
        'User Prompt (agy) : "/secops-doctor Audita las reglas con errores de timeout y las que tienen más falsos positivos esta semana"'
    )

    # -----------------------------------------------------------------------
    # Print Branch A Details
    # -----------------------------------------------------------------------
    _print_banner(
        "🔍 RAMA A: Diagnóstico de Rendimiento y Errores de Timeout YARA-L (RuleHealthAuditorAgent)"
    )
    print(f"• Reglas totales auditadas (`list_rules`)       : {branch_a_result['total_rules_scanned']}")
    print(f"• Reglas con errores de timeout (`list_rule_errors`): {branch_a_result['timeout_errors_found']}")

    for item in branch_a_result["optimized_rules"]:
        print(f"\n[!] Regla Detectada con Fallo de Ejecución:")
        print(f"    - Rule ID          : {item['rule_id']}")
        print(f"    - Rule Name        : {item['rule_name']}")
        print(f"    - alertingEnabled  : {item['alerting_enabled_before']} (Protobuf omitted -> False)")
        print(f"    - Error MCP        : {item['error_message']}")
        print("\n[Diagnóstico de Anti-Patrones YARA-L 2.0]:")
        for idx, ap in enumerate(item["anti_patterns"], start=1):
            print(f"  {idx}. [{ap['severity']}] {ap['id']}: {ap['finding']}")
            print(f"     -> Corrección: {ap['fix']}")

        print("\n[Diff YARA-L 2.0 (Antes vs. Después — Rama A)]:")
        print("-" * 88)
        print(item["yaral_diff"].rstrip())
        print("-" * 88)
        print(
            f"[Validación MCP (`validate_rule`)] : compilationState={item['validation']['compilationState']} "
            f"| performanceOptimized={item['validation']['performanceOptimized']}"
        )
        if item["deployment"]:
            print(
                f"[Despliegue MCP (`create_rule`)]   : ruleId={item['deployment']['ruleId']} "
                f"| revisionId={item['deployment']['revisionId']} | executionState={item['deployment']['executionState']}"
            )

    # -----------------------------------------------------------------------
    # Print Branch B Details
    # -----------------------------------------------------------------------
    _print_banner(
        "🎯 RAMA B: Tuning Automático de Falsos Positivos con Reference Lists (FalsePositiveTunerAgent)"
    )
    print(
        f"• Casos cerrados en SOAR analizados (`list_cases(filter='status=\"CLOSED\"')`): "
        f"{branch_b_result['closed_cases_analyzed']}"
    )
    for cluster in branch_b_result["repetitive_fp_clusters"]:
        print(f"\n[+] Patrón Repetitivo de Falso Positivo Identificado (`list_case_comments`):")
        print(f"    - Regla Ruidosa    : {cluster['rule_name']} ({cluster['rule_id']})")
        print(f"    - Casos Cerrados   : {cluster['fp_case_count']} ocurrencias cerradas como NOT_MALICIOUS (SOAR Case IDs: {cluster['sample_case_ids']})")
        print(f"    - Causas Raíz SOAR : {', '.join(cluster['root_causes'])}")
        print(f"    - Host Legítimo    : {cluster['entity_value']} ({cluster['entity_field']})")
        print(f"    - Nota Tier 1      : \"{cluster['sample_analyst_comment']}\"")

    print(f"\n[Actualización de Reference List (`%{branch_b_result['reference_list_name']}`)]:")
    print(f"    - Antes (`get_reference_list`)     : {branch_b_result['reference_list_before']}")
    print(f"    - Después (`update_reference_list`): {branch_b_result['reference_list_after']}")
    if branch_b_result.get("reference_list_revision_time"):
        print(f"    - Revision Timestamp (Live SecOps) : {branch_b_result['reference_list_revision_time']}")

    print("\n[Diff YARA-L 2.0 (Vinculación de Reference List `%authorized_ci_cd_runners` — Rama B)]:")
    print("-" * 88)
    print(branch_b_result["yaral_diff"].rstrip())
    print("-" * 88)
    if branch_b_result["validation"]:
        print(
            f"[Validación MCP (`validate_rule`)] : compilationState={branch_b_result['validation']['compilationState']}"
        )
    if branch_b_result["deployment"]:
        print(
            f"[Despliegue MCP (`create_rule`)]   : ruleId={branch_b_result['deployment']['ruleId']} "
            f"| revisionId={branch_b_result['deployment']['revisionId']}"
        )

    # -----------------------------------------------------------------------
    # Print Anti-Poisoning Guardrail Verification
    # -----------------------------------------------------------------------
    _print_banner(
        "🛡️ PRUEBA DE GUARDRAIL DE SEGURIDAD (Anti-Poisoning Policy Verification)"
    )
    print(
        f"Intentando agregar entidades de alto riesgo a `%{branch_b_result['reference_list_name']}`: "
        f"{poison_test_inputs}"
    )
    print(f"Estado devuelto por `update_reference_list`: {poison_attempt_result['status']}")
    print(f"¿Se modificó la Reference List?            : {poison_attempt_result['updated']}")
    print("\nAlertas emitidas por el Guardrail Anti-Poisoning:")
    for warn in poison_attempt_result["guardrail"]["warnings"]:
        print(f"  {warn}")

    _print_banner("✅ RESUMEN EJECUTIVO JSON (UC-02 Completado)")
    compact_summary = {
        "use_case": summary_payload["use_case"],
        "live_mode": use_live,
        "total_rules_scanned": branch_a_result["total_rules_scanned"],
        "timeout_rules_fixed": branch_a_result["timeout_errors_found"],
        "fixed_timeout_rule_id": branch_a_result["optimized_rules"][0]["rule_id"],
        "deployed_optimized_timeout_rule_id": (
            branch_a_result["optimized_rules"][0]["deployment"]["ruleId"]
            if branch_a_result["optimized_rules"][0].get("deployment")
            else None
        ),
        "fp_cases_mined": branch_b_result["repetitive_fp_clusters"][0]["fp_case_count"],
        "soar_closed_case_ids": branch_b_result["repetitive_fp_clusters"][0]["sample_case_ids"],
        "tuned_fp_rule_id": branch_b_result["repetitive_fp_clusters"][0]["rule_id"],
        "deployed_tuned_fp_rule_id": (
            branch_b_result["deployment"]["ruleId"]
            if branch_b_result.get("deployment")
            else None
        ),
        "reference_list_updated": f"%{branch_b_result['reference_list_name']}",
        "reference_list_entries": branch_b_result["reference_list_after"],
        "anti_poisoning_guardrail_enforced": not poison_attempt_result["updated"],
    }
    print(json.dumps(compact_summary, indent=2, ensure_ascii=False))
    return summary_payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="UC-02: SecOps Health & Rule Optimization Doctor CLI Demo"
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Execute live MCP calls against the configured Google Cloud SecOps tenant (secops_tenant.json).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit full structured JSON output only.",
    )
    args = parser.parse_args(argv)
    if args.live:
        os.environ["SECOPS_MOCK_MODE"] = "false"
    live_mode = True if args.live else (not is_mock_mode())
    run_demo(output_json_only=args.json, live_mode=live_mode)
    return 0


if __name__ == "__main__":
    sys.exit(main())

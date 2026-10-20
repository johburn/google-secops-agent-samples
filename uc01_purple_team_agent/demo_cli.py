#!/usr/bin/env python3
"""Executable CLI Demo Runner for UC-01: Autonomous Purple Team & Detection-as-Code.

Run from the workspace root:
    python3 -m uc01_purple_team_agent.demo_cli
    python3 -m uc01_purple_team_agent.demo_cli --live
    python3 -m uc01_purple_team_agent.demo_cli --live --json-only
    python3 -m uc01_purple_team_agent.demo_cli --json-only
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict

from .agent import (
    CoverageEvaluatorAgent,
    ThreatIntelToTdoAgent,
    YaraLAuthorAndValidatorAgent,
    is_live_secops_mode,
    root_agent,
    run_purple_team_pipeline,
)

# ANSI styling constants for terminal output
BOLD = "\033[1m"
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"
DIM = "\033[2m"
RESET = "\033[0m"


def _banner(title: str) -> None:
    line = "═" * 78
    print(f"\n{CYAN}{BOLD}╔{line}╗{RESET}")
    print(f"{CYAN}{BOLD}║ {title:<76} ║{RESET}")
    print(f"{CYAN}{BOLD}╚{line}╝{RESET}")


def _step(num: int, agent_name: str, title: str) -> None:
    print(
        f"\n{BOLD}{MAGENTA}[Step {num}] ({agent_name}){RESET} "
        f"{BOLD}{title}{RESET}"
    )
    print(f"{DIM}{'─' * 80}{RESET}")


def load_default_cti_report() -> str:
    """Loads `sample_cti_report.md` from the package directory."""
    report_path = os.path.join(
        os.path.dirname(__file__), "sample_cti_report.md"
    )
    with open(report_path, "r", encoding="utf-8") as f:
        return f.read()


def render_rich_demo(result: Dict[str, Any], cti_path: str) -> None:
    """Prints a rich step-by-step Purple Team execution walkthrough to stdout."""
    trace = result["pipeline_trace"]
    contract = result["contract_output"]
    session_state = trace["session_state"]
    tdo_bundle = session_state["tdo_bundle"]
    cov_eval = session_state["coverage_evaluation"]
    live_mode = bool(trace.get("live_mode", False))
    tenant = trace.get("tenant", {})

    _banner(
        "UC-01: AUTONOMOUS PURPLE TEAM & DETECTION-AS-CODE (Google ADK + SecOps MCP)"
    )
    print(
        f"  • {BOLD}Root Orchestrator:{RESET}  {root_agent.name} "
        f"(Sub-Agents: {ThreatIntelToTdoAgent.name}, "
        f"{CoverageEvaluatorAgent.name}, {YaraLAuthorAndValidatorAgent.name})"
    )
    print(f"  • {BOLD}Advisory Source:{RESET}    {cti_path}")
    print(
        f"  • {BOLD}Execution Mode:{RESET}     "
        f"{'LIVE Google Cloud SecOps Remote MCP (' + str(tenant.get('mcp_endpoint', 'https://chronicle.us.rep.googleapis.com/mcp')) + ')' if live_mode else 'SECOPS_MOCK_MODE (Self-Contained Deterministic Demo)'}"
    )
    if live_mode:
        print(
            f"  • {BOLD}SecOps Tenant:{RESET}      project={tenant.get('project_id')} | "
            f"customer_id={tenant.get('customer_id')} | region={tenant.get('region')}"
        )

    # Step 1: Model Armor Guard
    _step(
        1,
        ThreatIntelToTdoAgent.name,
        "Model Armor Guard — Prompt Injection & Jailbreak Inspection",
    )
    armor = trace["model_armor_inspection"]
    is_safe = armor.get("safe", armor.get("is_safe", True))
    print(
        f"  {GREEN}✔ Input Sanitized:{RESET} safe={is_safe} | "
        f"prompt_injection_detected={armor.get('prompt_injection_detected')}"
    )

    # Step 2: TDO Extraction
    _step(
        2,
        ThreatIntelToTdoAgent.name,
        "MCP Tool Call: `generate_threat_detection_opportunity`",
    )
    for idx, tdo in enumerate(tdo_bundle["tdos"], start=1):
        print(
            f"  {CYAN}[TDO #{idx}]{RESET} ID: {BOLD}{tdo['id']}{RESET} | "
            f"MITRE: {YELLOW}{', '.join(tdo['mitre_attack'])}{RESET} | "
            f"Severity: {RED}{tdo['severity']}{RESET}"
        )
        print(f"           Title: {tdo['title']}")

    # Step 3: Synthetic UDM Events Generation
    _step(
        3,
        ThreatIntelToTdoAgent.name,
        "MCP Tool Call: `generate_synthetic_events` -> Extracting `udmsJson`",
    )
    udms_json = tdo_bundle["udmsJson"]
    print(
        f"  {GREEN}✔ Generated {len(udms_json)} synthetic UDM events{RESET} "
        "(single-level serialized JSON in `session.state['tdo_bundle']['udmsJson']`):"
    )
    for idx, udm_str in enumerate(udms_json, start=1):
        udm_obj = json.loads(udm_str)
        cmd = udm_obj["target"]["process"]["command_line"]
        host = udm_obj["principal"]["hostname"]
        ev_type = udm_obj["metadata"]["event_type"]
        print(
            f"    {DIM}{idx}.{RESET} [{ev_type}] Host={BOLD}{host}{RESET} | "
            f"Cmd={YELLOW}{cmd}{RESET}"
        )

    # Step 4: Rule Coverage Evaluation (LRO + Polling + Protobuf boolean rule)
    _step(
        4,
        CoverageEvaluatorAgent.name,
        "MCP Tool Calls: `evaluate_rule_coverage_long_running`, `list_rules` & `get_rule`",
    )
    print(f"  • LRO Operation Name: {DIM}{cov_eval['operation_name']}{RESET}")
    if cov_eval.get("live_corpus_rules_checked"):
        print(
            f"  • Live SecOps Corpus Rules Checked (`list_rules`): "
            f"{BOLD}{cov_eval['live_corpus_rules_checked']}{RESET}"
        )
    print(
        f"  • Polling `get_operation`: done={BOLD}{cov_eval['done']}{RESET} | "
        f"coverageResults={BOLD}{cov_eval['coverage_results']}{RESET}"
    )
    print(
        f"  • Protobuf Boolean Normalization Check (`get_rule({cov_eval.get('baseline_rule_id')})` omitted `alertingEnabled`): "
        f"interpreted strictly as {BOLD}alerting_enabled={cov_eval['baseline_rule_alerting_enabled']}{RESET}"
    )
    print(
        f"  {RED}⚠ VERIFIED DETECTION GAP:{RESET} "
        f"verified_gap={BOLD}{cov_eval['verified_gap']}{RESET} "
        "(0 active rules detected the synthetic LSASS comsvcs.dll MiniDump telemetry)"
    )

    # Step 5: YARA-L 2.0 Generation & Self-Correction Validation Loop
    _step(
        5,
        YaraLAuthorAndValidatorAgent.name,
        "MCP Tool Calls: `generate_rules` & `validate_rule` (Self-Correction Loop)",
    )
    for attempt in trace["validation_attempts"]:
        state = attempt["compilationState"]
        badge = f"{GREEN}SUCCEEDED{RESET}" if state == "SUCCEEDED" else f"{YELLOW}FAILED (Auto-Fixing){RESET}"
        print(
            f"  • Iteration #{attempt['iteration']}: `validate_rule` -> {badge}"
        )
        if attempt["diagnostics"]:
            for diag in attempt["diagnostics"]:
                print(f"      Diagnostic: {RED}{diag}{RESET}")
        print(f"      Action:     {attempt['action']}")

    print(f"\n  {BOLD}Validated YARA-L 2.0 Rule Code:{RESET}")
    for line in trace["yara_l_code"].splitlines():
        print(f"    {CYAN}{line}{RESET}")

    # Step 6: Historical Noise Check + Rule Deployment & Verification
    _step(
        6,
        YaraLAuthorAndValidatorAgent.name,
        "MCP Tool Calls: `list_rule_detections` (72h), `create_rule` & `get_rule`",
    )
    gen_rule = contract["generated_rule"]
    verified_rule = trace.get("verified_deployed_rule") or {}
    print(
        f"  {GREEN}✔ 72h Retro-Hunt Noise Check (`list_rule_detections`):{RESET} "
        f"{gen_rule['historical_noise_72h']} false positives in the last 72 hours"
    )
    print(
        f"  {GREEN}✔ Deployed Rule (`create_rule` & `get_rule`):{RESET} "
        f"ruleId={BOLD}{gen_rule['deployed_rule_id']}{RESET} | "
        f"revisionId={BOLD}{verified_rule.get('revisionId', 'v_1')}{RESET} | "
        f"alerting_enabled={BOLD}{gen_rule['alerting_enabled']}{RESET} (safe burn-in mode)"
    )
    if verified_rule.get("name"):
        print(
            f"  {GREEN}✔ Live Resource Name:{RESET} {BOLD}{verified_rule['name']}{RESET}"
        )

    # Final JSON Contract Output (Section 4.4 of UseCasesSpec.md)
    _banner("FINAL STRUCTURED OUTPUT CONTRACT (UseCasesSpec.md Section 4.4)")
    print(json.dumps(contract, indent=2, ensure_ascii=False))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="UC-01: Autonomous Purple Team & Detection-as-Code CLI Demo"
    )
    parser.add_argument(
        "--cti-file",
        default=os.path.join(
            os.path.dirname(__file__), "sample_cti_report.md"
        ),
        help="Path to the Threat Intelligence report markdown file.",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Execute live MCP calls against the configured Google Cloud SecOps tenant (secops_tenant.json).",
    )
    parser.add_argument(
        "--json-only",
        action="store_true",
        help="Output only the Section 4.4 JSON contract to stdout.",
    )
    args = parser.parse_args(argv)

    if args.live:
        os.environ["SECOPS_MOCK_MODE"] = "false"

    live_mode = True if args.live else is_live_secops_mode()

    with open(args.cti_file, "r", encoding="utf-8") as f:
        cti_text = f.read()

    result = run_purple_team_pipeline(
        cti_text=cti_text,
        auto_deploy=True,
        simulate_self_correction=True,
        live_mode=live_mode,
    )

    if args.json_only:
        print(json.dumps(result["contract_output"], indent=2, ensure_ascii=False))
    else:
        render_rich_demo(result, cti_path=args.cti_file)

    return 0


if __name__ == "__main__":
    sys.exit(main())

"""UC-03: Conversational User Verifier (HITL) con Verificación Cruzada UDM & Model Armor.

Exposes `root_agent` for `adk web` and `adk run uc03_soar_hitl_verifier`, as well as
the 4-stage ADK sub-agents and the SOAR Playbook execution pipeline.
"""

from .agent import (
    employee_interviewer_agent,
    forensic_ground_truth_agent,
    root_agent,
    run_soar_hitl_verification_pipeline,
    soar_case_updater_agent,
    udm_alibi_fact_checker_agent,
)

__all__ = [
    "root_agent",
    "forensic_ground_truth_agent",
    "employee_interviewer_agent",
    "udm_alibi_fact_checker_agent",
    "soar_case_updater_agent",
    "run_soar_hitl_verification_pipeline",
]

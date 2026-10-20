"""UC-01: Autonomous Purple Team & Detection-as-Code Package.

Exposes `root_agent` and `agent` so `adk web` and `adk run uc01_purple_team_agent`
work out of the box.
"""

from . import agent
from .agent import (
    CoverageEvaluatorAgent,
    ThreatIntelToTdoAgent,
    YaraLAuthorAndValidatorAgent,
    YaraLValidationLoopAgent,
    parse_rule_alerting_enabled,
    root_agent,
    run_purple_team_pipeline,
)

__all__ = [
    "agent",
    "root_agent",
    "ThreatIntelToTdoAgent",
    "CoverageEvaluatorAgent",
    "YaraLAuthorAndValidatorAgent",
    "YaraLValidationLoopAgent",
    "parse_rule_alerting_enabled",
    "run_purple_team_pipeline",
]

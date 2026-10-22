"""Outcome and failure-reason taxonomies for evaluation trials.

Two orthogonal dimensions are recorded per trial: a single Outcome state, and
(for any non-success) a structured FailureReason. Partial progress is a
diagnostic, never counted as success. INFRA_ERROR is retried by the runner and
never charged against the agent.
"""
from enum import Enum


class Outcome(str, Enum):
    VERIFIED_SUCCESS = "verified_success"
    VERIFIED_FAILURE = "verified_failure"
    PARTIAL = "partial"
    TIMEOUT = "timeout"
    AGENT_ERROR = "agent_error"
    INFRA_ERROR = "infra_error"
    INCONCLUSIVE = "inconclusive"


class FailureReason(str, Enum):
    MODEL_REASONING = "model_reasoning"
    TOOL_EXECUTION = "tool_execution"
    ORCHESTRATION = "orchestration"
    CONFIGURATION = "configuration"
    INFRASTRUCTURE = "infrastructure"
    BUDGET_EXHAUSTION = "budget_exhaustion"
    VERIFICATION = "verification"
    POLICY = "policy_refusal"   # the model declined (stop_reason == "refusal") - not a solve failure


SUCCESS = {Outcome.VERIFIED_SUCCESS}
# Outcomes that mean "the harness broke", not "the agent failed" - excluded from
# agent solve-rate denominators and retried by the runner.
INFRA = {Outcome.INFRA_ERROR}

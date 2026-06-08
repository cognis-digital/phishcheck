"""PHISHCHECK - defensive phishing-signal scoring for URLs and emails.

Analysis/triage/detection only. No unauthorized attack capability, no network
calls. Pure-stdlib heuristic engine for authorized inbox/URL triage.
"""
from .core import (
    score_url,
    score_email,
    UrlFinding,
    EmailFinding,
    Verdict,
    RISK_THRESHOLDS,
)

TOOL_NAME = "phishcheck"
TOOL_VERSION = "1.0.0"

__all__ = [
    "score_url",
    "score_email",
    "UrlFinding",
    "EmailFinding",
    "Verdict",
    "RISK_THRESHOLDS",
    "TOOL_NAME",
    "TOOL_VERSION",
]

"""PHISHCHECK — Score URLs/emails for phishing signals (lookalike, auth, intent)."""
from phishcheck.core import scan, TOOL_NAME, TOOL_VERSION
__all__ = ["scan", "TOOL_NAME", "TOOL_VERSION"]

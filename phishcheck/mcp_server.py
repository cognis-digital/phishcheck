"""PHISHCHECK MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from phishcheck.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-phishcheck[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-phishcheck[mcp]'")
        return 1
    app = FastMCP("phishcheck")

    @app.tool()
    def phishcheck_scan(target: str) -> str:
        """Score URLs/emails for phishing signals (lookalike, auth, intent). Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("mail")


@mcp.tool()
def send_email(to: str, body: str) -> str:
    """Send an email."""
    return f"sent to {to}: {body}"


import contextvars
import hashlib
import os

from mcp.server.fastmcp import FastMCP, Context
from mcp.server.transport_security import TransportSecuritySettings

EMAIL = "24f2008212@ds.study.iitm.ac.in"

# Stores the challenge for the current HTTP request only.
request_challenge = contextvars.ContextVar(
    "request_challenge", default=None
)


class ChallengeHeaderMiddleware:
    """Capture the challenge header for each incoming HTTP request."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        challenge = headers.get(b"x-exam-challenge", b"").decode("ascii")

        token = request_challenge.set(challenge)
        try:
            await self.app(scope, receive, send)
        finally:
            request_challenge.reset(token)


mcp = FastMCP(
    "Exam Challenge Server",
    stateless_http=True,
    json_response=True,
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=[
            "mcp-challenge-n6so.onrender.com",
        ],
    ),
)



@mcp.tool()
def solve_challenge(ctx: Context) -> str:
    """Solve the current HTTP request's challenge."""
    challenge = request_challenge.get()

    if not challenge:
        raise ValueError("Missing X-Exam-Challenge header")

    value = f"{challenge}:{EMAIL}"
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


# Disable localhost-only host protection for public deployment.
security = TransportSecuritySettings(
    enable_dns_rebinding_protection=False
)

inner_app = mcp.streamable_http_app()

app = ChallengeHeaderMiddleware(inner_app)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "8000")),
    )


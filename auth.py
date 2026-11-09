"""Static Bearer token check. The server only stores the SHA-256, never the token."""
from __future__ import annotations

import hashlib
import hmac

from mcp.server.auth.provider import AccessToken


class StaticTokenVerifier:
    def __init__(self, sha256_hashes: list[str]):
        if not sha256_hashes:
            raise RuntimeError("MCP_TOKEN_SHA256 is empty: the server refuses to start without authentication")
        self._hashes = [h.lower() for h in sha256_hashes]

    async def verify_token(self, token: str) -> AccessToken | None:
        digest = hashlib.sha256(token.encode()).hexdigest()
        ok = False
        for good in self._hashes:  # check all of them: constant time regardless of which one matches
            ok |= hmac.compare_digest(digest, good)
        if not ok:
            return None
        return AccessToken(token="***", client_id="opsgate", scopes=["ops"], expires_at=None)

"""Small server-side OIDC authorization-code session store for local Phase 4.

Opaque browser cookies identify server-held tokens.  JavaScript never receives a
bearer token.  This deliberately has no distributed persistence: Phase 8 will
replace it with a production session store.
"""

from dataclasses import dataclass
from secrets import token_urlsafe
from time import time


@dataclass(frozen=True)
class PendingLogin:
    verifier: str
    expires_at: float


@dataclass(frozen=True)
class BrowserSession:
    access_token: str
    expires_at: float


class LocalOidcSessionStore:
    def __init__(self) -> None:
        self._pending: dict[str, PendingLogin] = {}
        self._sessions: dict[str, BrowserSession] = {}

    def begin(self, verifier: str, ttl_seconds: int = 300) -> str:
        state = token_urlsafe(32)
        self._pending[state] = PendingLogin(verifier, time() + ttl_seconds)
        return state

    def consume(self, state: str) -> PendingLogin | None:
        pending = self._pending.pop(state, None)
        return pending if pending and pending.expires_at >= time() else None

    def create(self, access_token: str, expires_in: int) -> str:
        session_id = token_urlsafe(32)
        self._sessions[session_id] = BrowserSession(access_token, time() + expires_in)
        return session_id

    def token(self, session_id: str | None) -> str | None:
        if not session_id:
            return None
        session = self._sessions.get(session_id)
        if session is None or session.expires_at < time():
            self._sessions.pop(session_id, None)
            return None
        return session.access_token

    def revoke(self, session_id: str | None) -> None:
        if session_id:
            self._sessions.pop(session_id, None)


local_oidc_sessions = LocalOidcSessionStore()

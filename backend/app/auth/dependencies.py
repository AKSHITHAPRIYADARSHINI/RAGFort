"""Safe FastAPI dependency building blocks for provider-independent identity."""

from collections.abc import Callable
from typing import Annotated, Protocol

from fastapi import Header

from backend.app.auth.models import Principal, RequestContext


class AuthenticationError(RuntimeError):
    code = "UNAUTHENTICATED"
    message = "Authentication is required."


class AuthenticationUnavailableError(RuntimeError):
    code = "AUTHENTICATION_UNAVAILABLE"
    message = "Authentication is unavailable right now."


class TokenValidator(Protocol):
    """An OIDC implementation must validate signature and required JWT claims."""

    def validate(self, token: str) -> Principal: ...


class RequestContextResolver(Protocol):
    """Resolves a verified external principal to current server-side policy data."""

    def resolve(self, principal: Principal) -> RequestContext: ...


def extract_bearer_token(authorization: str | None) -> str:
    """Reject malformed schemes rather than attempting permissive parsing."""
    if authorization is None:
        raise AuthenticationError()
    scheme, separator, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not separator or not token.strip() or " " in token.strip():
        raise AuthenticationError()
    return token.strip()


def build_request_context_dependency(
    validator: TokenValidator, resolver: RequestContextResolver
) -> Callable[..., RequestContext]:
    """Return a dependency suitable for routes without exposing auth configuration."""

    def require_context(
        authorization: Annotated[str | None, Header()] = None,
    ) -> RequestContext:
        token = extract_bearer_token(authorization)
        principal = validator.validate(token)
        return resolver.resolve(principal)

    return require_context

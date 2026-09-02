"""PyJWT/JWKS OIDC validator; provider configuration remains outside routes."""

from dataclasses import dataclass
from typing import Any

import jwt
from jwt import PyJWKClient
from jwt.exceptions import PyJWTError

from backend.app.auth.dependencies import AuthenticationError, AuthenticationUnavailableError
from backend.app.auth.models import Principal


@dataclass(frozen=True)
class OidcConfiguration:
    issuer: str
    audience: str
    jwks_url: str
    algorithms: tuple[str, ...] = ("RS256",)
    tenant_claim: str = "tenant_id"

    def __post_init__(self) -> None:
        if not self.issuer or not self.audience or not self.jwks_url:
            raise ValueError("OIDC issuer, audience, and JWKS URL are required")
        if not self.algorithms or any(
            algorithm not in {"RS256", "ES256"} for algorithm in self.algorithms
        ):
            raise ValueError("only explicitly configured asymmetric JWT algorithms are allowed")


class PyJwtOidcValidator:
    """Validates signature and registered claims before creating a Principal."""

    def __init__(self, config: OidcConfiguration, jwks_client: Any | None = None) -> None:
        self.config = config
        self.jwks_client = jwks_client or PyJWKClient(config.jwks_url)

    def validate(self, token: str) -> Principal:
        try:
            signing_key = self.jwks_client.get_signing_key_from_jwt(token).key
        except Exception as error:
            raise AuthenticationUnavailableError() from error
        try:
            claims = jwt.decode(
                token,
                signing_key,
                algorithms=list(self.config.algorithms),
                audience=self.config.audience,
                issuer=self.config.issuer,
                options={"require": ["exp", "iat", "sub"]},
            )
        except PyJWTError as error:
            raise AuthenticationError() from error
        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject:
            raise AuthenticationError()
        name = claims.get("name")
        tenant_hint = claims.get(self.config.tenant_claim)
        return Principal(
            subject=subject,
            issuer=self.config.issuer,
            authenticated_at=(
                claims.get("auth_time") if isinstance(claims.get("auth_time"), int) else None
            ),
            display_name=name if isinstance(name, str) else None,
            tenant_hint=tenant_hint if isinstance(tenant_hint, str) and tenant_hint else None,
        )

# ADR-003: OIDC authentication

## Context
Enterprise identity must be validated without browser-held service secrets.

## Decision
Support OAuth 2.0/OpenID Connect with short-lived JWTs validated by FastAPI; use an authorization epoch/revocation mechanism.

## Alternatives and reasoning
Local passwords and long-lived opaque tokens increase credential/operational risk. OIDC interoperates with enterprise identity providers and delivers signed claims, but claims must be validated and refreshed.

## Implications
Issuer, audience, expiry, signature, tenant binding, and revocation are server-side checks. Authentication is Phase 4; failure denies.

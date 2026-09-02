# ADR-018: Provider-independent OIDC identity boundary

## Context

Phase 4 needs a real, standards-based trust boundary without coupling RAGFort to a
specific cloud identity provider or committing local bootstrap credentials.

## Decision

RAGFort will validate short-lived OIDC JWT access tokens at the FastAPI boundary
through issuer discovery/JWKS and a fixed asymmetric algorithm allow-list.  The
application will convert verified token identity to a canonical, database-backed
principal before policy evaluation.  A local Keycloak service is an optional
development integration profile, not an authorization authority embedded in code.

## Alternatives

Custom passwords and browser-managed role claims were rejected because they expand
credential risk and make the browser an authority.  A Keycloak-only implementation
was rejected because it would make the backend provider-specific and require
committed bootstrap user credentials for repeatable tests.

## Security implications

The API must validate signature, issuer, audience, expiry, not-before, key identity,
and required claims.  It must reject unsupported algorithms, unknown keys, missing
tenant bindings, disabled accounts, and stale authorization epochs.  It must fail
closed when identity or policy dependencies are unavailable.

## Consequences

Tests may use generated asymmetric keys and a local JWKS fixture.  The local IdP
profile requires operator-supplied, untracked credentials; no browser receives a
client secret or access to Qdrant, PostgreSQL, or an LLM provider.

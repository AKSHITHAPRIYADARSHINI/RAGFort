# Local Keycloak OIDC profile

This profile is a development integration aid for Phase 4. Keycloak provides
OIDC tokens only; RAGFort's PostgreSQL records remain the authorization
authority for tenants, roles, account state, and authorization epochs.

## Bootstrap

1. Copy `.env.keycloak.example` to the ignored `.env.keycloak.local`.
2. Replace both placeholder values with local generated secrets. Do not commit
   that file and do not use a personal or production password.
3. Start the identity service with `docker compose up -d keycloak`.
4. Provision the synthetic realm and database identities:

   ```powershell
   $env:KEYCLOAK_ADMIN_URL = "http://localhost:8080"
   $env:KEYCLOAK_ADMIN = "ragfort-local-admin"
   $env:KEYCLOAK_ADMIN_PASSWORD = "<local secret>"
   $env:RAGFORT_DEV_USER_PASSWORD = "<local synthetic-user secret>"
   python -m backend.scripts.seed_identities
   ```

The seeder creates a public authorization-code client (`ragfort-frontend`) and
the resource audience (`ragfort-api`). It does not create or store a browser
client secret. Redirect URIs are loopback development URLs only.

The script writes only Keycloak subject IDs, display names, tenants, roles, and
authorization state to PostgreSQL. It never writes access tokens, refresh
tokens, passwords, or bootstrap credentials to the database.

## Runtime endpoints

- Browser issuer: `http://localhost:8080/realms/ragfort-local`
- Discovery: `/.well-known/openid-configuration` below that issuer
- JWKS: `/protocol/openid-connect/certs` below that issuer
- API-to-Keycloak JWKS traffic: `http://keycloak:8080/...` inside Compose

The backend validates the browser-visible issuer and obtains keys over the
internal Docker network. This avoids an issuer mismatch while keeping the
provider implementation replaceable.

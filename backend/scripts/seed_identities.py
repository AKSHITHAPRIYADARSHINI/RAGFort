"""Provision deterministic, synthetic Phase 4 identities for local OIDC runs.

This command is deliberately operator-gated: it requires credentials from the
ignored local environment and never writes passwords or tokens to PostgreSQL.
It is idempotent, so it can be used after a local Keycloak restart without
creating duplicate realm users or application memberships.
"""

import json
import os
from dataclasses import dataclass
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from sqlalchemy import delete, select

from backend.app.auth.persistence import (
    MembershipRoleRecord,
    RoleRecord,
    TenantMembershipRecord,
    TenantRecord,
    UserRecord,
)
from backend.app.documents.persistence import make_session_factory

REALM = "ragfort-local"
FRONTEND_CLIENT_ID = "ragfort-frontend"
RUNTIME_CLIENT_ID = "ragfort-runtime-test"
API_AUDIENCE = "ragfort-api"
DEFAULT_ISSUER = f"http://localhost:8080/realms/{REALM}"


@dataclass(frozen=True)
class SyntheticIdentity:
    key: str
    display_name: str
    tenant_id: str
    department: str
    role_names: tuple[str, ...]


# These are synthetic local identities only. Passwords are read from the
# ignored environment at execution time and are never represented here.
SYNTHETIC_IDENTITIES = (
    SyntheticIdentity("acme_employee", "ACME Employee", "tenant_acme", "general", ("viewer",)),
    SyntheticIdentity(
        "acme_finance_reader",
        "ACME Finance Reader",
        "tenant_acme",
        "finance",
        ("viewer", "finance_reader"),
    ),
    SyntheticIdentity(
        "acme_hr_reader", "ACME HR Reader", "tenant_acme", "hr", ("viewer", "hr_reader")
    ),
    SyntheticIdentity(
        "acme_knowledge_manager",
        "ACME Knowledge Manager",
        "tenant_acme",
        "knowledge",
        ("reviewer",),
    ),
    SyntheticIdentity(
        "acme_security_analyst",
        "ACME Security Analyst",
        "tenant_acme",
        "security",
        ("reviewer",),
    ),
    SyntheticIdentity(
        "globex_employee", "GLOBEX Employee", "tenant_globex", "general", ("viewer",)
    ),
    SyntheticIdentity(
        "globex_knowledge_manager",
        "GLOBEX Knowledge Manager",
        "tenant_globex",
        "knowledge",
        ("reviewer",),
    ),
)

TENANTS = {"tenant_acme": "ACME", "tenant_globex": "GLOBEX"}
ROLE_NAMES = tuple(
    sorted({role for identity in SYNTHETIC_IDENTITIES for role in identity.role_names})
)


def _required(name: str) -> str:
    value = os.getenv(name, "")
    if not value or value.startswith("REPLACE_WITH_"):
        raise RuntimeError(f"{name} must be set to a local, non-placeholder value.")
    return value


class KeycloakAdmin:
    def __init__(self, base_url: str, username: str, password: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self._token: str | None = None

    def _access_token(self) -> str:
        if self._token is not None:
            return self._token
        payload = urlencode(
            {
                "client_id": "admin-cli",
                "grant_type": "password",
                "username": self.username,
                "password": self.password,
            }
        ).encode()
        request = Request(
            f"{self.base_url}/realms/master/protocol/openid-connect/token",
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        self._token = str(self._request(request)["access_token"])
        return self._token

    def _request(self, request: Request, allow_not_found: bool = False):
        try:
            with urlopen(request, timeout=15) as response:  # noqa: S310 - configured local IdP only
                body = response.read()
                return json.loads(body.decode()) if body else None
        except HTTPError as error:
            if allow_not_found and error.code == 404:
                return None
            detail = error.read().decode(errors="replace")[:200]
            raise RuntimeError(f"Keycloak request failed ({error.code}): {detail}") from error

    def _admin_request(
        self,
        method: str,
        path: str,
        payload: dict | list | None = None,
        allow_not_found: bool = False,
    ):
        encoded = json.dumps(payload).encode() if payload is not None else None
        return self._request(
            Request(
                f"{self.base_url}/admin{path}",
                data=encoded,
                headers={
                    "Authorization": f"Bearer {self._access_token()}",
                    "Content-Type": "application/json",
                },
                method=method,
            ),
            allow_not_found=allow_not_found,
        )

    def ensure_realm(self) -> None:
        if self._admin_request("GET", f"/realms/{REALM}", allow_not_found=True) is None:
            self._admin_request(
                "POST",
                "/realms",
                {
                    "realm": REALM,
                    "enabled": True,
                    "registrationAllowed": False,
                    "resetPasswordAllowed": False,
                    "verifyEmail": False,
                },
            )

    def configure_local_runtime_actions(self) -> None:
        """Disable profile-completion actions only in the synthetic local realm.

        These actions make password-grant runtime probes fail before token
        issuance. They are not disabled in a production identity provider;
        this seeder is explicitly limited to the local development realm.
        """
        for alias in ("UPDATE_PROFILE", "VERIFY_PROFILE", "VERIFY_EMAIL"):
            self._admin_request(
                "PUT",
                f"/realms/{REALM}/authentication/required-actions/{alias}",
                {"alias": alias, "enabled": False, "defaultAction": False},
            )

    def ensure_role(self, role_name: str) -> dict:
        path = f"/realms/{REALM}/roles/{role_name}"
        role = self._admin_request("GET", path, allow_not_found=True)
        if role is None:
            self._admin_request("POST", f"/realms/{REALM}/roles", {"name": role_name})
            role = self._admin_request("GET", path)
        return role

    def ensure_client(self, client_id: str, payload: dict) -> None:
        clients = self._admin_request(
            "GET", f"/realms/{REALM}/clients?{urlencode({'clientId': client_id})}"
        )
        if not clients:
            self._admin_request("POST", f"/realms/{REALM}/clients", payload)
            return
        # Keep the local realm declarative and idempotent when its configuration
        # changes between development runs.
        self._admin_request("PUT", f"/realms/{REALM}/clients/{clients[0]['id']}", payload)

    def ensure_clients(self) -> None:
        self.ensure_client(
            API_AUDIENCE, {"clientId": API_AUDIENCE, "bearerOnly": True, "enabled": True}
        )
        # This client exists solely for non-browser local runtime validation.
        # The browser client remains authorization-code-only; no production
        # configuration enables the password grant.
        self.ensure_client(
            RUNTIME_CLIENT_ID,
            {
                "clientId": RUNTIME_CLIENT_ID,
                "enabled": True,
                "publicClient": True,
                "standardFlowEnabled": False,
                "directAccessGrantsEnabled": True,
                "protocol": "openid-connect",
            },
        )
        self.ensure_client(
            FRONTEND_CLIENT_ID,
            {
                "clientId": FRONTEND_CLIENT_ID,
                "enabled": True,
                "publicClient": True,
                "standardFlowEnabled": True,
                "directAccessGrantsEnabled": False,
                "redirectUris": ["http://localhost:3000/*", "http://127.0.0.1:3000/*"],
                "webOrigins": ["http://localhost:3000", "http://127.0.0.1:3000"],
                "protocol": "openid-connect",
            },
        )
        clients = self._admin_request(
            "GET", f"/realms/{REALM}/clients?{urlencode({'clientId': FRONTEND_CLIENT_ID})}"
        )
        client_uuid = clients[0]["id"]
        mappers = self._admin_request(
            "GET", f"/realms/{REALM}/clients/{client_uuid}/protocol-mappers/models"
        )
        names = {mapper["name"] for mapper in mappers}
        mapper_path = f"/realms/{REALM}/clients/{client_uuid}/protocol-mappers/models"
        if "tenant-id" not in names:
            self._admin_request(
                "POST",
                mapper_path,
                {
                    "name": "tenant-id",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-usermodel-attribute-mapper",
                    "config": {
                        "user.attribute": "tenant_id",
                        "claim.name": "tenant_id",
                        "jsonType.label": "String",
                        "access.token.claim": "true",
                        "id.token.claim": "true",
                        "userinfo.token.claim": "true",
                    },
                },
            )
        if "ragfort-api-audience" not in names:
            self._admin_request(
                "POST",
                mapper_path,
                {
                    "name": "ragfort-api-audience",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-audience-mapper",
                    "config": {
                        "included.client.audience": API_AUDIENCE,
                        "access.token.claim": "true",
                        "id.token.claim": "false",
                    },
                },
            )

    def ensure_user(self, identity: SyntheticIdentity, password: str) -> str:
        users = self._admin_request(
            "GET", f"/realms/{REALM}/users?{urlencode({'username': identity.key, 'exact': 'true'})}"
        )
        data = {
            "username": identity.key,
            "enabled": True,
            "emailVerified": True,
            "email": f"{identity.key}@ragfort.local",
            "lastName": "User",
            "requiredActions": [],
            "firstName": identity.display_name,
            "attributes": {"tenant_id": [identity.tenant_id], "department": [identity.department]},
        }
        if not users:
            self._admin_request("POST", f"/realms/{REALM}/users", data)
            users = self._admin_request(
                "GET",
                f"/realms/{REALM}/users?{urlencode({'username': identity.key, 'exact': 'true'})}",
            )
        user_id = str(users[0]["id"])
        self._admin_request(
            "PUT",
            f"/realms/{REALM}/users/{user_id}/reset-password",
            # Synthetic identities are used only in the ignored local profile.
            # A non-temporary password permits the isolated runtime test client
            # to obtain a token; browser login remains authorization-code-only.
            {"type": "password", "temporary": False, "value": password},
        )
        # Resetting credentials may reinstate a required action in some
        # Keycloak versions, so clear the local-only user profile afterwards.
        self._admin_request("PUT", f"/realms/{REALM}/users/{user_id}", data)
        desired_roles = [self.ensure_role(role) for role in identity.role_names]
        self._admin_request(
            "POST", f"/realms/{REALM}/users/{user_id}/role-mappings/realm", desired_roles
        )
        return user_id


def persist_application_identities(
    subjects: dict[str, str], issuer: str, database_url: str
) -> None:
    """Persist only canonical identity/authorization data, never credentials."""
    factory = make_session_factory(database_url)
    with factory.begin() as session:
        for tenant_id, name in TENANTS.items():
            tenant = session.get(TenantRecord, tenant_id)
            if tenant is None:
                session.add(TenantRecord(id=tenant_id, name=name, active=True))
            else:
                tenant.name, tenant.active = name, True
        session.flush()

        roles: dict[str, RoleRecord] = {}
        for role_name in ROLE_NAMES:
            role = session.scalar(select(RoleRecord).where(RoleRecord.name == role_name))
            if role is None:
                role = RoleRecord(id=f"role_{role_name}", name=role_name)
                session.add(role)
                session.flush()
            roles[role_name] = role

        for identity in SYNTHETIC_IDENTITIES:
            user = session.scalar(
                select(UserRecord).where(
                    UserRecord.issuer == issuer, UserRecord.subject == subjects[identity.key]
                )
            )
            if user is None:
                user = UserRecord(
                    id=f"user_{identity.key}",
                    issuer=issuer,
                    subject=subjects[identity.key],
                    display_name=identity.display_name,
                    department=identity.department,
                    active=True,
                    authorization_epoch=0,
                )
                session.add(user)
                session.flush()
            else:
                user.display_name = identity.display_name
                user.department = identity.department
                user.active = True
            membership = session.scalar(
                select(TenantMembershipRecord).where(
                    TenantMembershipRecord.user_id == user.id,
                    TenantMembershipRecord.tenant_id == identity.tenant_id,
                )
            )
            if membership is None:
                membership = TenantMembershipRecord(
                    id=f"membership_{identity.key}",
                    user_id=user.id,
                    tenant_id=identity.tenant_id,
                    active=True,
                    authorization_epoch=0,
                )
                session.add(membership)
                session.flush()
            else:
                membership.active = True
            session.execute(
                delete(MembershipRoleRecord).where(
                    MembershipRoleRecord.membership_id == membership.id
                )
            )
            session.add_all(
                [
                    MembershipRoleRecord(membership_id=membership.id, role_id=roles[role].id)
                    for role in identity.role_names
                ]
            )


def main() -> None:
    base_url = os.getenv("KEYCLOAK_ADMIN_URL", "http://localhost:8080")
    admin = KeycloakAdmin(
        base_url, _required("KEYCLOAK_ADMIN"), _required("KEYCLOAK_ADMIN_PASSWORD")
    )
    password = _required("RAGFORT_DEV_USER_PASSWORD")
    admin.ensure_realm()
    admin.configure_local_runtime_actions()
    admin.ensure_clients()
    subjects = {
        identity.key: admin.ensure_user(identity, password) for identity in SYNTHETIC_IDENTITIES
    }
    persist_application_identities(
        subjects,
        os.getenv("OIDC_ISSUER", DEFAULT_ISSUER),
        os.getenv("DATABASE_URL", "sqlite:///./ragfort-documents.db"),
    )
    print(
        f"Provisioned {len(subjects)} synthetic identities in {REALM}; no credentials were stored."
    )


if __name__ == "__main__":
    main()

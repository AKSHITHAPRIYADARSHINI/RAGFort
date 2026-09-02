import { ApiRequestError, authenticatedFetch } from "./client";

/** Safe identity information intentionally limited to the `/api/v1/me` contract. */
export type SessionUser = {
  display_name: string;
  tenant_id: string;
  roles: string[];
};

export type SessionState =
  | { status: "loading" }
  | { status: "authenticated"; user: SessionUser }
  | { status: "unauthenticated" }
  | { status: "expired" }
  | { status: "unavailable" };

type MeEnvelope = {
  success: boolean;
  data?: SessionUser;
  error?: { code?: string; message?: string };
};

export async function readSession(): Promise<SessionState> {
  try {
    const response = await authenticatedFetch("/api/v1/me");
    const payload = (await response.json()) as MeEnvelope;
    if (response.ok && payload.success && payload.data) return { status: "authenticated", user: payload.data };
    if (response.status === 401) return payload.error?.code === "SESSION_EXPIRED" ? { status: "expired" } : { status: "unauthenticated" };
    return { status: "unavailable" };
  } catch (error) {
    return error instanceof ApiRequestError && error.status === 401 ? { status: "unauthenticated" } : { status: "unavailable" };
  }
}

/** Login is an IdP-owned redirect, never a browser-managed token substitute. */
export function loginUrl(): string | null {
  const configured = process.env.NEXT_PUBLIC_OIDC_LOGIN_URL;
  return configured && configured.startsWith("http") ? configured : null;
}

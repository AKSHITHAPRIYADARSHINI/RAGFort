/** Session contract types only; no local login or browser-managed authority. */
export type SessionUser = {
  display_name: string;
  tenant_name: string;
  permissions: string[];
};

export type SessionState =
  | { status: "loading" }
  | { status: "authenticated"; user: SessionUser }
  | { status: "unauthenticated" }
  | { status: "unavailable" };

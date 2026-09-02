"use client";

import type { SessionState } from "../api/auth";

/** Transparent temporary state until FastAPI exposes an authenticated session contract. */
export function SessionShell({ state = { status: "unavailable" } }: { state?: SessionState }) {
  if (state.status === "authenticated") {
    return <p className="session-status">{state.user.display_name} · {state.user.tenant_name}</p>;
  }
  if (state.status === "loading") {
    return <p className="session-status" aria-live="polite">Checking your session…</p>;
  }
  return <p className="session-status" aria-live="polite">Secure sign-in is being configured.</p>;
}

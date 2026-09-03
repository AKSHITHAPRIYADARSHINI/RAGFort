"use client";

import type { ReactNode } from "react";
import { useSession } from "./session-provider";

export function SessionGate({ children }: { children: ReactNode }) {
  const { state, signInUrl, signOut } = useSession();
  if (state.status === "loading") return <main className="auth-shell"><section className="auth-card" aria-live="polite"><p className="eyebrow">RAGFort</p><h1>Checking your session</h1><p>Preparing secure access to organizational knowledge.</p></section></main>;
  if (state.status !== "authenticated") {
    const expired = state.status === "expired";
    return <main className="auth-shell"><section className="auth-card" aria-labelledby="sign-in-title"><p className="eyebrow">RAGFort</p><h1 id="sign-in-title">{expired ? "Your session has expired" : "Secure access to organizational knowledge"}</h1><p>{expired ? "Sign in again to continue securely." : "Access is determined by your organization and assigned permissions."}</p>{signInUrl ? <a className="ask sign-in" href={signInUrl}>Sign in with organization</a> : <p className="session-note" role="status">Organization sign-in is not available in this environment.</p>}</section></main>;
  }
  return <><header className="session-bar"><span>{state.user.display_name}</span><button type="button" onClick={() => void signOut()}>Sign out</button></header>{children}</>;
}

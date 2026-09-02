"use client";

import { createContext, ReactNode, useContext, useEffect, useMemo, useState } from "react";
import { loginUrl, readSession, SessionState } from "../api/auth";

type SessionContextValue = { state: SessionState; refresh: () => Promise<void>; signInUrl: string | null };
const SessionContext = createContext<SessionContextValue | undefined>(undefined);

export function SessionProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<SessionState>({ status: "loading" });
  const refresh = async () => setState(await readSession());
  useEffect(() => { void refresh(); }, []);
  const value = useMemo(() => ({ state, refresh, signInUrl: loginUrl() }), [state]);
  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}

export function useSession(): SessionContextValue {
  const value = useContext(SessionContext);
  if (!value) throw new Error("useSession must be used inside SessionProvider");
  return value;
}

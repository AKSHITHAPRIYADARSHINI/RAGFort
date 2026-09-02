import type { Metadata } from "next";
import "./styles.css";
import { SessionProvider } from "../components/session-provider";
import { SessionGate } from "../components/session-gate";

export const metadata: Metadata = { title: "RAGFort", description: "Grounded knowledge-base answers" };
export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) { return <html lang="en"><body><SessionProvider><SessionGate>{children}</SessionGate></SessionProvider></body></html>; }

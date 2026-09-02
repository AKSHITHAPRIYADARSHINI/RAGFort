import { authenticatedJson } from "./client";

export type Source = { document_id: string; chunk_id: string; title: string; source: string; section?: string | null };
export type QueryData = { answer: string | null; answer_status: "grounded" | "insufficient_context"; sources: Source[] };
export async function askQuestion(query: string): Promise<{ data: QueryData; requestId: string }> {
  const data = await authenticatedJson<QueryData>("/api/v1/query", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ query }) });
  return { data, requestId: "" };
}

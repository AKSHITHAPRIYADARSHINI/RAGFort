export type Source = { document_id: string; chunk_id: string; title: string; source: string; section?: string | null };
export type QueryData = { answer: string | null; answer_status: "grounded" | "insufficient_context"; sources: Source[] };
type Envelope = { success: boolean; data?: QueryData; error?: { code: string; message: string }; request_id: string };

export async function askQuestion(query: string): Promise<{ data: QueryData; requestId: string }> {
  const baseUrl = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000";
  const response = await fetch(`${baseUrl}/api/v1/query`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ query }) });
  const payload = (await response.json()) as Envelope;
  if (!response.ok || !payload.success || !payload.data) throw new Error(payload.error?.message ?? "We couldn't search the knowledge base right now.");
  return { data: payload.data, requestId: payload.request_id };
}

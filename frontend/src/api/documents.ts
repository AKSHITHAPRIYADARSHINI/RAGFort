export type Finding = { category: string; severity: string; description: string };
export type DocumentSummary = {
  document_id: string; version_id: string; name: string; status: string; classification: string;
  detected_type: string; size_bytes: number; index_state: string; version: number; uploaded_at: string;
  findings?: Finding[];
};
type Envelope<T> = { success: boolean; data?: T; error?: { message: string } };
const baseUrl = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${baseUrl}${path}`, init);
  const payload = (await response.json()) as Envelope<T>;
  if (!response.ok || !payload.success || !payload.data) throw new Error(payload.error?.message ?? "We couldn't process this document safely.");
  return payload.data;
}
export function listDocuments() { return request<{ documents: DocumentSummary[] }>("/api/v1/documents"); }
export function uploadDocument(file: File) { const form = new FormData(); form.append("file", file); return request<DocumentSummary>("/api/v1/documents", { method: "POST", body: form }); }
export function getDocumentSecurity(id: string) { return request<DocumentSummary>(`/api/v1/documents/${id}/security`); }
export function transitionDocument(id: string, action: "approve" | "quarantine") { return request<DocumentSummary>(`/api/v1/documents/${id}/${action}`, { method: "POST" }); }
export function deleteDocument(id: string) { return request<DocumentSummary>(`/api/v1/documents/${id}`, { method: "DELETE" }); }

import { authenticatedJson } from "./client";

export type Finding = { category: string; severity: string; description: string };
export type DocumentSummary = {
  document_id: string; version_id: string; name: string; status: string; classification: string;
  detected_type: string; size_bytes: number; index_state: string; version: number; uploaded_at: string;
  findings?: Finding[];
};
async function request<T>(path: string, init?: RequestInit): Promise<T> {
  return authenticatedJson<T>(path, init);
}
export function listDocuments() { return request<{ documents: DocumentSummary[] }>("/api/v1/documents"); }
export function uploadDocument(file: File) { const form = new FormData(); form.append("file", file); return request<DocumentSummary>("/api/v1/documents", { method: "POST", body: form }); }
export function getDocumentSecurity(id: string) { return request<DocumentSummary>(`/api/v1/documents/${id}/security`); }
export function transitionDocument(id: string, action: "approve" | "quarantine") { return request<DocumentSummary>(`/api/v1/documents/${id}/${action}`, { method: "POST" }); }
export function deleteDocument(id: string) { return request<DocumentSummary>(`/api/v1/documents/${id}`, { method: "DELETE" }); }

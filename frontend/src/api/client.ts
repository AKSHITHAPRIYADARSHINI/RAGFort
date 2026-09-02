/** Browser-to-API boundary reserved for Phase 4 authenticated requests. */
export type ApiError = {
  code?: string;
  message: string;
  requestId?: string;
};

export type ApiEnvelope<T> = {
  success: boolean;
  data?: T;
  error?: { code?: string; message: string };
  request_id?: string;
};

const apiBaseUrl = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000";

export function apiUrl(path: string): string {
  return `${apiBaseUrl}${path}`;
}

/**
 * The caller cannot attach bearer tokens, tenant IDs, roles, or service secrets.
 * It will be used once the server publishes its cookie-session and CSRF contract.
 */
export async function authenticatedFetch(path: string, init: RequestInit = {}): Promise<Response> {
  return fetch(apiUrl(path), { ...init, credentials: "include" });
}

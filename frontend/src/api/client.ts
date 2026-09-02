/** Browser-to-API boundary. Credentials are cookie-only; callers cannot attach bearer tokens. */
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

export class ApiRequestError extends Error {
  constructor(message: string, readonly status: number, readonly code?: string) {
    super(message);
  }
}

const apiBaseUrl = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000";

export function apiUrl(path: string): string {
  return `${apiBaseUrl}${path}`;
}

/** The backend OIDC BFF supplies HttpOnly cookie sessions; no JS token path exists. */
export async function authenticatedFetch(path: string, init: RequestInit = {}): Promise<Response> {
  return fetch(apiUrl(path), { ...init, credentials: "include", headers: { Accept: "application/json", ...init.headers } });
}

export async function authenticatedJson<T>(path: string, init: RequestInit = {}): Promise<T> {
  const response = await authenticatedFetch(path, init);
  let payload: ApiEnvelope<T>;
  try { payload = (await response.json()) as ApiEnvelope<T>; } catch { throw new ApiRequestError("We couldn't complete that request safely.", response.status); }
  if (!response.ok || !payload.success || payload.data === undefined) {
    throw new ApiRequestError(payload.error?.message ?? "We couldn't complete that request safely.", response.status, payload.error?.code);
  }
  return payload.data;
}

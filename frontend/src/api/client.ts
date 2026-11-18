import { safeStorageGet, safeStorageSet } from "@/lib/utils";

const BASE = (import.meta.env.VITE_API_BASE as string | undefined) ?? "/api/v1";
const TOKEN_KEY = "tc-token";

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

let unauthorizedHandler: (() => void) | null = null;
export function onUnauthorized(fn: () => void) {
  unauthorizedHandler = fn;
}

export const tokenStore = {
  get: () => safeStorageGet(TOKEN_KEY),
  set: (t: string | null) => safeStorageSet(TOKEN_KEY, t),
};

async function raw(path: string, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers);
  const token = tokenStore.get();
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (init.body && !(init.body instanceof FormData) && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  const res = await fetch(`${BASE}${path}`, { ...init, headers });
  if (res.status === 401 && token) unauthorizedHandler?.();
  if (!res.ok) {
    let msg = `${res.status} ${res.statusText}`;
    try {
      const body = await res.json();
      if (typeof body.detail === "string") msg = body.detail;
      else if (Array.isArray(body.detail)) msg = body.detail.map((d: { msg: string }) => d.msg).join("; ");
    } catch {
      /* non-JSON error */
    }
    throw new ApiError(res.status, msg);
  }
  return res;
}

export const api = {
  get: async <T>(path: string) => (await raw(path)).json() as Promise<T>,
  post: async <T>(path: string, body?: unknown) =>
    (await raw(path, { method: "POST", body: body === undefined ? undefined : JSON.stringify(body) })).json() as Promise<T>,
  postForm: async <T>(path: string, form: FormData) =>
    (await raw(path, { method: "POST", body: form })).json() as Promise<T>,
  blob: async (path: string, method: "GET" | "POST" = "GET") => (await raw(path, { method })).blob(),
};

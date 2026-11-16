import type { Alert, AlertDetail, AlertUpdate, Health, LogEvent, Page, Rule, StatsSummary } from "./types";

const BASE = import.meta.env.VITE_API_BASE ?? "/api/v1";
const KEY_STORAGE = "minisiem.apiKey";

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export function getApiKey(): string {
  try {
    return localStorage.getItem(KEY_STORAGE) ?? "";
  } catch {
    return "";
  }
}

export function setApiKey(key: string): void {
  try {
    if (key) localStorage.setItem(KEY_STORAGE, key);
    else localStorage.removeItem(KEY_STORAGE);
  } catch {
    /* storage unavailable (private mode): the key just won't persist */
  }
}

type Params = Record<string, string | number | boolean | undefined | null>;

/** Builds "?a=1&b=2", leaving out anything unset or empty so filters stay optional. */
export function toQuery(params: Params = {}): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === "") continue;
    search.set(key, String(value));
  }
  const text = search.toString();
  return text ? `?${text}` : "";
}

async function request<T>(url: string, init: RequestInit = {}, signal?: AbortSignal): Promise<T> {
  const headers = new Headers(init.headers);
  const key = getApiKey();
  if (key) headers.set("X-API-Key", key);
  if (init.body) headers.set("Content-Type", "application/json");

  let response: Response;
  try {
    response = await fetch(url, { ...init, headers, signal });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") throw error;
    throw new ApiError(0, "Cannot reach the API. Is the backend running on port 8000?");
  }

  if (!response.ok) {
    let detail = response.statusText;
    try {
      const body = await response.json();
      if (typeof body.detail === "string") detail = body.detail;
      else if (Array.isArray(body.detail)) detail = body.detail.map((d: { msg: string }) => d.msg).join("; ");
    } catch {
      /* body was not JSON; keep the status text */
    }
    throw new ApiError(response.status, detail || `Request failed (${response.status})`);
  }
  return (await response.json()) as T;
}

const get = <T>(path: string, params?: Params, signal?: AbortSignal) =>
  request<T>(`${BASE}${path}${toQuery(params)}`, {}, signal);

export interface AlertFilters {
  status?: string;
  active?: boolean;
  severity?: string;
  rule_id?: string;
  src_ip?: string;
  username?: string;
  sort?: string;
  page?: number;
  size?: number;
}

export interface EventFilters {
  source_type?: string;
  action?: string;
  src_ip?: string;
  username?: string;
  host?: string;
  q?: string;
  page?: number;
  size?: number;
}

export const api = {
  health: (signal?: AbortSignal) => request<Health>("/health", {}, signal),
  stats: (params: { from?: string; to?: string; top?: number }, signal?: AbortSignal) =>
    get<StatsSummary>("/stats/summary", params, signal),
  alerts: (filters: AlertFilters, signal?: AbortSignal) => get<Page<Alert>>("/alerts", { ...filters }, signal),
  alert: (id: string, signal?: AbortSignal) => get<AlertDetail>(`/alerts/${encodeURIComponent(id)}`, {}, signal),
  updateAlert: (id: string, update: AlertUpdate) =>
    request<Alert>(`${BASE}/alerts/${encodeURIComponent(id)}`, { method: "PATCH", body: JSON.stringify(update) }),
  events: (filters: EventFilters, signal?: AbortSignal) => get<Page<LogEvent>>("/events", { ...filters }, signal),
  rules: (signal?: AbortSignal) => get<Rule[]>("/rules", {}, signal),
};

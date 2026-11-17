import type {
  Alert,
  AlertDetail,
  AlertUpdate,
  Coverage,
  Health,
  IngestResult,
  IpProfile,
  LogEvent,
  LogFormat,
  NotificationStatus,
  NotificationTest,
  Page,
  Rule,
  RuleTestResult,
  StatsSummary,
} from "./types";

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

export type Params = Record<string, string | number | boolean | undefined | null>;

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
  if (init.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");

  let response: Response;
  try {
    response = await fetch(url, { ...init, headers, signal });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") throw error;
    throw new ApiError(0, "Cannot reach the API. Is the backend running on port 8000?");
  }

  if (!response.ok) throw await failure(response);
  return (await response.json()) as T;
}

/** Turns an error response into an ApiError carrying the server's explanation when it gave one. */
async function failure(response: Response): Promise<ApiError> {
  let detail = response.statusText;
  try {
    const body = await response.json();
    if (typeof body.detail === "string") detail = body.detail;
    else if (Array.isArray(body.detail)) detail = body.detail.map((d: { msg: string }) => d.msg).join("; ");
  } catch {
    /* body was not JSON; keep the status text */
  }
  return new ApiError(response.status, detail || `Request failed (${response.status})`);
}

export interface CsvDownload {
  blob: Blob;
  filename: string;
  /** Rows that matched the filters, or null if a proxy stripped the header that says so. */
  total: number | null;
  /** Rows actually in the file; smaller than total when the server's export limit cut it short. */
  exported: number | null;
}

/** Fetches a CSV with the API key header (a plain link could not send it) so the caller can save it. */
async function download(path: string, params: Params, signal?: AbortSignal): Promise<CsvDownload> {
  const headers = new Headers();
  const key = getApiKey();
  if (key) headers.set("X-API-Key", key);
  let response: Response;
  try {
    response = await fetch(`${BASE}${path}${toQuery(params)}`, { headers, signal });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") throw error;
    throw new ApiError(0, "Cannot reach the API. Is the backend running on port 8000?");
  }
  if (!response.ok) throw await failure(response);
  const disposition = response.headers.get("Content-Disposition") ?? "";
  const count = (name: string) => {
    const value = response.headers.get(name);
    return value !== null && value.trim() !== "" && Number.isFinite(Number(value)) ? Number(value) : null;
  };
  return {
    blob: await response.blob(),
    filename: /filename="([^"]+)"/.exec(disposition)?.[1] ?? path.split("/")[1] + ".csv",
    total: count("X-Total-Rows"),
    exported: count("X-Exported-Rows"),
  };
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
  setRuleEnabled: (id: string, enabled: boolean) =>
    request<Rule>(`${BASE}/rules/${encodeURIComponent(id)}`, { method: "PATCH", body: JSON.stringify({ enabled }) }),
  /** Dry run: what the rule would raise over the stored events. Changes nothing. */
  testRule: (id: string, signal?: AbortSignal) =>
    request<RuleTestResult>(`${BASE}/rules/${encodeURIComponent(id)}/test`, { method: "POST" }, signal),
  coverage: (signal?: AbortSignal) => get<Coverage>("/coverage", {}, signal),
  /** Opens the live feed. fetch rather than EventSource, because only fetch can send the API key header. */
  openStream: async (signal: AbortSignal): Promise<ReadableStream<Uint8Array>> => {
    const headers = new Headers({ Accept: "text/event-stream" });
    const key = getApiKey();
    if (key) headers.set("X-API-Key", key);
    let response: Response;
    try {
      response = await fetch(`${BASE}/stream`, { headers, signal });
    } catch (error) {
      if (error instanceof DOMException && error.name === "AbortError") throw error;
      throw new ApiError(0, "Cannot reach the API. Is the backend running on port 8000?");
    }
    if (!response.ok) throw await failure(response);
    if (!response.body) throw new ApiError(0, "This browser cannot stream responses.");
    return response.body;
  },
  notifications: (signal?: AbortSignal) => get<NotificationStatus>("/notifications", {}, signal),
  testNotification: () => request<NotificationTest>(`${BASE}/notifications/test`, { method: "POST" }),
  downloadCsv: (path: "/alerts/export.csv" | "/events/export.csv", params: Params, signal?: AbortSignal) =>
    download(path, params, signal),
  ip: (ip: string, signal?: AbortSignal) => get<IpProfile>(`/ips/${encodeURIComponent(ip)}`, {}, signal),
  /** Sends raw log text through the same parsers and detection rules as live traffic. */
  ingest: (format: LogFormat, text: string, host?: string) =>
    request<IngestResult>(`${BASE}/ingest/${format}${toQuery({ host })}`, {
      method: "POST",
      body: text,
      headers: { "Content-Type": "text/plain" },
    }),
};

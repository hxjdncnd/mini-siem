// @vitest-environment jsdom
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Alert, AlertDetail, IpProfile, LogEvent, Rule, RuleTestResult, StatsSummary } from "./api/types";
import { App } from "./App";

const alert: Alert = {
  id: "alert-1",
  rule_id: "ssh-brute-force",
  rule_name: "SSH brute force",
  severity: "high",
  score: 76,
  status: "OPEN",
  summary: "40 failed SSH logins from 203.0.113.50",
  group_key: "203.0.113.50",
  mitre: "T1110.001",
  src_ip: "203.0.113.50",
  username: "root",
  host: "web01",
  first_seen: "2026-11-16T19:00:00Z",
  last_seen: "2026-11-16T19:05:00Z",
  event_count: 40,
  note: null,
  created_at: "2026-11-16T19:05:00Z",
  updated_at: "2026-11-16T19:05:00Z",
};

const event: LogEvent = {
  id: "event-1",
  timestamp: "2026-11-16T19:00:01Z",
  received_at: "2026-11-16T19:00:02Z",
  source_type: "AUTH",
  action: "LOGIN_FAILURE",
  host: "web01",
  src_ip: "203.0.113.50",
  dst_ip: null,
  src_port: null,
  dst_port: null,
  username: "root",
  protocol: null,
  http_method: null,
  http_path: null,
  http_status: null,
  user_agent: null,
  raw: "Nov 16 19:00:01 web01 sshd[8320]: Failed password for root from 203.0.113.50",
};

const rule: Rule = {
  id: "ssh-brute-force-success",
  name: "Successful login after brute force",
  description: "An address that had been failing logins then got in.",
  severity: "critical",
  type: "sequence",
  group_by: ["src_ip"],
  window_seconds: null,
  threshold: 5,
  distinct_field: null,
  within_seconds: 600,
  mitre: "T1110.001",
  enabled: true,
  alert_count: 1,
};

const stats: StatsSummary = {
  from: "2026-11-15T19:00:00Z",
  to: "2026-11-16T19:00:00Z",
  total_events: 298,
  events_by_source: [{ key: "AUTH", count: 200 }],
  events_by_action: [{ key: "LOGIN_FAILURE", count: 150 }],
  top_source_ips: [{ key: "198.51.100.41", count: 48 }],
  events_over_time: [
    { start: "2026-11-16T18:00:00Z", count: 10 },
    { start: "2026-11-16T18:30:00Z", count: 25 },
  ],
  bucket_seconds: 1800,
  total_alerts: 14,
  open_alerts: 13,
  alerts_by_severity: [
    { key: "critical", count: 1 },
    { key: "high", count: 7 },
  ],
  alerts_by_status: [{ key: "OPEN", count: 14 }],
  alerts_by_rule: [{ key: "ssh-brute-force", count: 3 }],
};

const ipProfile: IpProfile = {
  ip: "203.0.113.50",
  classification: { kind: "documentation", label: "Reserved for documentation", internal: false },
  event_count: 7,
  first_seen: "2026-11-16T19:00:00Z",
  last_seen: "2026-11-16T19:05:00Z",
  hosts: [{ key: "web01", count: 7 }],
  actions: [{ key: "LOGIN_FAILURE", count: 7 }],
  usernames: [{ key: "admin", count: 4 }],
  http_paths: [],
  dst_ports: [],
  events_over_time: [{ start: "2026-11-16T19:00:00Z", count: 7 }],
  bucket_seconds: 10,
  alerts: [alert],
  max_score: 76,
  recent_events: [event],
};

const ruleTest: RuleTestResult = {
  rule_id: "ssh-brute-force-success",
  enabled: true,
  events_scanned: 298,
  events_total: 298,
  scanned_from: "2026-11-16T18:00:00Z",
  scanned_to: "2026-11-16T19:30:00Z",
  would_raise: 2,
  already_raised: 2,
  findings: [
    {
      summary: "203.0.113.61 logged in successfully after repeated failures",
      severity: "critical",
      score: 92,
      group_key: "src_ip=203.0.113.61",
      src_ip: "203.0.113.61",
      username: null,
      host: null,
      first_seen: "2026-11-16T19:00:00Z",
      last_seen: "2026-11-16T19:02:00Z",
      event_count: 11,
    },
  ],
};

const csvResponse = (body: string, headers: Record<string, string> = {}) =>
  new Response(body, {
    status: 200,
    headers: {
      "Content-Type": "text/csv",
      "Content-Disposition": 'attachment; filename="alerts-2026-11-17.csv"',
      "X-Total-Rows": "14",
      "X-Exported-Rows": "14",
      ...headers,
    },
  });

const page = <T,>(items: T[]) => ({ items, total: items.length, page: 0, size: 50 });
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

let calls: { url: string; method: string; body?: string }[];
let respond: (url: URL, method: string) => Response;

function defaultRespond(url: URL, method: string): Response {
  const path = url.pathname;
  if (path === "/health") return json({ status: "ok", rules: 11 });
  if (path === "/api/v1/stats/summary") return json(stats);
  if (path === "/api/v1/ips/203.0.113.50") return json(ipProfile);
  if (path.startsWith("/api/v1/ips/")) return json({ detail: "No activity" }, 404);
  if (path.startsWith("/api/v1/ingest/")) {
    return json({ received: 15, stored: 15, skipped: 0, failed: 0, errors: [], alerts_created: 2, alerts_updated: 0 });
  }
  if (path === "/api/v1/rules") return json([rule]);
  if (path === "/api/v1/rules/ssh-brute-force-success") return json({ ...rule, enabled: method === "PATCH" ? false : true });
  if (path === "/api/v1/rules/ssh-brute-force-success/test") return json(ruleTest);
  if (path === "/api/v1/notifications") return json({ enabled: true, min_severity: "critical", destination: "hooks.slack.com" });
  if (path === "/api/v1/notifications/test") return json({ delivered: true, status: 200, error: null });
  if (path === "/api/v1/alerts/export.csv") return csvResponse("id,rule_id\nalert-1,ssh-brute-force\n");
  if (path === "/api/v1/events/export.csv") return csvResponse("time,action\n", { "Content-Disposition": 'attachment; filename="events-2026-11-17.csv"' });
  if (path === "/api/v1/events") return json(page([event]));
  if (path === "/api/v1/alerts/alert-1") {
    if (method === "PATCH") return json({ ...alert, status: "ACKNOWLEDGED" });
    const detail: AlertDetail = { ...alert, events: [event] };
    return json(detail);
  }
  if (path === "/api/v1/alerts") return json(page([alert]));
  return json({ detail: "not found" }, 404);
}

function renderAt(route: string) {
  return render(
    <MemoryRouter initialEntries={[route]}>
      <App />
    </MemoryRouter>,
  );
}

beforeEach(() => {
  calls = [];
  respond = defaultRespond;
  vi.stubGlobal(
    "ResizeObserver",
    class {
      observe() {}
      unobserve() {}
      disconnect() {}
    },
  );
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string, init?: RequestInit) => {
      const url = new URL(input, "http://localhost");
      const method = init?.method ?? "GET";
      calls.push({ url: url.pathname + url.search, method, body: init?.body as string | undefined });
      return respond(url, method);
    }),
  );
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("Overview", () => {
  it("shows the headline numbers and the highest-risk alerts", async () => {
    renderAt("/");
    expect(await screen.findByText("298")).toBeTruthy();
    expect(screen.getByText("Events ingested")).toBeTruthy();
    expect(await screen.findByRole("link", { name: "SSH brute force" })).toBeTruthy();
    expect(screen.getByText("198.51.100.41")).toBeTruthy();
  });

  it("asks for an API key when the server answers 401", async () => {
    respond = (url, method) => (url.pathname === "/api/v1/stats/summary" ? json({ detail: "Missing or invalid X-API-Key header" }, 401) : defaultRespond(url, method));
    renderAt("/");
    expect(await screen.findByText("The API needs a key")).toBeTruthy();
  });
});

describe("Alerts", () => {
  it("lists alerts and applies the default 'active' filter", async () => {
    renderAt("/alerts");
    expect(await screen.findByText("40 failed SSH logins from 203.0.113.50")).toBeTruthy();
    const listCall = calls.find((c) => c.url.startsWith("/api/v1/alerts?") && c.url.includes("sort=recent"));
    expect(listCall?.url).toContain("active=true");
  });

  it("opens the evidence drawer and triages an alert", async () => {
    const user = userEvent.setup();
    renderAt("/alerts");
    await user.click(await screen.findByText("40 failed SSH logins from 203.0.113.50"));

    const drawer = await screen.findByRole("dialog");
    expect(await within(drawer).findByText(/Failed password for root/)).toBeTruthy();
    expect(within(drawer).getByRole("link", { name: "T1110.001" }).getAttribute("href")).toBe(
      "https://attack.mitre.org/techniques/T1110/001/",
    );

    await user.click(within(drawer).getByRole("button", { name: "Acknowledge" }));
    await waitFor(() => {
      const patch = calls.find((c) => c.method === "PATCH");
      expect(patch?.url).toBe("/api/v1/alerts/alert-1");
      expect(JSON.parse(patch?.body ?? "{}")).toEqual({ status: "ACKNOWLEDGED" });
    });
  });

  it("closes the drawer with Escape", async () => {
    const user = userEvent.setup();
    renderAt("/alerts?alert=alert-1");
    await screen.findByRole("dialog");
    await user.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  });

  it("reports a failed triage instead of failing silently", async () => {
    const user = userEvent.setup();
    const original = respond;
    respond = (url, method) => (method === "PATCH" ? json({ detail: "Provide 'status' and/or 'note'" }, 400) : original(url, method));
    renderAt("/alerts?alert=alert-1");
    const drawer = await screen.findByRole("dialog");
    await user.click(await within(drawer).findByRole("button", { name: "Resolve" }));
    expect(await within(drawer).findByText("Provide 'status' and/or 'note'")).toBeTruthy();
  });
});

describe("Events", () => {
  it("expands a row to show the raw log line", async () => {
    const user = userEvent.setup();
    renderAt("/events");
    await user.click(await screen.findByText("user root"));
    expect(await screen.findByText(/Failed password for root from 203\.0\.113\.50/)).toBeTruthy();
  });
});

describe("Rules", () => {
  it("describes a sequence rule that has no window", async () => {
    renderAt("/rules");
    expect(await screen.findByText("5 matching events, then a follow-up event within 10 min")).toBeTruthy();
  });
});

describe("IP investigation", () => {
  it("shows what an address did, its alerts and its latest events", async () => {
    renderAt("/ips/203.0.113.50");
    expect(await screen.findByText("Reserved for documentation")).toBeTruthy();
    expect(screen.getByText("Accounts it tried")).toBeTruthy();
    expect(screen.getByText("admin")).toBeTruthy();
    expect(screen.getByText("SSH brute force")).toBeTruthy();
    expect(screen.getByText(/Failed password for root|user root/)).toBeTruthy();
  });

  it("says so when the address has never been seen", async () => {
    renderAt("/ips/198.51.100.7");
    expect(await screen.findByText(/No activity from 198\.51\.100\.7/)).toBeTruthy();
  });

  it("is reachable from the lookup box and from addresses in the alert list", async () => {
    const user = userEvent.setup();
    renderAt("/alerts");
    await user.type(await screen.findByLabelText("Investigate an IP"), "203.0.113.50{Enter}");
    expect(await screen.findByText("Reserved for documentation")).toBeTruthy();
  });
});

describe("Upload", () => {
  it("detects the format, uploads the file and reports what the rules found", async () => {
    const user = userEvent.setup();
    renderAt("/upload");
    await user.click(await screen.findByRole("button", { name: "Try a sample SSH attack" }));
    expect(await screen.findByText(/Auto-detect: SSH and sudo/)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Upload and analyze" }));
    expect(await screen.findByText(/2 new alerts/)).toBeTruthy();
    const post = calls.find((c) => c.method === "POST");
    expect(post?.url).toBe("/api/v1/ingest/sshd");
    expect(post?.body).toContain("Failed password");
  });

  it("will not upload when the format cannot be told", async () => {
    const user = userEvent.setup();
    renderAt("/upload");
    const input = await screen.findByLabelText("Log file");
    await user.upload(input, new File(["hello\nworld\n"], "mystery.txt", { type: "text/plain" }));
    expect(await screen.findByText(/Could not tell what kind of log/)).toBeTruthy();
    expect((screen.getByRole("button", { name: "Upload and analyze" }) as HTMLButtonElement).disabled).toBe(true);
  });
});

describe("Rules: respond", () => {
  it("switches a rule off through the API", async () => {
    const user = userEvent.setup();
    renderAt("/rules");
    await user.click(await screen.findByRole("switch", { name: /Switch off Successful login after brute force/ }));
    await waitFor(() => expect(calls.some((c) => c.method === "PATCH")).toBe(true));
    const patch = calls.find((c) => c.method === "PATCH");
    expect(patch?.url).toBe("/api/v1/rules/ssh-brute-force-success");
    expect(JSON.parse(patch?.body ?? "{}")).toEqual({ enabled: false });
  });

  it("reports a rule that could not be switched instead of pretending it worked", async () => {
    const user = userEvent.setup();
    respond = (url, method) =>
      method === "PATCH" ? json({ detail: "database is locked" }, 500) : defaultRespond(url, method);
    renderAt("/rules");
    await user.click(await screen.findByRole("switch", { name: /Switch off/ }));
    expect(await screen.findByText("database is locked")).toBeTruthy();
  });

  it("tries a rule against the stored events without changing anything", async () => {
    const user = userEvent.setup();
    renderAt("/rules");
    await user.click(await screen.findByRole("button", { name: "Test Successful login after brute force" }));
    const drawer = await screen.findByRole("dialog");
    expect(await within(drawer).findByText(/would be raised on the stored events/)).toBeTruthy();
    expect(within(drawer).getByText(/Nothing was created or changed/)).toBeTruthy();
    expect(within(drawer).getByText("203.0.113.61 logged in successfully after repeated failures")).toBeTruthy();
    const post = calls.find((c) => c.url.endsWith("/test"));
    expect(post?.method).toBe("POST");
  });

  it("shows where critical alerts are sent and can send a test message", async () => {
    const user = userEvent.setup();
    renderAt("/rules");
    expect(await screen.findByText("hooks.slack.com")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Send a test message" }));
    expect(await screen.findByText(/Delivered \(HTTP 200\)/)).toBeTruthy();
  });

  it("explains how to turn notifications on when they are off", async () => {
    respond = (url, method) =>
      url.pathname === "/api/v1/notifications"
        ? json({ enabled: false, min_severity: "critical", destination: null })
        : defaultRespond(url, method);
    renderAt("/rules");
    expect(await screen.findByText("MINISIEM_WEBHOOK_URL")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Send a test message" })).toBeNull();
  });

  it("says when a test message was not delivered", async () => {
    const user = userEvent.setup();
    respond = (url, method) =>
      url.pathname === "/api/v1/notifications/test"
        ? json({ delivered: false, status: 404, error: "The receiver answered HTTP 404" })
        : defaultRespond(url, method);
    renderAt("/rules");
    await user.click(await screen.findByRole("button", { name: "Send a test message" }));
    expect(await screen.findByText(/Not delivered: The receiver answered HTTP 404/)).toBeTruthy();
  });
});

describe("CSV export", () => {
  let saved: { filename: string }[];
  beforeEach(() => {
    saved = [];
    // jsdom has no object URLs and cannot navigate, so stand in for both and record what would be saved.
    Object.defineProperty(URL, "createObjectURL", { configurable: true, value: () => "blob:test" });
    Object.defineProperty(URL, "revokeObjectURL", { configurable: true, value: () => {} });
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) {
      saved.push({ filename: this.download });
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
    Reflect.deleteProperty(URL, "createObjectURL");
    Reflect.deleteProperty(URL, "revokeObjectURL");
  });

  it("downloads the alerts the page is filtered to", async () => {
    const user = userEvent.setup();
    renderAt("/alerts?severity=high&sort=score");
    await user.click(await screen.findByRole("button", { name: "Export CSV" }));
    expect(await screen.findByText("Saved 14 rows.")).toBeTruthy();
    const call = calls.find((c) => c.url.startsWith("/api/v1/alerts/export.csv"));
    expect(call?.url).toContain("severity=high");
    expect(call?.url).toContain("sort=score");
    expect(call?.url).toContain("active=true");
    expect(call?.url).not.toContain("page=");
    expect(saved).toEqual([{ filename: "alerts-2026-11-17.csv" }]);
  });

  it("downloads the events matching the search", async () => {
    const user = userEvent.setup();
    renderAt("/events?src_ip=203.0.113.50&q=sqlmap");
    await user.click(await screen.findByRole("button", { name: "Export CSV" }));
    await waitFor(() => expect(saved).toHaveLength(1));
    const call = calls.find((c) => c.url.startsWith("/api/v1/events/export.csv"));
    expect(call?.url).toContain("src_ip=203.0.113.50");
    expect(call?.url).toContain("q=sqlmap");
    expect(saved[0]?.filename).toBe("events-2026-11-17.csv");
  });

  it("warns when the server cut the export short", async () => {
    const user = userEvent.setup();
    respond = (url, method) =>
      url.pathname === "/api/v1/alerts/export.csv"
        ? csvResponse("id\n", { "X-Total-Rows": "250000", "X-Exported-Rows": "100000" })
        : defaultRespond(url, method);
    renderAt("/alerts");
    await user.click(await screen.findByRole("button", { name: "Export CSV" }));
    expect(await screen.findByText(/first 100,000 of 250,000 rows/)).toBeTruthy();
  });

  it("still saves the file when a proxy strips the row-count headers", async () => {
    const user = userEvent.setup();
    respond = (url, method) =>
      url.pathname === "/api/v1/alerts/export.csv"
        ? new Response("id\n", { status: 200, headers: { "Content-Type": "text/csv" } })
        : defaultRespond(url, method);
    renderAt("/alerts");
    await user.click(await screen.findByRole("button", { name: "Export CSV" }));
    expect(await screen.findByText("Saved the CSV file.")).toBeTruthy();
    expect(saved).toEqual([{ filename: "alerts.csv" }]);
  });

  it("shows the problem when the export fails", async () => {
    const user = userEvent.setup();
    respond = (url, method) =>
      url.pathname === "/api/v1/alerts/export.csv" ? json({ detail: "Missing or invalid X-API-Key header" }, 401) : defaultRespond(url, method);
    renderAt("/alerts");
    await user.click(await screen.findByRole("button", { name: "Export CSV" }));
    expect(await screen.findByText("Missing or invalid X-API-Key header")).toBeTruthy();
    expect(saved).toHaveLength(0);
  });
});

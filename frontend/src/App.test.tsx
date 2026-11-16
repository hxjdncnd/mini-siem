// @vitest-environment jsdom
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Alert, AlertDetail, LogEvent, Rule, StatsSummary } from "./api/types";
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

const page = <T,>(items: T[]) => ({ items, total: items.length, page: 0, size: 50 });
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

let calls: { url: string; method: string; body?: string }[];
let respond: (url: URL, method: string) => Response;

function defaultRespond(url: URL, method: string): Response {
  const path = url.pathname;
  if (path === "/health") return json({ status: "ok", rules: 11 });
  if (path === "/api/v1/stats/summary") return json(stats);
  if (path === "/api/v1/rules") return json([rule]);
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

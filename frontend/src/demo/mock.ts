// Demo mode: answers the dashboard's API calls from a snapshot of a real simulator run, in the browser, so the
// hosted demo needs no backend. Regenerate the snapshot with scripts/capture_demo.py.
// Timestamps are shifted so the data always looks like it just happened. Changes live in memory and reset on reload.
import raw from "./data.json";

type Json = Record<string, any>;
const data = raw as unknown as Json;
const delta = Date.now() - Date.parse(data.capturedAt);
const TIME_KEYS = new Set(["timestamp", "received_at", "first_seen", "last_seen", "created_at", "updated_at", "start", "from", "to"]);

function shift(value: any): any {
  if (Array.isArray(value)) return value.map(shift);
  if (value && typeof value === "object") {
    const out: Json = {};
    for (const [key, v] of Object.entries(value)) {
      out[key] = TIME_KEYS.has(key) && typeof v === "string" ? new Date(Date.parse(v) + delta).toISOString() : shift(v);
    }
    return out;
  }
  return value;
}

const alerts: Json[] = shift(data.alerts);
const details: Record<string, Json> = shift(data.details);
const events: Json[] = shift(data.events);
const rules: Json[] = data.rules;
const stats: Record<string, Json> = shift(data.stats);
const ips: Record<string, Json> = shift(data.ips);
const ruleTests: Record<string, Json> = shift(data.ruleTests);
const coverage: Json = data.coverage;

const RANK: Record<string, number> = { low: 0, medium: 1, high: 2, critical: 3 };
const ACTIVE = new Set(["OPEN", "ACKNOWLEDGED"]);

const reply = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

function paginate(items: Json[], params: URLSearchParams, defaultSize: number) {
  const size = Math.min(500, Math.max(1, Number(params.get("size")) || defaultSize));
  const page = Math.max(0, Number(params.get("page")) || 0);
  return { items: items.slice(page * size, (page + 1) * size), total: items.length, page, size };
}

function filterAlerts(p: URLSearchParams) {
  let rows = alerts.filter((a) => {
    if (p.get("active") === "true" && !ACTIVE.has(a.status)) return false;
    if (p.get("active") === "false" && ACTIVE.has(a.status)) return false;
    if (p.get("status") && a.status !== p.get("status")) return false;
    if (p.get("severity") && a.severity !== p.get("severity")) return false;
    if (p.get("rule_id") && a.rule_id !== p.get("rule_id")) return false;
    if (p.get("src_ip") && a.src_ip !== p.get("src_ip")) return false;
    if (p.get("username") && a.username !== p.get("username")) return false;
    return true;
  });
  rows = [...rows].sort((a, b) =>
    p.get("sort") === "score"
      ? b.score - a.score || Date.parse(b.last_seen) - Date.parse(a.last_seen)
      : Date.parse(b.last_seen) - Date.parse(a.last_seen) || RANK[b.severity]! - RANK[a.severity]!,
  );
  return rows;
}

function filterEvents(p: URLSearchParams) {
  const q = p.get("q")?.toLowerCase();
  return events
    .filter((e) => {
      for (const key of ["source_type", "action", "src_ip", "username", "host"]) {
        if (p.get(key) && e[key] !== p.get(key)) return false;
      }
      return !q || String(e.raw ?? "").toLowerCase().includes(q);
    })
    .sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp));
}

const listAlerts = (p: URLSearchParams) => paginate(filterAlerts(p), p, 50);
const listEvents = (p: URLSearchParams) => paginate(filterEvents(p), p, 50);

function summary(p: URLSearchParams) {
  const end = p.get("to") ? Date.parse(p.get("to")!) : Date.now();
  const start = p.get("from") ? Date.parse(p.get("from")!) : end - 24 * 3600_000;
  const hours = Math.max(0.01, (end - start) / 3600_000);
  const nearest = Object.keys(stats).reduce((best, h) =>
    Math.abs(Math.log(Number(h) / hours)) < Math.abs(Math.log(Number(best) / hours)) ? h : best,
  );
  const base = structuredClone(stats[nearest]!);
  const count = (key: string) => {
    const tally = new Map<string, number>();
    for (const a of alerts) tally.set(a[key], (tally.get(a[key]) ?? 0) + 1);
    return [...tally].map(([k, n]) => ({ key: k, count: n })).sort((x, y) => y.count - x.count || x.key.localeCompare(y.key));
  };
  base.alerts_by_status = count("status");
  base.open_alerts = alerts.filter((a) => ACTIVE.has(a.status)).length;
  base.total_alerts = alerts.length;
  return base;
}

function update(id: string, body: Json) {
  const alert = alerts.find((a) => a.id === id);
  if (!alert) return reply({ detail: `No alert with id ${id}` }, 404);
  if (body.status === undefined && !("note" in body)) return reply({ detail: "Provide 'status' and/or 'note'" }, 400);
  if (body.status) alert.status = body.status;
  if ("note" in body) alert.note = body.note;
  alert.updated_at = new Date().toISOString();
  Object.assign(details[id]!, alert);
  return reply(alert);
}


// ---- CSV export: same formula defusing as the backend (a leading apostrophe on = + - @) ----
const ALERT_COLUMNS = ["id", "rule_id", "rule_name", "severity", "score", "status", "summary", "src_ip", "username", "host", "first_seen", "last_seen", "event_count", "mitre", "note"];
const EVENT_COLUMNS = ["id", "timestamp", "source_type", "action", "host", "src_ip", "dst_ip", "src_port", "dst_port", "username", "protocol", "http_method", "http_path", "http_status", "user_agent", "raw"];

function cell(value: unknown): string {
  let text = value === null || value === undefined ? "" : String(value);
  if (/^[=+\-@\t\r]/.test(text)) text = "'" + text;
  return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

function csv(name: string, columns: string[], rows: Json[]) {
  const body = [columns.join(","), ...rows.map((r) => columns.map((c) => cell(r[c])).join(","))].join("\r\n") + "\r\n";
  return new Response(body, {
    status: 200,
    headers: {
      "Content-Type": "text/csv",
      "Content-Disposition": `attachment; filename="${name}-demo.csv"`,
      "X-Total-Rows": String(rows.length),
      "X-Exported-Rows": String(rows.length),
    },
  });
}

// ---- Rules: switching one off really changes what the demo reports ----
function setRule(id: string, body: Json) {
  const rule = rules.find((r) => r.id === id);
  if (!rule) return reply({ detail: `No rule with id ${id}` }, 404);
  if (typeof body.enabled !== "boolean") return reply({ detail: "Provide 'enabled' as true or false" }, 400);
  rule.enabled = body.enabled;
  return reply({ ...rule, alert_count: alerts.filter((a) => a.rule_id === id).length });
}

function testRule(id: string) {
  const base = ruleTests[id];
  const rule = rules.find((r) => r.id === id);
  if (!base || !rule) return reply({ detail: `No rule with id ${id}` }, 404);
  // A switched-off rule raises nothing live, so everything it would find counts as new.
  const found = base.would_raise;
  return reply({ ...base, enabled: rule.enabled, already_raised: rule.enabled ? base.already_raised : 0, would_raise: rule.enabled ? base.would_raise : found });
}

function coverageNow() {
  const on = new Map(rules.map((r) => [r.id, r.enabled]));
  const copy = structuredClone(coverage);
  for (const tactic of copy.tactics) {
    for (const tech of tactic.techniques) for (const r of tech.rules) r.enabled = on.get(r.id) ?? r.enabled;
  }
  copy.rules_enabled = rules.filter((r) => r.enabled).length;
  return copy;
}

// ---- Live feed: every so often a believable attack lands, raising an alert and updating the page ----
const encoder = new TextEncoder();
const SCRIPTS = [
  { rule: "ssh-brute-force", ip: "203.0.113.77", text: "failed SSH logins from" },
  { rule: "port-scan", ip: "198.51.100.88", text: "ports probed by" },
  { rule: "web-sql-injection", ip: "203.0.113.99", text: "injection attempts from" },
  { rule: "web-content-discovery", ip: "192.0.2.150", text: "missing pages requested by" },
];
let nextScript = 0;

function liveAttack() {
  const script = SCRIPTS[nextScript++ % SCRIPTS.length]!;
  const rule = rules.find((r) => r.id === script.rule && r.enabled);
  if (!rule) return { type: "ingest", stored: 6, alerts_created: 0, alerts_updated: 0, new_alerts: [] };
  const now = new Date().toISOString();
  const score = rule.severity === "high" ? 74 : 52;
  const alert: Json = {
    id: crypto.randomUUID(), rule_id: rule.id, rule_name: rule.name, severity: rule.severity, score, status: "OPEN",
    summary: `${12 + nextScript} ${script.text} ${script.ip}`, group_key: `src_ip=${script.ip}`, mitre: rule.mitre,
    src_ip: script.ip, username: null, host: "web01", first_seen: now, last_seen: now, event_count: 12 + nextScript,
    note: null, created_at: now, updated_at: now,
  };
  alerts.unshift(alert);
  details[alert.id] = { ...alert, events: [] };
  return {
    type: "ingest", stored: alert.event_count, alerts_created: 1, alerts_updated: 0,
    new_alerts: [{ id: alert.id, rule_name: alert.rule_name, severity: alert.severity, summary: alert.summary, score }],
  };
}

function stream(signal?: AbortSignal | null) {
  let timer: number | undefined;
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(encoder.encode("retry: 3000\n\n: connected\n\n"));
      timer = window.setInterval(() => {
        const message = liveAttack();
        controller.enqueue(encoder.encode(`event: ingest\ndata: ${JSON.stringify(message)}\n\n`));
      }, 14_000);
      signal?.addEventListener("abort", () => {
        window.clearInterval(timer);
        try { controller.close(); } catch { /* already closed */ }
      });
    },
    cancel() { window.clearInterval(timer); },
  });
  return new Response(body, { status: 200, headers: { "Content-Type": "text/event-stream" } });
}

export function installMock() {
  const realFetch = window.fetch.bind(window);
  window.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
    const href = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    const url = new URL(href, window.location.href);
    const path = url.pathname;
    const method = (init?.method ?? "GET").toUpperCase();
    const p = url.searchParams;
    if (!path.endsWith("/stream")) await new Promise((resolve) => setTimeout(resolve, 60)); // feel like a network call

    if (path.endsWith("/health")) return reply({ status: "ok", rules: rules.length });
    const api = path.match(/\/api\/v1(\/.*)$/)?.[1];
    if (!api) return realFetch(input, init);

    if (api === "/stream") return stream(init?.signal);
    if (api === "/coverage") return reply(coverageNow());
    if (api === "/notifications") return reply({ enabled: true, min_severity: "high", destination: "hooks.slack.com (demo)" });
    if (api === "/notifications/test") return reply({ delivered: true, status: 200, error: null });
    if (api === "/alerts/export.csv") return csv("alerts", ALERT_COLUMNS, filterAlerts(p));
    if (api === "/events/export.csv") return csv("events", EVENT_COLUMNS, filterEvents(p));
    if (api.startsWith("/ingest/"))
      return reply({ detail: "Uploading needs the real backend: this hosted demo replays a recorded run. Run it locally with docker compose up." }, 501);
    const ip = api.match(/^\/ips\/([^/]+)$/);
    if (ip) {
      const key = decodeURIComponent(ip[1]!);
      return ips[key] ? reply(ips[key]) : reply({ detail: `No activity recorded from ${key}` }, 404);
    }
    const rule = api.match(/^\/rules\/([^/]+)(\/test)?$/);
    if (rule) {
      const id = decodeURIComponent(rule[1]!);
      if (rule[2] && method === "POST") return testRule(id);
      if (method === "PATCH") return setRule(id, JSON.parse(String(init?.body ?? "{}")));
    }
    if (api === "/rules") return reply(rules.map((r) => ({ ...r, alert_count: alerts.filter((a) => a.rule_id === r.id).length })));
    if (api === "/stats/summary") return reply(summary(p));
    if (api === "/events") return reply(listEvents(p));
    if (api === "/alerts") return reply(listAlerts(p));
    const one = api.match(/^\/alerts\/([^/]+)$/);
    if (one) {
      const id = decodeURIComponent(one[1]!);
      if (method === "PATCH") return update(id, JSON.parse(String(init?.body ?? "{}")));
      return details[id] ? reply(details[id]) : reply({ detail: `No alert with id ${id}` }, 404);
    }
    return reply({ detail: "Not found" }, 404);
  };

  const note = document.createElement("div");
  note.textContent = "Demo: simulated attack data, changes reset on reload";
  note.style.cssText =
    "position:fixed;left:50%;transform:translateX(-50%);bottom:10px;z-index:100;padding:6px 12px;border-radius:999px;font:600 12px/1.4 system-ui,sans-serif;color:#8794b0;background:#0d1424;border:1px solid #22304d;pointer-events:none";
  document.body.appendChild(note);
}

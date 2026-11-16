import { describe, expect, it } from "vitest";
import type { LogEvent } from "../api/types";
import { toQuery } from "../api/client";
import { describeEvent, formatDuration, hoursAgoIso, humanize, mitreUrl, timeAgo } from "./format";

const base: LogEvent = {
  id: "1",
  timestamp: "2026-01-01T00:00:00Z",
  received_at: "2026-01-01T00:00:00Z",
  source_type: "AUTH",
  action: "LOGIN_FAILURE",
  host: null,
  src_ip: null,
  dst_ip: null,
  src_port: null,
  dst_port: null,
  username: null,
  protocol: null,
  http_method: null,
  http_path: null,
  http_status: null,
  user_agent: null,
  raw: null,
};

describe("humanize", () => {
  it("turns enum values into sentence case", () => {
    expect(humanize("LOGIN_FAILURE")).toBe("Login failure");
    expect(humanize("FALSE_POSITIVE")).toBe("False positive");
  });
});

describe("timeAgo", () => {
  const now = Date.parse("2026-01-01T12:00:00Z");
  it("picks a sensible unit", () => {
    expect(timeAgo("2026-01-01T11:59:58Z", now)).toBe("just now");
    expect(timeAgo("2026-01-01T11:59:30Z", now)).toBe("30s ago");
    expect(timeAgo("2026-01-01T11:55:00Z", now)).toBe("5m ago");
    expect(timeAgo("2026-01-01T09:00:00Z", now)).toBe("3h ago");
    expect(timeAgo("2025-12-29T12:00:00Z", now)).toBe("3d ago");
  });
});

describe("formatDuration", () => {
  it("scales from seconds to days", () => {
    expect(formatDuration(45)).toBe("45s");
    expect(formatDuration(300)).toBe("5 min");
    expect(formatDuration(7200)).toBe("2 h");
    expect(formatDuration(172800)).toBe("2 d");
  });
});

describe("mitreUrl", () => {
  it("links techniques and sub-techniques", () => {
    expect(mitreUrl("T1110")).toBe("https://attack.mitre.org/techniques/T1110/");
    expect(mitreUrl("T1110.001")).toBe("https://attack.mitre.org/techniques/T1110/001/");
  });
});

describe("describeEvent", () => {
  it("summarises web requests", () => {
    const event: LogEvent = { ...base, source_type: "WEB", http_method: "GET", http_path: "/admin", http_status: 404 };
    expect(describeEvent(event)).toBe("GET /admin -> 404");
  });
  it("summarises firewall connections", () => {
    const event: LogEvent = {
      ...base,
      source_type: "FIREWALL",
      src_ip: "10.0.0.5",
      src_port: 4444,
      dst_ip: "10.0.0.9",
      dst_port: 22,
      protocol: "TCP",
    };
    expect(describeEvent(event)).toBe("10.0.0.5:4444 -> 10.0.0.9:22 TCP");
  });
  it("summarises auth events by user", () => {
    expect(describeEvent({ ...base, username: "root" })).toBe("user root");
  });
});

describe("hoursAgoIso", () => {
  it("subtracts whole hours", () => {
    expect(hoursAgoIso(24, Date.parse("2026-01-02T00:00:00Z"))).toBe("2026-01-01T00:00:00.000Z");
  });
});

describe("toQuery", () => {
  it("drops empty values and keeps the rest", () => {
    expect(toQuery({ a: "x", b: "", c: undefined, d: 0, e: false })).toBe("?a=x&d=0&e=false");
    expect(toQuery({})).toBe("");
  });
});

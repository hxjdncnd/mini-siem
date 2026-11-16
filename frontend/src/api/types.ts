// These mirror the response models in backend/app/schemas.py.

export type Severity = "low" | "medium" | "high" | "critical";
export type AlertStatus = "OPEN" | "ACKNOWLEDGED" | "RESOLVED" | "FALSE_POSITIVE";
export type SourceType = "AUTH" | "WEB" | "FIREWALL";
export type EventAction =
  | "LOGIN_SUCCESS"
  | "LOGIN_FAILURE"
  | "INVALID_USER"
  | "SUDO_COMMAND"
  | "HTTP_REQUEST"
  | "CONN_BLOCKED"
  | "CONN_ALLOWED";

// Most urgent first: the order used wherever severities are listed.
export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];
export const STATUSES: AlertStatus[] = ["OPEN", "ACKNOWLEDGED", "RESOLVED", "FALSE_POSITIVE"];
export const SOURCE_TYPES: SourceType[] = ["AUTH", "WEB", "FIREWALL"];
export const ACTIONS: EventAction[] = [
  "LOGIN_SUCCESS",
  "LOGIN_FAILURE",
  "INVALID_USER",
  "SUDO_COMMAND",
  "HTTP_REQUEST",
  "CONN_BLOCKED",
  "CONN_ALLOWED",
];

export interface Page<T> {
  items: T[];
  total: number;
  page: number;
  size: number;
}

export interface LogEvent {
  id: string;
  timestamp: string;
  received_at: string;
  source_type: SourceType;
  action: EventAction;
  host: string | null;
  src_ip: string | null;
  dst_ip: string | null;
  src_port: number | null;
  dst_port: number | null;
  username: string | null;
  protocol: string | null;
  http_method: string | null;
  http_path: string | null;
  http_status: number | null;
  user_agent: string | null;
  raw: string | null;
}

export interface Alert {
  id: string;
  rule_id: string;
  rule_name: string;
  severity: Severity;
  score: number;
  status: AlertStatus;
  summary: string;
  group_key: string;
  mitre: string | null;
  src_ip: string | null;
  username: string | null;
  host: string | null;
  first_seen: string;
  last_seen: string;
  event_count: number;
  note: string | null;
  created_at: string;
  updated_at: string;
}

export interface AlertDetail extends Alert {
  events: LogEvent[];
}

export interface AlertUpdate {
  status?: AlertStatus;
  note?: string | null;
}

export interface Rule {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  type: string;
  group_by: string[];
  window_seconds: number | null;
  threshold: number | null;
  distinct_field: string | null;
  within_seconds: number | null;
  mitre: string | null;
  enabled: boolean;
  alert_count: number;
}

export interface CountBy {
  key: string;
  count: number;
}

export interface TimeBucket {
  start: string;
  count: number;
}

export interface StatsSummary {
  from: string;
  to: string;
  total_events: number;
  events_by_source: CountBy[];
  events_by_action: CountBy[];
  top_source_ips: CountBy[];
  events_over_time: TimeBucket[];
  bucket_seconds: number;
  total_alerts: number;
  open_alerts: number;
  alerts_by_severity: CountBy[];
  alerts_by_status: CountBy[];
  alerts_by_rule: CountBy[];
}

export interface Health {
  status: string;
  rules: number;
}

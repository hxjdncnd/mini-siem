import type { LogEvent } from "../api/types";

export function formatNumber(value: number): string {
  return value.toLocaleString("en-US");
}

/** "LOGIN_FAILURE" -> "Login failure" */
export function humanize(value: string): string {
  const text = value.replace(/_/g, " ").toLowerCase();
  return text.charAt(0).toUpperCase() + text.slice(1);
}

export function formatDateTime(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

/** Compact relative time: "just now", "5m ago", "3h ago", "2d ago". */
export function timeAgo(iso: string, now: number = Date.now()): string {
  const seconds = Math.round((now - new Date(iso).getTime()) / 1000);
  if (Number.isNaN(seconds)) return iso;
  if (seconds < 5) return "just now";
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

export function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)} min`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)} h`;
  return `${Math.round(seconds / 86400)} d`;
}

/** "T1110.001" -> link to the technique page on attack.mitre.org. */
export function mitreUrl(technique: string): string {
  const [id, sub] = technique.split(".");
  return `https://attack.mitre.org/techniques/${id}/${sub ? `${sub}/` : ""}`;
}

/** One line describing what an event was, whatever its source. */
export function describeEvent(event: LogEvent): string {
  switch (event.source_type) {
    case "WEB":
      return [event.http_method, event.http_path, event.http_status ? `-> ${event.http_status}` : null]
        .filter(Boolean)
        .join(" ");
    case "FIREWALL": {
      const from = event.src_ip ? `${event.src_ip}${event.src_port ? `:${event.src_port}` : ""}` : "?";
      const to = event.dst_ip ? `${event.dst_ip}${event.dst_port ? `:${event.dst_port}` : ""}` : "?";
      return `${from} -> ${to}${event.protocol ? ` ${event.protocol}` : ""}`;
    }
    default:
      return event.username ? `user ${event.username}` : "";
  }
}

export function hoursAgoIso(hours: number, now: number = Date.now()): string {
  return new Date(now - hours * 3600_000).toISOString();
}

/** Axis label for a timeline bucket; long buckets show the date, short ones the clock time. */
export function formatBucketLabel(iso: string, bucketSeconds: number): string {
  const date = new Date(iso);
  if (bucketSeconds >= 86400) return date.toLocaleDateString(undefined, { month: "short", day: "numeric" });
  return date.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", hour12: false });
}

import { useState } from "react";
import { Link } from "react-router-dom";
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api } from "../api/client";
import { SEVERITIES, type Severity } from "../api/types";
import { SeverityBadge, ScoreBar } from "../components/Badges";
import { BarList } from "../components/BarList";
import { Kpi } from "../components/Kpi";
import { PageHeader } from "../components/Layout";
import { Empty, ErrorState, Loading } from "../components/States";
import { useAsync } from "../hooks/useAsync";
import { formatBucketLabel, formatDateTime, formatDuration, formatNumber, hoursAgoIso, humanize, timeAgo } from "../lib/format";

const RANGES = [
  { label: "1h", hours: 1 },
  { label: "6h", hours: 6 },
  { label: "24h", hours: 24 },
  { label: "7d", hours: 168 },
  { label: "30d", hours: 720 },
];

export function Overview() {
  const [hours, setHours] = useState(24);
  const stats = useAsync((signal) => api.stats({ from: hoursAgoIso(hours), top: 8 }, signal), [hours], 15_000);
  const urgent = useAsync((signal) => api.alerts({ active: true, sort: "score", size: 6 }, signal), [], 15_000);

  const data = stats.data;
  const severityCount = (severity: Severity) => data?.alerts_by_severity.find((c) => c.key === severity)?.count ?? 0;
  const severityTotal = SEVERITIES.reduce((sum, s) => sum + severityCount(s), 0);

  return (
    <>
      <PageHeader
        title="Overview"
        subtitle="What the platform has seen and what it has flagged. Refreshes every 15 seconds."
        actions={
          <div className="segmented" role="group" aria-label="Time range">
            {RANGES.map((range) => (
              <button key={range.label} aria-pressed={hours === range.hours} onClick={() => setHours(range.hours)}>
                {range.label}
              </button>
            ))}
          </div>
        }
      />

      {!data && stats.loading && <Loading />}
      {!data && stats.error && <ErrorState error={stats.error} onRetry={stats.reload} />}

      {data && (
        <div className={stats.loading ? "dim" : undefined}>
          <section className="kpis" aria-label="Key numbers">
            <Kpi label="Events ingested" value={formatNumber(data.total_events)} hint={`last ${RANGES.find((r) => r.hours === hours)?.label}`} />
            <Kpi label="Active alerts" value={formatNumber(data.open_alerts)} hint="open or acknowledged" tone={data.open_alerts ? "high" : "accent"} />
            <Kpi label="Critical alerts" value={formatNumber(severityCount("critical"))} hint="in this range, any status" tone={severityCount("critical") ? "critical" : undefined} />
            <Kpi label="Total alerts" value={formatNumber(data.total_alerts)} hint="in this range, any status" />
          </section>

          <div className="grid-2">
            <section className="card">
              <div className="card-head">
                <h2>Events over time</h2>
                <span className="muted small">one bar = {formatDuration(data.bucket_seconds)}</span>
              </div>
              <div className="chart">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart
                    data={data.events_over_time.map((b) => ({
                      start: b.start,
                      label: formatBucketLabel(b.start, data.bucket_seconds),
                      count: b.count,
                    }))}
                    margin={{ top: 6, right: 8, bottom: 0, left: -12 }}
                  >
                    <defs>
                      <linearGradient id="events-fill" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#4cc9a7" stopOpacity={0.45} />
                        <stop offset="100%" stopColor="#4cc9a7" stopOpacity={0.02} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid stroke="#1d2a45" vertical={false} />
                    <XAxis dataKey="label" tick={{ fill: "#8794b0", fontSize: 11.5 }} tickLine={false} axisLine={{ stroke: "#22304d" }} minTickGap={32} />
                    <YAxis tick={{ fill: "#8794b0", fontSize: 11.5 }} tickLine={false} axisLine={false} allowDecimals={false} />
                    <Tooltip
                      contentStyle={{ background: "#0b1120", border: "1px solid #22304d", borderRadius: 8, fontSize: 12.5 }}
                      labelStyle={{ color: "#8794b0" }}
                      itemStyle={{ color: "#e5eaf5" }}
                      labelFormatter={(_, payload) => {
                        const start = payload?.[0]?.payload?.start;
                        return start ? formatDateTime(start) : "";
                      }}
                      formatter={(value) => [formatNumber(Number(value)), "Events"]}
                    />
                    <Area type="monotone" dataKey="count" stroke="#4cc9a7" strokeWidth={2} fill="url(#events-fill)" isAnimationActive={false} />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </section>

            <section className="card">
              <h2>Alerts by severity</h2>
              {severityTotal === 0 ? (
                <p className="muted small">No alerts in this range.</p>
              ) : (
                <>
                  <div className="sevstrip" role="img" aria-label="Alert severity distribution">
                    {SEVERITIES.map((s) => (
                      <span key={s} className={`sev-bg-${s}`} style={{ width: `${(severityCount(s) / severityTotal) * 100}%` }} />
                    ))}
                  </div>
                  <div className="legend">
                    {SEVERITIES.map((s) => (
                      <Link key={s} to={`/alerts?severity=${s}&status=all`}>
                        <i className={`sev-bg-${s}`} />
                        {humanize(s)} <strong>{severityCount(s)}</strong>
                      </Link>
                    ))}
                  </div>
                </>
              )}
              <h2 style={{ marginTop: 22 }}>Alerts by rule</h2>
              <BarList
                items={data.alerts_by_rule.slice(0, 6)}
                to={(rule) => `/alerts?rule_id=${encodeURIComponent(rule)}&status=all`}
                empty="No alerts in this range."
              />
            </section>
          </div>

          <div className="grid-3">
            <section className="card">
              <h2>Top source addresses</h2>
              <BarList items={data.top_source_ips} to={(ip) => `/events?src_ip=${encodeURIComponent(ip)}`} />
            </section>
            <section className="card">
              <h2>Events by source</h2>
              <BarList items={data.events_by_source} label={humanize} />
            </section>
            <section className="card">
              <h2>Events by action</h2>
              <BarList items={data.events_by_action} label={humanize} />
            </section>
          </div>
        </div>
      )}

      <section className="card">
        <div className="card-head">
          <h2>Highest-risk active alerts</h2>
          <Link to="/alerts?sort=score" className="small">
            View all alerts
          </Link>
        </div>
        {urgent.error && !urgent.data && <ErrorState error={urgent.error} onRetry={urgent.reload} />}
        {urgent.data && urgent.data.items.length === 0 && <Empty>No active alerts. Run the simulator to generate some.</Empty>}
        {urgent.data && urgent.data.items.length > 0 && (
          <div className="table-wrap" style={{ border: 0 }}>
            <table>
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Alert</th>
                  <th>Score</th>
                  <th className="nowrap">Last seen</th>
                </tr>
              </thead>
              <tbody>
                {urgent.data.items.map((alert) => (
                  <tr key={alert.id}>
                    <td>
                      <SeverityBadge severity={alert.severity} />
                    </td>
                    <td>
                      <Link to={`/alerts?alert=${alert.id}&status=all`}>{alert.rule_name}</Link>
                      <div className="cell-sub">{alert.summary}</div>
                    </td>
                    <td>
                      <ScoreBar score={alert.score} severity={alert.severity} />
                    </td>
                    <td className="nowrap muted">{timeAgo(alert.last_seen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  );
}

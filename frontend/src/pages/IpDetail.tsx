import { Link, useParams } from "react-router-dom";
import { ApiError, api } from "../api/client";
import { ScoreBar, SeverityBadge, StatusBadge } from "../components/Badges";
import { BarList } from "../components/BarList";
import { EventsChart } from "../components/EventsChart";
import { Kpi } from "../components/Kpi";
import { PageHeader } from "../components/Layout";
import { Empty, ErrorState, Loading } from "../components/States";
import { useAsync } from "../hooks/useAsync";
import { describeEvent, formatDateTime, formatDuration, formatNumber, humanize, timeAgo } from "../lib/format";

export function IpDetail() {
  const { ip = "" } = useParams();
  const profile = useAsync((signal) => api.ip(ip, signal), [ip], 15_000, { live: true });
  const data = profile.data;

  if (!data && profile.loading) return <Loading label="Looking up the address" />;
  if (!data && profile.error) {
    const unseen = profile.error instanceof ApiError && profile.error.status === 404;
    return unseen ? (
      <>
        <PageHeader title={ip} subtitle="Nothing recorded for this address." />
        <Empty>
          <strong>No activity from {ip}.</strong>
          <span>It has not appeared as a source in any ingested log.</span>
          <Link to="/events">Browse all events</Link>
        </Empty>
      </>
    ) : (
      <ErrorState error={profile.error} onRetry={profile.reload} />
    );
  }
  if (!data) return null;

  const active = data.alerts.filter((a) => a.status === "OPEN" || a.status === "ACKNOWLEDGED").length;
  const riskTone = data.max_score >= 90 ? "critical" : data.max_score >= 70 ? "high" : undefined;
  const lists = [
    { title: "Accounts it tried", items: data.usernames, label: (k: string) => k },
    { title: "Ports it probed", items: data.dst_ports, label: (k: string) => k },
    { title: "Paths it requested", items: data.http_paths, label: (k: string) => k },
    { title: "Machines it touched", items: data.hosts, label: (k: string) => k },
  ].filter((list) => list.items.length > 0);

  return (
    <>
      <PageHeader
        title={data.ip}
        subtitle={data.classification.label}
        actions={
          <Link className="btn" to={`/events?src_ip=${encodeURIComponent(data.ip)}`}>
            All events from this address
          </Link>
        }
      />

      <section className="kpis" aria-label="Key numbers">
        <Kpi label="Events" value={formatNumber(data.event_count)} hint="ever recorded from this address" />
        <Kpi label="Alerts" value={formatNumber(data.alerts.length)} hint={`${active} still active`} tone={active ? "high" : undefined} />
        <Kpi label="Highest risk" value={data.max_score || "-"} hint={data.max_score ? "alert risk score, 0-100" : "no alerts raised"} tone={riskTone} />
        <Kpi
          label="Last seen"
          value={data.last_seen ? timeAgo(data.last_seen) : "-"}
          hint={data.first_seen ? `first seen ${formatDateTime(data.first_seen)}` : undefined}
        />
      </section>

      <div className={`grid-2${lists.length ? "" : ""}`}>
        <section className="card">
          <div className="card-head">
            <h2>Activity</h2>
            <span className="muted small">one bar = {formatDuration(data.bucket_seconds)}</span>
          </div>
          <EventsChart buckets={data.events_over_time} bucketSeconds={data.bucket_seconds} />
        </section>
        <section className="card">
          <h2>What it did</h2>
          <BarList items={data.actions} label={humanize} />
        </section>
      </div>

      {lists.length > 0 && (
        <div className="grid-auto">
          {lists.map((list) => (
            <section className="card" key={list.title}>
              <h2>{list.title}</h2>
              <BarList items={list.items} label={list.label} />
            </section>
          ))}
        </div>
      )}

      <section className="card" style={{ marginBottom: 14 }}>
        <h2>Alerts about this address</h2>
        {data.alerts.length === 0 ? (
          <p className="muted small">None. Its activity did not trip any detection rule.</p>
        ) : (
          <div className="table-wrap" style={{ border: 0 }}>
            <table>
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Alert</th>
                  <th>Risk</th>
                  <th>Status</th>
                  <th className="nowrap">Last seen</th>
                </tr>
              </thead>
              <tbody>
                {data.alerts.map((alert) => (
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
                    <td>
                      <StatusBadge status={alert.status} />
                    </td>
                    <td className="nowrap muted">{timeAgo(alert.last_seen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="card">
        <div className="card-head">
          <h2>Latest events</h2>
          <span className="muted small">newest first</span>
        </div>
        <div className="table-wrap" style={{ border: 0 }}>
          <table>
            <thead>
              <tr>
                <th className="nowrap">Time</th>
                <th>Action</th>
                <th>Machine</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>
              {data.recent_events.map((event) => (
                <tr key={event.id}>
                  <td className="nowrap muted">{formatDateTime(event.timestamp)}</td>
                  <td className="nowrap">{humanize(event.action)}</td>
                  <td className="mono">{event.host ?? "-"}</td>
                  <td className="mono">{describeEvent(event)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </>
  );
}

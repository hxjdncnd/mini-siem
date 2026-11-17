import { Fragment, useState } from "react";
import { api } from "../api/client";
import { ACTIONS, SOURCE_TYPES } from "../api/types";
import { ExportButton } from "../components/ExportButton";
import { IpLink } from "../components/IpLink";
import { PageHeader } from "../components/Layout";
import { Pagination } from "../components/Pagination";
import { Empty, ErrorState, Loading } from "../components/States";
import { TextFilter } from "../components/TextFilter";
import { useAsync } from "../hooks/useAsync";
import { useFilters } from "../hooks/useFilters";
import { describeEvent, formatDateTime, humanize } from "../lib/format";

const PAGE_SIZE = 50;
const DEFAULTS = { source_type: "", action: "", src_ip: "", username: "", q: "", page: "0" };

export function Events() {
  const [filters, setFilters] = useFilters(DEFAULTS);
  const page = Math.max(0, Number(filters.page) || 0);
  const [expanded, setExpanded] = useState<string | null>(null);

  const query = {
    source_type: filters.source_type,
    action: filters.action,
    src_ip: filters.src_ip,
    username: filters.username,
    q: filters.q,
  };
  const events = useAsync(
    (signal) => api.events({ ...query, page, size: PAGE_SIZE }, signal),
    [filters.source_type, filters.action, filters.src_ip, filters.username, filters.q, page],
  );
  const data = events.data;

  return (
    <>
      <PageHeader
        title="Events"
        subtitle="Every normalized log event, newest first."
        actions={
          <>
            <ExportButton path="/events/export.csv" params={query} />
            <button className="btn" onClick={events.reload}>
              Refresh
            </button>
          </>
        }
      />

      <div className="filters">
        <div className="field">
          <label htmlFor="f-source">Source</label>
          <select id="f-source" value={filters.source_type} onChange={(e) => setFilters({ source_type: e.target.value })}>
            <option value="">Any</option>
            {SOURCE_TYPES.map((s) => (
              <option key={s} value={s}>
                {humanize(s)}
              </option>
            ))}
          </select>
        </div>
        <div className="field">
          <label htmlFor="f-action">Action</label>
          <select id="f-action" value={filters.action} onChange={(e) => setFilters({ action: e.target.value })}>
            <option value="">Any</option>
            {ACTIONS.map((a) => (
              <option key={a} value={a}>
                {humanize(a)}
              </option>
            ))}
          </select>
        </div>
        <TextFilter label="Source IP" value={filters.src_ip} onCommit={(v) => setFilters({ src_ip: v })} />
        <TextFilter label="User" value={filters.username} onCommit={(v) => setFilters({ username: v })} width={120} />
        <TextFilter label="Search raw log" value={filters.q} onCommit={(v) => setFilters({ q: v })} width={220} placeholder="text in the log line" />
      </div>

      {!data && events.loading && <Loading />}
      {!data && events.error && <ErrorState error={events.error} onRetry={events.reload} />}
      {events.error && data && <p className="muted small">Could not refresh: {events.error.message}</p>}
      {data && data.items.length === 0 && <Empty>No events match these filters.</Empty>}

      {data && data.items.length > 0 && (
        <>
          <div className={`table-wrap${events.loading ? " dim" : ""}`}>
            <table>
              <thead>
                <tr>
                  <th className="nowrap">Time</th>
                  <th>Source</th>
                  <th>Action</th>
                  <th>Host</th>
                  <th>Source IP</th>
                  <th>User</th>
                  <th>Detail</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((event) => {
                  const open = expanded === event.id;
                  return (
                    <Fragment key={event.id}>
                      <tr
                        className={`clickable${open ? " selected" : ""}`}
                        tabIndex={0}
                        aria-expanded={open}
                        onClick={() => setExpanded(open ? null : event.id)}
                        onKeyDown={(e) => {
                          if (e.key === "Enter") setExpanded(open ? null : event.id);
                        }}
                      >
                        <td className="nowrap muted">{formatDateTime(event.timestamp)}</td>
                        <td className="nowrap">{humanize(event.source_type)}</td>
                        <td className="nowrap">{humanize(event.action)}</td>
                        <td className="mono">{event.host ?? "-"}</td>
                        <td className="mono">{event.src_ip ? <IpLink ip={event.src_ip} /> : "-"}</td>
                        <td className="mono">{event.username ?? "-"}</td>
                        <td className="mono">{describeEvent(event)}</td>
                      </tr>
                      {open && (
                        <tr>
                          <td colSpan={7}>
                            <pre className="raw">{event.raw ?? "(no raw line stored)"}</pre>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
          <Pagination page={page} size={PAGE_SIZE} total={data.total} onPage={(p) => setFilters({ page: String(p) })} />
        </>
      )}
    </>
  );
}

import { api } from "../api/client";
import { SEVERITIES, STATUSES } from "../api/types";
import { ScoreBar, SeverityBadge, StatusBadge } from "../components/Badges";
import { PageHeader } from "../components/Layout";
import { Pagination } from "../components/Pagination";
import { Empty, ErrorState, Loading } from "../components/States";
import { TextFilter } from "../components/TextFilter";
import { useAsync } from "../hooks/useAsync";
import { useFilters } from "../hooks/useFilters";
import { formatNumber, humanize, timeAgo } from "../lib/format";
import { AlertDrawer } from "./AlertDrawer";

const PAGE_SIZE = 25;
const DEFAULTS = { status: "active", severity: "", rule_id: "", src_ip: "", sort: "recent", page: "0", alert: "" };
const KEEP_PAGE = ["page", "alert"];

export function Alerts() {
  const [filters, setFilters] = useFilters(DEFAULTS, KEEP_PAGE);
  const page = Math.max(0, Number(filters.page) || 0);

  const rules = useAsync((signal) => api.rules(signal), []);
  const alerts = useAsync(
    (signal) =>
      api.alerts(
        {
          active: filters.status === "active" ? true : undefined,
          status: filters.status === "active" || filters.status === "all" ? undefined : filters.status,
          severity: filters.severity,
          rule_id: filters.rule_id,
          src_ip: filters.src_ip,
          sort: filters.sort,
          page,
          size: PAGE_SIZE,
        },
        signal,
      ),
    [filters.status, filters.severity, filters.rule_id, filters.src_ip, filters.sort, page],
    15_000,
  );

  const data = alerts.data;

  return (
    <>
      <PageHeader title="Alerts" subtitle="Detections raised by the rule engine. Click one to see its evidence and triage it." />

      <div className="filters">
        <div className="field">
          <label htmlFor="f-status">Status</label>
          <select id="f-status" value={filters.status} onChange={(e) => setFilters({ status: e.target.value })}>
            <option value="active">Active (open + acknowledged)</option>
            <option value="all">All</option>
            {STATUSES.map((s) => (
              <option key={s} value={s}>
                {humanize(s)}
              </option>
            ))}
          </select>
        </div>
        <div className="field">
          <label htmlFor="f-severity">Severity</label>
          <select id="f-severity" value={filters.severity} onChange={(e) => setFilters({ severity: e.target.value })}>
            <option value="">Any</option>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {humanize(s)}
              </option>
            ))}
          </select>
        </div>
        <div className="field">
          <label htmlFor="f-rule">Rule</label>
          <select id="f-rule" value={filters.rule_id} onChange={(e) => setFilters({ rule_id: e.target.value })}>
            <option value="">Any</option>
            {rules.data?.map((rule) => (
              <option key={rule.id} value={rule.id}>
                {rule.name}
              </option>
            ))}
            {filters.rule_id && !rules.data?.some((r) => r.id === filters.rule_id) && (
              <option value={filters.rule_id}>{filters.rule_id}</option>
            )}
          </select>
        </div>
        <TextFilter label="Source IP" value={filters.src_ip} onCommit={(v) => setFilters({ src_ip: v })} placeholder="e.g. 203.0.113.7" />
        <div className="field">
          <label htmlFor="f-sort">Sort by</label>
          <select id="f-sort" value={filters.sort} onChange={(e) => setFilters({ sort: e.target.value })}>
            <option value="recent">Most recent</option>
            <option value="score">Highest risk</option>
          </select>
        </div>
      </div>

      {!data && alerts.loading && <Loading />}
      {!data && alerts.error && <ErrorState error={alerts.error} onRetry={alerts.reload} />}
      {alerts.error && data && <p className="muted small">Could not refresh: {alerts.error.message}</p>}

      {data && data.items.length === 0 && (
        <Empty>
          <strong>No alerts match these filters.</strong>
          <span>Run the simulator (python3 simulator/simulate.py) to generate some.</span>
        </Empty>
      )}

      {data && data.items.length > 0 && (
        <>
          <div className={`table-wrap${alerts.loading ? " dim" : ""}`}>
            <table>
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Alert</th>
                  <th>Entity</th>
                  <th>Risk</th>
                  <th>Events</th>
                  <th>Status</th>
                  <th className="nowrap">Last seen</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((alert) => (
                  <tr
                    key={alert.id}
                    className={`clickable${filters.alert === alert.id ? " selected" : ""}`}
                    tabIndex={0}
                    onClick={() => setFilters({ alert: alert.id })}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") setFilters({ alert: alert.id });
                    }}
                  >
                    <td>
                      <SeverityBadge severity={alert.severity} />
                    </td>
                    <td>
                      <strong>{alert.rule_name}</strong>
                      <div className="cell-sub">{alert.summary}</div>
                    </td>
                    <td className="mono">
                      {alert.src_ip ?? alert.username ?? alert.host ?? "-"}
                      {alert.src_ip && alert.username && <div className="cell-sub">user {alert.username}</div>}
                    </td>
                    <td>
                      <ScoreBar score={alert.score} severity={alert.severity} />
                    </td>
                    <td>{formatNumber(alert.event_count)}</td>
                    <td>
                      <StatusBadge status={alert.status} />
                    </td>
                    <td className="nowrap muted">{timeAgo(alert.last_seen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pagination page={page} size={PAGE_SIZE} total={data.total} onPage={(p) => setFilters({ page: String(p) })} />
        </>
      )}

      {filters.alert && (
        <AlertDrawer id={filters.alert} onClose={() => setFilters({ alert: "" })} onChanged={alerts.reload} />
      )}
    </>
  );
}

import { Link } from "react-router-dom";
import { api } from "../api/client";
import type { Rule } from "../api/types";
import { SeverityBadge } from "../components/Badges";
import { PageHeader } from "../components/Layout";
import { ErrorState, Loading } from "../components/States";
import { useAsync } from "../hooks/useAsync";
import { formatDuration, humanize, mitreUrl } from "../lib/format";

/** The rule's trigger condition in one plain sentence. */
function condition(rule: Rule): string {
  const window = rule.window_seconds ? formatDuration(rule.window_seconds) : null;
  switch (rule.type) {
    case "threshold":
      return `${rule.threshold} matching events within ${window}`;
    case "distinct":
      return `${rule.threshold} distinct ${rule.distinct_field} values within ${window}`;
    case "sequence":
      return `${rule.threshold} matching events, then a follow-up event within ${
        rule.within_seconds ? formatDuration(rule.within_seconds) : "the time limit"
      }`;
    default:
      return "Any single matching event";
  }
}

export function Rules() {
  const rules = useAsync((signal) => api.rules(signal), []);
  const data = rules.data;

  return (
    <>
      <PageHeader title="Detection rules" subtitle="Loaded from backend/rules/*.yml and checked when the server starts." />
      {!data && rules.loading && <Loading />}
      {!data && rules.error && <ErrorState error={rules.error} onRetry={rules.reload} />}
      {data && (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Rule</th>
                <th>Type</th>
                <th>Severity</th>
                <th>Triggers when</th>
                <th>Grouped by</th>
                <th>MITRE</th>
                <th>Alerts</th>
              </tr>
            </thead>
            <tbody>
              {data.map((rule) => (
                <tr key={rule.id}>
                  <td>
                    <strong>{rule.name}</strong>
                    {!rule.enabled && <span className="badge status-false_positive" style={{ marginLeft: 8 }}>disabled</span>}
                    <div className="cell-sub">{rule.description}</div>
                    <div className="cell-sub mono">{rule.id}</div>
                  </td>
                  <td>{humanize(rule.type)}</td>
                  <td>
                    <SeverityBadge severity={rule.severity} />
                  </td>
                  <td>{condition(rule)}</td>
                  <td className="mono">{rule.group_by.length ? rule.group_by.join(", ") : "-"}</td>
                  <td>
                    {rule.mitre ? (
                      <a href={mitreUrl(rule.mitre)} target="_blank" rel="noreferrer noopener">
                        {rule.mitre}
                      </a>
                    ) : (
                      "-"
                    )}
                  </td>
                  <td>
                    <Link to={`/alerts?rule_id=${encodeURIComponent(rule.id)}&status=all`}>{rule.alert_count}</Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}

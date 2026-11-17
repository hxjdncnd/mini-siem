import { Link } from "react-router-dom";
import { api } from "../api/client";
import type { Rule } from "../api/types";
import { ScoreBar, SeverityBadge } from "../components/Badges";
import { Drawer } from "../components/Drawer";
import { IpLink } from "../components/IpLink";
import { ErrorState, Loading } from "../components/States";
import { useAsync } from "../hooks/useAsync";
import { formatDateTime, formatNumber } from "../lib/format";

/** Dry run of one rule over the stored events: what it would raise, without raising anything. */
export function RuleTestDrawer({ rule, onClose }: { rule: Rule; onClose: () => void }) {
  const test = useAsync((signal) => api.testRule(rule.id, signal), [rule.id]);
  const result = test.data;

  return (
    <Drawer title={`Test: ${rule.name}`} onClose={onClose}>
      {!result && test.loading && <Loading label="Replaying stored events through the rule" />}
      {!result && test.error && <ErrorState error={test.error} onRetry={test.reload} />}

      {result && (
        <>
          <div>
            <p style={{ fontSize: 15 }}>
              {result.would_raise === 0 ? (
                <>
                  <strong>Nothing.</strong> This rule would not have raised an alert on the stored events.
                </>
              ) : (
                <>
                  <strong>
                    {formatNumber(result.would_raise)} {result.would_raise === 1 ? "alert" : "alerts"}
                  </strong>{" "}
                  would be raised on the stored events.
                </>
              )}
            </p>
            <p className="muted small" style={{ marginTop: 6 }}>
              Replayed {formatNumber(result.events_scanned)}
              {result.events_scanned < result.events_total ? ` of ${formatNumber(result.events_total)}` : ""} events
              {result.scanned_from && result.scanned_to
                ? ` from ${formatDateTime(result.scanned_from)} to ${formatDateTime(result.scanned_to)}`
                : ""}
              . {formatNumber(result.already_raised)} {result.already_raised === 1 ? "alert has" : "alerts have"} already
              been raised by this rule
              {!result.enabled && " (it is switched off, so it raises nothing new)"}. Nothing was created or changed.
            </p>
          </div>

          {result.findings.length > 0 && (
            <section>
              <h3 style={{ marginBottom: 8 }}>
                Would raise{" "}
                {result.would_raise > result.findings.length && (
                  <span className="muted small" style={{ fontWeight: 400 }}>
                    (highest risk {result.findings.length} of {formatNumber(result.would_raise)})
                  </span>
                )}
              </h3>
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Severity</th>
                      <th>What</th>
                      <th>Risk</th>
                      <th>Events</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.findings.map((finding) => (
                      <tr key={`${finding.group_key}-${finding.first_seen}`}>
                        <td>
                          <SeverityBadge severity={finding.severity} />
                        </td>
                        <td>
                          {finding.summary}
                          <div className="cell-sub">
                            {finding.src_ip ? <IpLink ip={finding.src_ip} /> : finding.username ?? finding.host ?? finding.group_key}
                            {" - "}
                            {formatDateTime(finding.first_seen)}
                          </div>
                        </td>
                        <td>
                          <ScoreBar score={finding.score} severity={finding.severity} />
                        </td>
                        <td>{formatNumber(finding.event_count)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          )}

          <p className="muted small">
            Want to see the alerts that already exist?{" "}
            <Link to={`/alerts?rule_id=${encodeURIComponent(rule.id)}&status=all`} onClick={onClose}>
              Open them in the queue
            </Link>
            .
          </p>
        </>
      )}
    </Drawer>
  );
}

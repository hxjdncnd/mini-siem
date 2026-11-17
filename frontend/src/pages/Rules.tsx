import { useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import type { NotificationTest, Rule } from "../api/types";
import { SeverityBadge } from "../components/Badges";
import { PageHeader } from "../components/Layout";
import { ErrorState, Loading } from "../components/States";
import { useAsync } from "../hooks/useAsync";
import { formatDuration, humanize, mitreUrl } from "../lib/format";
import { RuleTestDrawer } from "./RuleTestDrawer";

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

function Notifications() {
  const status = useAsync((signal) => api.notifications(signal), []);
  const [sending, setSending] = useState(false);
  const [outcome, setOutcome] = useState<{ ok: boolean; text: string } | null>(null);
  const data = status.data;
  if (!data) return null;

  async function sendTest() {
    setSending(true);
    setOutcome(null);
    try {
      const result: NotificationTest = await api.testNotification();
      setOutcome(
        result.delivered
          ? { ok: true, text: `Delivered (HTTP ${result.status}). Check the channel.` }
          : { ok: false, text: `Not delivered: ${result.error ?? "unknown error"}` },
      );
    } catch (error) {
      setOutcome({ ok: false, text: error instanceof Error ? error.message : "Could not send the test." });
    } finally {
      setSending(false);
    }
  }

  return (
    <section className="card notify" aria-label="Notifications">
      <div>
        <h2>Notifications</h2>
        {data.enabled ? (
          <p>
            New <strong>{data.min_severity}</strong> alerts, and anything more serious, are posted to{" "}
            <strong className="mono">{data.destination}</strong> as soon as they are raised.
          </p>
        ) : (
          <p className="muted">
            Off. Set <code>MINISIEM_WEBHOOK_URL</code> to a Slack, Discord or any other webhook address and restart the
            server to get a message when a serious alert appears.
          </p>
        )}
      </div>
      {data.enabled && (
        <div className="notify-actions">
          {outcome && (
            <span className="small" role={outcome.ok ? "status" : "alert"} style={{ color: outcome.ok ? "var(--accent)" : "var(--high)" }}>
              {outcome.text}
            </span>
          )}
          <button className="btn" onClick={() => void sendTest()} disabled={sending}>
            {sending ? "Sending..." : "Send a test message"}
          </button>
        </div>
      )}
    </section>
  );
}

export function Rules() {
  const rules = useAsync((signal) => api.rules(signal), []);
  const data = rules.data;
  const [testing, setTesting] = useState<Rule | null>(null);
  const [switching, setSwitching] = useState<string | null>(null);
  const [problem, setProblem] = useState<string | null>(null);

  async function setEnabled(rule: Rule, enabled: boolean) {
    setSwitching(rule.id);
    setProblem(null);
    try {
      await api.setRuleEnabled(rule.id, enabled);
      rules.reload();
    } catch (error) {
      setProblem(error instanceof Error ? error.message : "Could not change the rule.");
    } finally {
      setSwitching(null);
    }
  }

  return (
    <>
      <PageHeader
        title="Detection rules"
        subtitle="Loaded from backend/rules/*.yml and checked when the server starts. Switch one off, or try it against the stored events first."
      />
      <Notifications />
      {problem && (
        <div className="state state-error" role="alert" style={{ marginBottom: 14 }}>
          {problem}
        </div>
      )}
      {!data && rules.loading && <Loading />}
      {!data && rules.error && <ErrorState error={rules.error} onRetry={rules.reload} />}
      {data && (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>On</th>
                <th>Rule</th>
                <th>Type</th>
                <th>Severity</th>
                <th>Triggers when</th>
                <th>Grouped by</th>
                <th>MITRE</th>
                <th>Alerts</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {data.map((rule) => (
                <tr key={rule.id} className={rule.enabled ? undefined : "row-off"}>
                  <td>
                    <label className="switch">
                      <input
                        type="checkbox"
                        role="switch"
                        aria-label={`${rule.enabled ? "Switch off" : "Switch on"} ${rule.name}`}
                        checked={rule.enabled}
                        disabled={switching === rule.id}
                        onChange={(event) => void setEnabled(rule, event.target.checked)}
                      />
                      <span className="track" aria-hidden="true" />
                    </label>
                  </td>
                  <td>
                    <strong>{rule.name}</strong>
                    {!rule.enabled && <span className="badge status-false_positive" style={{ marginLeft: 8 }}>off</span>}
                    <div className="cell-sub">{rule.description}</div>
                    <div className="cell-sub mono">{rule.id}</div>
                  </td>
                  <td>{humanize(rule.type)}</td>
                  <td>
                    <SeverityBadge severity={rule.severity} />
                  </td>
                  <td className="cond">{condition(rule)}</td>
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
                  <td>
                    <button className="btn" onClick={() => setTesting(rule)} aria-label={`Test ${rule.name}`}>
                      Test
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {testing && <RuleTestDrawer rule={testing} onClose={() => setTesting(null)} />}
    </>
  );
}

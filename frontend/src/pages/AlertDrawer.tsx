import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import type { AlertStatus } from "../api/types";
import { ScoreBar, SeverityBadge, StatusBadge } from "../components/Badges";
import { Drawer } from "../components/Drawer";
import { IpLink } from "../components/IpLink";
import { ErrorState, Loading } from "../components/States";
import { useAsync } from "../hooks/useAsync";
import { describeEvent, formatDateTime, formatNumber, humanize, mitreUrl } from "../lib/format";

const ACTION_LABEL: Record<AlertStatus, string> = {
  OPEN: "Reopen",
  ACKNOWLEDGED: "Acknowledge",
  RESOLVED: "Resolve",
  FALSE_POSITIVE: "Mark false positive",
};
const ACTION_ORDER: AlertStatus[] = ["ACKNOWLEDGED", "RESOLVED", "FALSE_POSITIVE", "OPEN"];

export function AlertDrawer({ id, onClose, onChanged }: { id: string; onClose: () => void; onChanged: () => void }) {
  const detail = useAsync((signal) => api.alert(id, signal), [id]);
  const alert = detail.data;

  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);

  useEffect(() => {
    setNote(alert?.note ?? "");
  }, [alert?.id, alert?.note]);

  async function save(update: { status?: AlertStatus; note?: string | null }) {
    setBusy(true);
    setProblem(null);
    try {
      await api.updateAlert(id, update);
      detail.reload();
      onChanged();
    } catch (error) {
      setProblem(error instanceof Error ? error.message : "Could not save the change.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Drawer title={alert ? alert.rule_name : "Alert"} onClose={onClose}>
      {!alert && detail.loading && <Loading />}
      {!alert && detail.error && <ErrorState error={detail.error} onRetry={detail.reload} />}

      {alert && (
        <>
          <div>
            <p style={{ fontSize: 15 }}>{alert.summary}</p>
            <p className="muted small" style={{ marginTop: 6, display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
              <SeverityBadge severity={alert.severity} />
              <StatusBadge status={alert.status} />
              <ScoreBar score={alert.score} severity={alert.severity} />
            </p>
          </div>

          <dl className="meta">
            <div>
              <dt>Rule</dt>
              <dd>
                <Link to={`/alerts?rule_id=${encodeURIComponent(alert.rule_id)}&status=all`} onClick={onClose}>
                  {alert.rule_id}
                </Link>
              </dd>
            </div>
            <div>
              <dt>MITRE ATT&amp;CK</dt>
              <dd>
                {alert.mitre ? (
                  <a href={mitreUrl(alert.mitre)} target="_blank" rel="noreferrer noopener">
                    {alert.mitre}
                  </a>
                ) : (
                  "-"
                )}
              </dd>
            </div>
            <div>
              <dt>Source IP</dt>
              <dd className="mono">{alert.src_ip ? <IpLink ip={alert.src_ip} /> : "-"}</dd>
            </div>
            <div>
              <dt>User</dt>
              <dd className="mono">{alert.username ?? "-"}</dd>
            </div>
            <div>
              <dt>Host</dt>
              <dd className="mono">{alert.host ?? "-"}</dd>
            </div>
            <div>
              <dt>Events</dt>
              <dd>{formatNumber(alert.event_count)}</dd>
            </div>
            <div>
              <dt>First seen</dt>
              <dd>{formatDateTime(alert.first_seen)}</dd>
            </div>
            <div>
              <dt>Last seen</dt>
              <dd>{formatDateTime(alert.last_seen)}</dd>
            </div>
          </dl>

          <section>
            <h2 style={{ marginBottom: 10 }}>Triage</h2>
            <div className="actions">
              {ACTION_ORDER.filter((status) => status !== alert.status).map((status) => (
                <button key={status} className="btn" disabled={busy} onClick={() => save({ status })}>
                  {ACTION_LABEL[status]}
                </button>
              ))}
            </div>
            <div className="field" style={{ marginTop: 14 }}>
              <label htmlFor="alert-note">Analyst note</label>
              <textarea
                id="alert-note"
                value={note}
                maxLength={2000}
                placeholder="What did you find? Why is this a false positive?"
                onChange={(e) => setNote(e.target.value)}
              />
            </div>
            <div className="actions" style={{ marginTop: 8 }}>
              <button
                className="btn btn-primary"
                disabled={busy || note === (alert.note ?? "")}
                onClick={() => save({ note: note.trim() === "" ? null : note })}
              >
                Save note
              </button>
            </div>
            {problem && (
              <p role="alert" className="small" style={{ color: "var(--critical)", marginTop: 8 }}>
                {problem}
              </p>
            )}
          </section>

          <section>
            <h2 style={{ marginBottom: 10 }}>
              Evidence{" "}
              <span className="muted small" style={{ fontWeight: 400 }}>
                {alert.events.length < alert.event_count
                  ? `showing the first ${alert.events.length} of ${formatNumber(alert.event_count)} events`
                  : `${formatNumber(alert.events.length)} events, oldest first`}
              </span>
            </h2>
            <div className="evidence">
              {alert.events.map((event) => (
                <article key={event.id} className="evidence-item">
                  <div className="evidence-head">
                    <span>
                      <strong>{humanize(event.action)}</strong>{" "}
                      <span className="muted">{describeEvent(event)}</span>
                    </span>
                    <span className="muted nowrap">{formatDateTime(event.timestamp)}</span>
                  </div>
                  {event.raw && <pre className="raw">{event.raw}</pre>}
                </article>
              ))}
            </div>
          </section>
        </>
      )}
    </Drawer>
  );
}

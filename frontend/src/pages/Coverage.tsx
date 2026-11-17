import { useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import type { CoverageTechnique, Severity } from "../api/types";
import { Kpi } from "../components/Kpi";
import { PageHeader } from "../components/Layout";
import { ErrorState, Loading } from "../components/States";
import { useAsync } from "../hooks/useAsync";
import { formatNumber, mitreUrl } from "../lib/format";

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low"];

/** The most serious severity among the rules covering a technique, used to colour its card. */
function topSeverity(technique: CoverageTechnique): Severity | null {
  return SEVERITY_ORDER.find((s) => technique.rules.some((r) => r.severity === s)) ?? null;
}

function TechniqueCard({ technique }: { technique: CoverageTechnique }) {
  const severity = topSeverity(technique);
  const allOff = technique.covered && technique.rules.every((r) => !r.enabled);
  return (
    <li className={`tech${technique.covered ? "" : " tech-gap"}${allOff ? " tech-off" : ""}`} data-severity={severity ?? undefined}>
      <div className="tech-head">
        <a href={mitreUrl(technique.id)} target="_blank" rel="noreferrer noopener" className="mono small">
          {technique.id}
        </a>
        {technique.alert_count > 0 && (
          <span className="tech-alerts" title={`${technique.active_alerts} still active`}>
            {formatNumber(technique.alert_count)} {technique.alert_count === 1 ? "alert" : "alerts"}
          </span>
        )}
      </div>
      <div className="tech-name">{technique.name}</div>
      {technique.covered ? (
        <ul className="tech-rules">
          {technique.rules.map((rule) => (
            <li key={rule.id}>
              <Link to={`/alerts?rule_id=${encodeURIComponent(rule.id)}&status=all`}>{rule.name}</Link>
              {!rule.enabled && <span className="badge status-false_positive">off</span>}
            </li>
          ))}
        </ul>
      ) : (
        <div className="small muted">No rule yet</div>
      )}
    </li>
  );
}

export function Coverage() {
  const coverage = useAsync((signal) => api.coverage(signal), [], undefined, { live: true });
  const [showGaps, setShowGaps] = useState(true);
  const data = coverage.data;

  const gapCount = data ? new Set(data.tactics.flatMap((t) => t.techniques.filter((x) => !x.covered).map((x) => x.id))).size : 0;

  return (
    <>
      <PageHeader
        title="ATT&CK coverage"
        subtitle="Which MITRE ATT&CK techniques the detection rules watch for, laid out by tactic. Every card links to its rules and alerts."
        actions={
          <label className="check">
            <input type="checkbox" checked={showGaps} onChange={(event) => setShowGaps(event.target.checked)} />
            Show techniques with no rule yet
          </label>
        }
      />
      {!data && coverage.loading && <Loading />}
      {!data && coverage.error && <ErrorState error={coverage.error} onRetry={coverage.reload} />}
      {data && (
        <>
          <section className="kpis" aria-label="Coverage summary">
            <Kpi label="Techniques covered" value={formatNumber(data.techniques_covered)} tone="accent" hint="with at least one rule" />
            <Kpi label="Rules on" value={`${data.rules_enabled} / ${data.rules_total}`} hint={data.rules_enabled < data.rules_total ? "some are switched off" : "all running"} />
            <Kpi label="Ideas for next rules" value={formatNumber(gapCount)} hint="hand-picked, not the whole matrix" />
          </section>

          <div className="matrix" role="list" aria-label="ATT&CK tactics">
            {data.tactics.map((tactic) => {
              const shown = tactic.techniques.filter((t) => showGaps || t.covered);
              if (shown.length === 0) return null;
              const covered = tactic.techniques.filter((t) => t.covered).length;
              return (
                <section className="tactic" key={tactic.id} role="listitem" aria-label={tactic.name}>
                  <header>
                    <h3>{tactic.name}</h3>
                    <span className="muted small">{covered > 0 ? `${covered} covered` : "no rules"}</span>
                  </header>
                  <ul>
                    {shown.map((technique) => (
                      <TechniqueCard key={technique.id} technique={technique} />
                    ))}
                  </ul>
                </section>
              );
            })}
          </div>

          <p className="muted small" style={{ marginTop: 14 }}>
            A technique counts as covered when a rule is tagged with it. That says a rule exists, not that it would catch every
            variant of the behaviour, so read it as a map of intent. Rules are tagged in <code>backend/rules/*.yml</code> with{" "}
            <code>mitre:</code>.
            {data.rules_untagged.length > 0 && ` Not on the map because they have no tag: ${data.rules_untagged.join(", ")}.`}
          </p>
        </>
      )}
    </>
  );
}

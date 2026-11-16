import type { AlertStatus, Severity } from "../api/types";
import { humanize } from "../lib/format";

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`badge sev-${severity}`}>{severity}</span>;
}

export function StatusBadge({ status }: { status: AlertStatus }) {
  return <span className={`badge status-${status.toLowerCase()}`}>{humanize(status)}</span>;
}

/** Risk score 0-100 as a small bar coloured by the alert's severity. */
export function ScoreBar({ score, severity }: { score: number; severity: Severity }) {
  return (
    <span className="score" title={`Risk score ${score} / 100`}>
      <span className="score-track">
        <span className={`score-fill sev-bg-${severity}`} style={{ width: `${Math.min(100, score)}%` }} />
      </span>
      <span className="score-num">{score}</span>
    </span>
  );
}

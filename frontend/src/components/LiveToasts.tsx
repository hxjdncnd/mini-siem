import { Link } from "react-router-dom";
import { useLive } from "../hooks/useLive";
import { SeverityBadge } from "./Badges";

/** New serious alerts, popping up wherever the analyst happens to be looking. */
export function LiveToasts() {
  const { toasts, dismiss } = useLive();
  if (toasts.length === 0) return null;
  return (
    <div className="toasts" aria-live="polite" aria-label="New alerts">
      {toasts.map((toast) => (
        <div className={`toast toast-${toast.severity}`} key={toast.id} role="status">
          <div className="toast-head">
            <SeverityBadge severity={toast.severity} />
            <strong>{toast.rule_name}</strong>
            <button className="toast-close" onClick={() => dismiss(toast.id)} aria-label={`Dismiss ${toast.rule_name}`}>
              &times;
            </button>
          </div>
          <p className="small">{toast.summary}</p>
          <Link to={`/alerts?alert=${encodeURIComponent(toast.id)}&status=all`} onClick={() => dismiss(toast.id)}>
            Open the alert
          </Link>
        </div>
      ))}
    </div>
  );
}

import { Link } from "react-router-dom";
import type { CountBy } from "../api/types";
import { formatNumber } from "../lib/format";

/** A ranked list where each row's bar is sized relative to the largest count. */
export function BarList({
  items,
  label = (key) => key,
  to,
  empty = "Nothing to show in this range.",
}: {
  items: CountBy[];
  label?: (key: string) => string;
  to?: (key: string) => string;
  empty?: string;
}) {
  if (items.length === 0) return <p className="muted small">{empty}</p>;
  const max = Math.max(...items.map((item) => item.count), 1);
  return (
    <ul className="barlist">
      {items.map((item) => (
        <li key={item.key}>
          <div className="barlist-row">
            {to ? (
              <Link className="barlist-label mono" to={to(item.key)}>
                {label(item.key)}
              </Link>
            ) : (
              <span className="barlist-label">{label(item.key)}</span>
            )}
            <span className="barlist-count">{formatNumber(item.count)}</span>
          </div>
          <div className="barlist-track">
            <div className="barlist-fill" style={{ width: `${(item.count / max) * 100}%` }} />
          </div>
        </li>
      ))}
    </ul>
  );
}

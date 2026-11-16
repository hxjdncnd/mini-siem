import { formatNumber } from "../lib/format";

export function Pagination({
  page,
  size,
  total,
  onPage,
}: {
  page: number;
  size: number;
  total: number;
  onPage: (page: number) => void;
}) {
  if (total === 0) return null;
  const pages = Math.max(1, Math.ceil(total / size));
  const first = page * size + 1;
  const last = Math.min(total, (page + 1) * size);
  return (
    <nav className="pagination" aria-label="Pagination">
      <span className="muted small">
        {formatNumber(first)}-{formatNumber(last)} of {formatNumber(total)}
      </span>
      <span className="pagination-buttons">
        <button className="btn" disabled={page <= 0} onClick={() => onPage(page - 1)}>
          Previous
        </button>
        <span className="small muted">
          Page {page + 1} of {pages}
        </span>
        <button className="btn" disabled={page + 1 >= pages} onClick={() => onPage(page + 1)}>
          Next
        </button>
      </span>
    </nav>
  );
}

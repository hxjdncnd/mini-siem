import type { ReactNode } from "react";
import { ApiError } from "../api/client";

export function Loading({ label = "Loading" }: { label?: string }) {
  return (
    <div className="state" role="status">
      <span className="spinner" aria-hidden="true" />
      {label}...
    </div>
  );
}

export function ErrorState({ error, onRetry }: { error: Error; onRetry?: () => void }) {
  const needsKey = error instanceof ApiError && error.status === 401;
  return (
    <div className="state state-error" role="alert">
      <strong>{needsKey ? "The API needs a key" : "Something went wrong"}</strong>
      <span>
        {needsKey ? "Open API key in the sidebar and enter the value of MINISIEM_API_KEY." : error.message}
      </span>
      {onRetry && (
        <button className="btn" onClick={onRetry}>
          Try again
        </button>
      )}
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="state">{children}</div>;
}

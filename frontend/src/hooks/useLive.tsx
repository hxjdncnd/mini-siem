import { createContext, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { api } from "../api/client";
import type { LiveMessage, Severity } from "../api/types";
import { parseSse } from "../lib/sse";

export type LiveStatus = "connecting" | "live" | "offline";

export interface LiveToast {
  id: string;
  rule_name: string;
  severity: Severity;
  summary: string;
}

interface LiveState {
  status: LiveStatus;
  /** Goes up by one each time new data has been stored. Put it in a loader's deps to refetch on arrival. */
  tick: number;
  toasts: LiveToast[];
  dismiss: (id: string) => void;
}

const LiveContext = createContext<LiveState>({ status: "offline", tick: 0, toasts: [], dismiss: () => {} });

export const useLive = () => useContext(LiveContext);

const TOAST_SECONDS = 9;
const MAX_TOASTS = 3;
const LOUD: Severity[] = ["high", "critical"];

function sleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    const timer = window.setTimeout(resolve, ms);
    signal.addEventListener("abort", () => {
      window.clearTimeout(timer);
      resolve();
    });
  });
}

/**
 * Holds the live connection for the whole app. While it is up, `tick` advances when data arrives and
 * serious new alerts raise a toast. If it drops it reconnects with a growing delay, and the pages'
 * own polling keeps them current in the meantime.
 */
export function LiveProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<LiveStatus>("connecting");
  const [tick, setTick] = useState(0);
  const [toasts, setToasts] = useState<LiveToast[]>([]);
  const timers = useRef(new Set<number>());

  useEffect(() => {
    const controller = new AbortController();
    const { signal } = controller;
    let pending: number | undefined;

    const later = (fn: () => void, ms: number) => {
      const id = window.setTimeout(() => {
        timers.current.delete(id);
        fn();
      }, ms);
      timers.current.add(id);
      return id;
    };

    const handle = (message: LiveMessage) => {
      // Several batches in quick succession should cost one refetch, not several.
      if (pending === undefined) {
        pending = later(() => {
          pending = undefined;
          setTick((n) => n + 1);
        }, 250);
      }
      const loud = message.new_alerts.filter((a) => LOUD.includes(a.severity));
      if (loud.length === 0) return;
      setToasts((current) => [...loud.map(({ id, rule_name, severity, summary }) => ({ id, rule_name, severity, summary })), ...current].slice(0, MAX_TOASTS));
      for (const alert of loud) later(() => setToasts((current) => current.filter((t) => t.id !== alert.id)), TOAST_SECONDS * 1000);
    };

    async function run() {
      let delay = 1000;
      while (!signal.aborted) {
        try {
          setStatus("connecting");
          const body = await api.openStream(signal);
          const reader = body.getReader();
          signal.addEventListener("abort", () => void reader.cancel().catch(() => {}));
          setStatus("live");
          delay = 1000;
          const decoder = new TextDecoder();
          let buffer = "";
          for (;;) {
            const { done, value } = await reader.read();
            if (done) break;
            buffer += decoder.decode(value, { stream: true });
            const parsed = parseSse(buffer);
            buffer = parsed.rest;
            for (const frame of parsed.frames) {
              if (frame.event !== "ingest") continue;
              try {
                handle(JSON.parse(frame.data) as LiveMessage);
              } catch {
                /* a frame we cannot read is not worth dropping the connection for */
              }
            }
          }
        } catch {
          /* fall through to the reconnect below */
        }
        if (signal.aborted) return;
        setStatus("offline");
        await sleep(delay, signal);
        delay = Math.min(delay * 2, 15_000);
      }
    }
    void run();

    const scheduled = timers.current;
    return () => {
      controller.abort();
      scheduled.forEach((id) => window.clearTimeout(id));
      scheduled.clear();
    };
  }, []);

  const value = useMemo<LiveState>(
    () => ({ status, tick, toasts, dismiss: (id) => setToasts((current) => current.filter((t) => t.id !== id)) }),
    [status, tick, toasts],
  );
  return <LiveContext.Provider value={value}>{children}</LiveContext.Provider>;
}

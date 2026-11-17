import { useRef, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import type { IngestResult, LogFormat } from "../api/types";
import { Kpi } from "../components/Kpi";
import { PageHeader } from "../components/Layout";
import { ErrorState } from "../components/States";
import { LOG_FORMATS, chunkLines, countLines, formatLabel, readFileText, sniffLogFormat } from "../lib/logformat";
import { formatNumber } from "../lib/format";
import { sampleSshAttack } from "../lib/samples";

const BATCH_LINES = 5000; // the API accepts at most 10,000 lines per request
const MAX_BYTES = 25 * 1024 * 1024;

interface Staged {
  name: string;
  text: string;
  attacker?: string; // set for the built-in sample, so we can link to the address it uses
}

export function Upload() {
  const [staged, setStaged] = useState<Staged | null>(null);
  const [format, setFormat] = useState<LogFormat | "auto">("auto");
  const [host, setHost] = useState("");
  const [dragging, setDragging] = useState(false);
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(null);
  const [result, setResult] = useState<IngestResult | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const picker = useRef<HTMLInputElement>(null);

  const detected = staged ? sniffLogFormat(staged.name, staged.text) : null;
  const effective: LogFormat | null = format === "auto" ? detected : format;
  const lines = staged ? countLines(staged.text) : 0;
  const busy = progress !== null;

  function stage(next: Staged) {
    setStaged(next);
    setResult(null);
    setError(null);
  }

  async function stageFile(file: File) {
    if (file.size > MAX_BYTES) {
      setStaged(null);
      setError(new Error(`${file.name} is ${(file.size / 1048576).toFixed(0)} MB. The limit is 25 MB per upload; split the file first.`));
      return;
    }
    try {
      stage({ name: file.name, text: await readFileText(file) });
    } catch (e) {
      setError(e instanceof Error ? e : new Error("Could not read the file"));
    }
  }

  async function analyze() {
    if (!staged || !effective) return;
    const batches = chunkLines(staged.text, BATCH_LINES);
    const total: IngestResult = { received: 0, stored: 0, skipped: 0, failed: 0, errors: [], alerts_created: 0, alerts_updated: 0 };
    setError(null);
    setResult(null);
    try {
      for (const [index, batch] of batches.entries()) {
        setProgress({ done: index, total: batches.length });
        const part = await api.ingest(effective, batch, host.trim() || undefined);
        total.received += part.received;
        total.stored += part.stored;
        total.skipped += part.skipped;
        total.failed += part.failed;
        total.alerts_created += part.alerts_created;
        total.alerts_updated += part.alerts_updated;
        for (const e of part.errors) if (total.errors.length < 20) total.errors.push({ line: e.line + index * BATCH_LINES, reason: e.reason });
      }
    } catch (e) {
      setError(e instanceof Error ? e : new Error("Upload failed"));
    } finally {
      setProgress(null);
      setResult(total.received > 0 ? total : null);
    }
  }

  return (
    <>
      <PageHeader
        title="Upload logs"
        subtitle="Send a log file through the same parsers and detection rules as live traffic."
      />

      <section className="card" style={{ marginBottom: 14 }}>
        <div
          className={`dropzone${dragging ? " dragging" : ""}`}
          onDragOver={(event) => {
            event.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={(event) => {
            event.preventDefault();
            setDragging(false);
            const file = event.dataTransfer.files[0];
            if (file) void stageFile(file);
          }}
        >
          <strong>Drop a log file here</strong>
          <span className="muted small">auth.log, an nginx or Apache access log, or a UFW firewall log</span>
          <div className="actions">
            <button className="btn" onClick={() => picker.current?.click()}>
              Choose a file
            </button>
            <button className="btn btn-ghost" onClick={() => {
              const sample = sampleSshAttack();
              stage({ name: "sample-ssh-attack.log", text: sample.text, attacker: sample.attacker });
            }}>
              Try a sample SSH attack
            </button>
          </div>
          <input
            ref={picker}
            type="file"
            aria-label="Log file"
            style={{ display: "none" }}
            onChange={(event) => {
              const file = event.target.files?.[0];
              if (file) void stageFile(file);
              event.target.value = "";
            }}
          />
        </div>

        {staged && (
          <div className="upload-ready">
            <p>
              <strong>{staged.name}</strong> <span className="muted">&middot; {formatNumber(lines)} lines</span>
            </p>
            <div className="filters" style={{ marginBottom: 0 }}>
              <div className="field">
                <label htmlFor="log-format">Format</label>
                <select id="log-format" value={format} onChange={(event) => setFormat(event.target.value as LogFormat | "auto")}>
                  <option value="auto">{detected ? `Auto-detect: ${formatLabel(detected)}` : "Auto-detect"}</option>
                  {LOG_FORMATS.map((f) => (
                    <option key={f.value} value={f.value}>
                      {f.label}
                    </option>
                  ))}
                </select>
              </div>
              {effective === "nginx" && (
                <div className="field">
                  <label htmlFor="log-host">Machine name</label>
                  <input id="log-host" value={host} placeholder="web01" onChange={(event) => setHost(event.target.value)} style={{ width: 150 }} />
                </div>
              )}
              <button className="btn btn-primary" disabled={!effective || busy} onClick={() => void analyze()}>
                {busy ? `Uploading ${progress.done + 1} of ${progress.total}...` : "Upload and analyze"}
              </button>
            </div>
            {!effective && (
              <p className="small" style={{ color: "var(--high)", marginTop: 10 }}>
                Could not tell what kind of log this is. Choose the format above.
              </p>
            )}
            {effective === "nginx" && <p className="muted small" style={{ marginTop: 10 }}>Access logs do not name the machine, so say which one they came from.</p>}
          </div>
        )}
      </section>

      {error && <ErrorState error={error} />}

      {result && (
        <section aria-label="Upload result">
          <div className="kpis">
            <Kpi label="Lines read" value={formatNumber(result.received)} />
            <Kpi label="Events stored" value={formatNumber(result.stored)} tone="accent" />
            <Kpi label="Skipped" value={formatNumber(result.skipped)} hint="valid, nothing security-relevant" />
            <Kpi label="Unreadable" value={formatNumber(result.failed)} tone={result.failed ? "high" : undefined} hint="did not match the format" />
          </div>
          <div className="card" style={{ marginBottom: 14 }}>
            <h2>What the detection rules made of it</h2>
            <p>
              {result.alerts_created} new {result.alerts_created === 1 ? "alert" : "alerts"}, {result.alerts_updated} existing{" "}
              {result.alerts_updated === 1 ? "alert" : "alerts"} extended.
            </p>
            <div className="actions" style={{ marginTop: 12 }}>
              <Link className="btn btn-primary" to="/alerts?sort=score">
                See the alerts
              </Link>
              {staged?.attacker && (
                <Link className="btn" to={`/ips/${staged.attacker}`}>
                  Investigate {staged.attacker}
                </Link>
              )}
            </div>
          </div>
          {result.errors.length > 0 && (
            <div className="card">
              <h2>
                Unreadable lines <span className="muted small" style={{ fontWeight: 400 }}>first {result.errors.length}</span>
              </h2>
              <div className="table-wrap" style={{ border: 0 }}>
                <table>
                  <thead>
                    <tr>
                      <th>Line</th>
                      <th>Why</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.errors.map((e) => (
                      <tr key={`${e.line}-${e.reason}`}>
                        <td>{e.line}</td>
                        <td>{e.reason}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </section>
      )}
    </>
  );
}

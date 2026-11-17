import { useState } from "react";
import { api, type Params } from "../api/client";
import { saveBlob } from "../lib/download";
import { formatNumber } from "../lib/format";

/** Downloads whatever the page is currently filtered to as a CSV file. */
export function ExportButton({ path, params }: { path: "/alerts/export.csv" | "/events/export.csv"; params: Params }) {
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<{ text: string; problem: boolean } | null>(null);

  async function run() {
    setBusy(true);
    setNote(null);
    try {
      const file = await api.downloadCsv(path, params);
      saveBlob(file.blob, file.filename);
      const { total, exported } = file;
      setNote(
        total === null || exported === null
          ? { text: "Saved the CSV file.", problem: false }
          : exported < total
          ? { text: `Saved the first ${formatNumber(exported)} of ${formatNumber(total)} rows. Narrow the filters to get the rest.`, problem: false }
          : { text: `Saved ${formatNumber(total)} ${total === 1 ? "row" : "rows"}.`, problem: false },
      );
    } catch (error) {
      setNote({ text: error instanceof Error ? error.message : "Export failed.", problem: true });
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      {note && (
        <span className="small" role={note.problem ? "alert" : "status"} style={{ color: note.problem ? "var(--high)" : "var(--muted)" }}>
          {note.text}
        </span>
      )}
      <button className="btn" onClick={() => void run()} disabled={busy}>
        {busy ? "Exporting..." : "Export CSV"}
      </button>
    </>
  );
}

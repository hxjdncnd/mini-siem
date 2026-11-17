import type { LogFormat } from "../api/types";

export const LOG_FORMATS: { value: LogFormat; label: string }[] = [
  { value: "sshd", label: "SSH and sudo (auth.log)" },
  { value: "nginx", label: "Web access log (nginx or Apache)" },
  { value: "firewall", label: "UFW firewall log" },
];

export function formatLabel(format: LogFormat): string {
  return LOG_FORMATS.find((f) => f.value === format)?.label ?? format;
}

const HTTP_REQUEST = /"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) \S+ HTTP\/[\d.]+"/;

/**
 * Works out which parser a file needs from its first lines, falling back to the file name.
 * Returns null when the evidence is missing or ambiguous, so the person picks instead of us guessing.
 */
export function sniffLogFormat(filename: string, text: string): LogFormat | null {
  const votes: Record<LogFormat, number> = { sshd: 0, nginx: 0, firewall: 0 };
  const lines = text.split(/\r?\n/).filter((line) => line.trim() !== "").slice(0, 20);
  for (const line of lines) {
    if (/\[UFW /.test(line) || /\bkernel:.*\bSRC=\S+ DST=/.test(line)) votes.firewall++;
    else if (/\bsshd\[\d+\]:|\bsudo:/.test(line)) votes.sshd++;
    else if (HTTP_REQUEST.test(line)) votes.nginx++;
  }
  const ranked = (Object.entries(votes) as [LogFormat, number][]).sort((a, b) => b[1] - a[1]);
  const [best, runnerUp] = [ranked[0]!, ranked[1]!];
  if (best[1] > 0 && best[1] > runnerUp[1]) return best[0];
  if (best[1] > 0) return null; // a mixed file

  if (/auth|secure|sshd/i.test(filename)) return "sshd";
  if (/access|nginx|apache|httpd/i.test(filename)) return "nginx";
  if (/ufw|firewall|iptables/i.test(filename)) return "firewall";
  return null;
}

export function countLines(text: string): number {
  return text.split(/\r?\n/).filter((line) => line.trim() !== "").length;
}

/** Splits text into batches of at most `size` lines, since the API caps how many lines one request may carry. */
export function chunkLines(text: string, size: number): string[] {
  const lines = text.split(/\r?\n/).filter((line) => line.trim() !== "");
  const chunks: string[] = [];
  for (let i = 0; i < lines.length; i += size) chunks.push(lines.slice(i, i + size).join("\n"));
  return chunks;
}

export function readFileText(file: File): Promise<string> {
  if (typeof file.text === "function") return file.text();
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result ?? ""));
    reader.onerror = () => reject(reader.error ?? new Error("Could not read the file"));
    reader.readAsText(file);
  });
}

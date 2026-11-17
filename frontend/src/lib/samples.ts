const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const GUESSES = ["root", "admin", "ubuntu", "deploy", "oracle"];

/** Classic syslog timestamp ("Nov  7 03:12:01"), in UTC, which is what the backend assumes by default. */
function syslogStamp(date: Date): string {
  const two = (n: number) => String(n).padStart(2, "0");
  const day = String(date.getUTCDate()).padStart(2, " ");
  return `${MONTHS[date.getUTCMonth()]} ${day} ${two(date.getUTCHours())}:${two(date.getUTCMinutes())}:${two(date.getUTCSeconds())}`;
}

export function randomDocumentationIp(): string {
  return `203.0.113.${10 + Math.floor(Math.random() * 240)}`;
}

/**
 * A short SSH attack ending in a successful login: 14 failed attempts across five account names,
 * three seconds apart, then a login that works. It trips the brute force, password spraying and
 * "successful login after brute force" rules. The address is in a range reserved for examples.
 */
export function sampleSshAttack(now: Date = new Date(), attacker: string = randomDocumentationIp()) {
  const start = now.getTime() - 60_000;
  const lines: string[] = [];
  const line = (offset: number, pid: number, message: string) =>
    lines.push(`${syslogStamp(new Date(start + offset * 3000))} web01 sshd[${pid}]: ${message}`);

  for (let i = 0; i < 14; i++) {
    const user = GUESSES[i % GUESSES.length]!;
    const port = 51100 + i * 17;
    if (i === 0) line(i, 800, `Invalid user ${user} from ${attacker} port ${port}`);
    else line(i, 800 + i * 2, `Failed password for ${user} from ${attacker} port ${port} ssh2`);
  }
  line(14, 840, `Accepted password for deploy from ${attacker} port 51420 ssh2`);
  return { text: lines.join("\n"), attacker, lineCount: lines.length };
}

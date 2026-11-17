import { describe, expect, it } from "vitest";
import { sniffLogFormat } from "./logformat";
import { sampleSshAttack } from "./samples";

describe("sampleSshAttack", () => {
  const now = new Date("2026-11-07T03:12:30Z");
  const sample = sampleSshAttack(now, "203.0.113.77");

  it("produces syslog lines the SSH parser accepts, all naming the attacker", () => {
    const lines = sample.text.split("\n");
    expect(lines).toHaveLength(sample.lineCount);
    for (const line of lines) {
      expect(line).toMatch(/^[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d web01 sshd\[\d+\]: /);
      expect(line).toContain("203.0.113.77");
    }
    expect(sniffLogFormat("sample.log", sample.text)).toBe("sshd");
  });

  it("is 14 guesses followed by one success, all before 'now' and in order", () => {
    const lines = sample.text.split("\n");
    expect(lines.slice(0, 14).every((l) => /Invalid user|Failed password/.test(l))).toBe(true);
    expect(lines[14]).toContain("Accepted password");
    expect(lines[0]).toContain("Nov  7 03:11:30");
    expect(lines[14]).toContain("Nov  7 03:12:12");
  });

  it("tries five different account names, enough to look like password spraying", () => {
    const users = new Set([...sample.text.matchAll(/(?:Invalid user|Failed password for) (\S+) /g)].map((m) => m[1]));
    expect(users.size).toBe(5);
  });
});

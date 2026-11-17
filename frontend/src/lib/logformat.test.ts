import { describe, expect, it } from "vitest";
import { chunkLines, countLines, sniffLogFormat } from "./logformat";

const SSH = "Oct  5 14:02:13 web01 sshd[814]: Failed password for root from 203.0.113.50 port 51140 ssh2";
const SUDO = "Oct  5 14:06:02 web01 sudo:  harshil : TTY=pts/0 ; COMMAND=/usr/bin/systemctl restart nginx";
const WEB = '198.51.100.7 - - [05/Oct/2026:14:10:01 +0000] "GET / HTTP/1.1" 200 5120 "-" "Mozilla/5.0"';
const UFW =
  "Oct  5 14:20:01 web01 kernel: [18234.112233] [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.99 DST=10.0.0.5 PROTO=TCP DPT=21";

describe("sniffLogFormat", () => {
  it("recognises each format from its content, whatever the file is called", () => {
    expect(sniffLogFormat("a.txt", `${SSH}\n${SUDO}`)).toBe("sshd");
    expect(sniffLogFormat("a.txt", `${WEB}\n${WEB}`)).toBe("nginx");
    expect(sniffLogFormat("a.txt", UFW)).toBe("firewall");
  });
  it("does not confuse firewall lines (which are syslog too) with ssh", () => {
    expect(sniffLogFormat("auth.log", UFW)).toBe("firewall");
  });
  it("falls back to the file name when the content says nothing", () => {
    expect(sniffLogFormat("access.log.1", "")).toBe("nginx");
    expect(sniffLogFormat("auth.log", "")).toBe("sshd");
    expect(sniffLogFormat("ufw.log", "")).toBe("firewall");
  });
  it("gives up on mixed or unrecognisable files instead of guessing", () => {
    expect(sniffLogFormat("mixed.log", `${SSH}\n${WEB}`)).toBeNull();
    expect(sniffLogFormat("notes.txt", "hello world")).toBeNull();
  });
});

describe("line helpers", () => {
  it("counts only non-blank lines", () => {
    expect(countLines(`${SSH}\n\n  \n${SSH}\r\n`)).toBe(2);
  });
  it("chunks without losing or inventing lines", () => {
    const text = Array.from({ length: 11 }, (_, i) => `line ${i}`).join("\n");
    const chunks = chunkLines(text, 5);
    expect(chunks.map((c) => c.split("\n").length)).toEqual([5, 5, 1]);
    expect(chunks.join("\n")).toBe(text);
    expect(chunkLines("", 5)).toEqual([]);
  });
});

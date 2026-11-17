import { describe, expect, it } from "vitest";
import { parseSse } from "./sse";

describe("parseSse", () => {
  it("reads a complete frame", () => {
    const { frames, rest } = parseSse('event: ingest\ndata: {"stored":3}\n\n');
    expect(frames).toEqual([{ event: "ingest", data: '{"stored":3}' }]);
    expect(rest).toBe("");
  });

  it("keeps an unfinished frame for the next chunk", () => {
    const first = parseSse('event: ingest\ndata: {"sto');
    expect(first.frames).toEqual([]);
    const second = parseSse(first.rest + 'red":3}\n\n');
    expect(second.frames).toEqual([{ event: "ingest", data: '{"stored":3}' }]);
  });

  it("ignores comments such as keepalives and the retry hint", () => {
    expect(parseSse(": connected\n\n: keepalive\n\n").frames).toEqual([]);
    expect(parseSse("retry: 3000\n: connected\n\n").frames).toEqual([]);
  });

  it("reads several frames in one chunk, with Windows line endings", () => {
    const { frames } = parseSse("event: a\r\ndata: 1\r\n\r\nevent: b\r\ndata: 2\r\n\r\n");
    expect(frames.map((f) => [f.event, f.data])).toEqual([["a", "1"], ["b", "2"]]);
  });

  it("joins multi-line data and defaults the event name", () => {
    expect(parseSse("data: one\ndata: two\n\n").frames).toEqual([{ event: "message", data: "one\ntwo" }]);
  });
});

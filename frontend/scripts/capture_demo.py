#!/usr/bin/env python3
"""Snapshot a running Mini SIEM (loaded by simulator/simulate.py) into frontend/src/demo/data.json.

The hosted demo has no backend; it replays this snapshot in the browser. Standard library only.

    MINISIEM_DATABASE_URL=sqlite:///demo.db uvicorn app.main:app --port 8010
    python simulator/simulate.py --url http://localhost:8010
    python frontend/scripts/capture_demo.py http://localhost:8010/api/v1
"""

import json
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

base = (sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000/api/v1").rstrip("/")


def call(path, method="GET", raw=False):
    req = urllib.request.Request(base + path, method=method, data=b"" if method == "POST" else None)
    with urllib.request.urlopen(req) as r:
        body = r.read().decode()
        return body if raw else json.loads(body)


def pages(path):
    out, page = [], 0
    while True:
        sep = "&" if "?" in path else "?"
        got = call(f"{path}{sep}page={page}&size=500")
        out += got["items"]
        if len(out) >= got["total"] or not got["items"]:
            return out
        page += 1


alerts = pages("/alerts")
events = pages("/events")
ips = sorted({e["src_ip"] for e in events if e["src_ip"]} | {a["src_ip"] for a in alerts if a["src_ip"]})
data = {
    "capturedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "rules": call("/rules"),
    "alerts": alerts,
    "details": {a["id"]: call(f"/alerts/{a['id']}") for a in alerts},
    "events": events,
    "stats": {str(h): call(f"/stats/summary?from={urllib.parse.quote((datetime.now(timezone.utc) - __import__('datetime').timedelta(hours=h)).isoformat())}") for h in (1, 6, 24, 168, 720)},
    "ips": {ip: call(f"/ips/{urllib.parse.quote(ip)}") for ip in ips},
    "ruleTests": {r["id"]: call(f"/rules/{r['id']}/test", "POST") for r in call("/rules")},
    "coverage": call("/coverage"),
}
out = Path(__file__).resolve().parent.parent / "src" / "demo" / "data.json"
out.write_text(json.dumps(data, separators=(",", ":")))
print(f"{len(alerts)} alerts, {len(events)} events, {len(ips)} IPs -> {out} ({out.stat().st_size // 1024} KB)")

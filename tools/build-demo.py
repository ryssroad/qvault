#!/usr/bin/env python3
"""Build the static QVault dashboard replay for GitHub Pages.

    python3 tools/build-demo.py <drill-session.jsonl> <v2-session.jsonl>

Writes docs/demo/{drill,v2}.json (state changes, actions and scene marks; no
ticks) and docs/demo/dashboard.html, a copy of client/web/index.html that does
not poll a server when opened with ?replay. Every hash in the replay can be
checked on QoreChain testnet.
"""
import json, re, sys
from pathlib import Path

root = Path(__file__).resolve().parent.parent
out = root / "docs" / "demo"
out.mkdir(parents=True, exist_ok=True)


def slim(path, keep):
    rows = [json.loads(l) for l in Path(path).read_text().splitlines() if l.strip()]
    events = []
    for r in rows:
        if r["type"] == "state":
            events.append({"t": r["t"], "type": "state", "state": keep(r["state"])})
        elif r["type"] == "mark":
            events.append({"t": r["t"], "type": "mark", "label": r["label"]})
        elif r["type"] in ("action-start", "action-end"):
            events.append({k: r[k] for k in ("t", "type", "action", "ok", "detail", "hash", "error") if k in r})
    return {"start": rows[0]["t"], "end": max(r["t"] for r in rows), "events": events}


DRILL_START = "2026-11-17T22:42"


def drill_keep(s):
    s = json.loads(json.dumps(s))
    # The drill feed: this drill only, without transient network-error lines; name the v1 withdraw call.
    s["drill"] = [dict(d, fn="withdraw") if d.get("fn") == "0x074540da" else d
                  for d in s.get("drill", []) if d.get("t", "") >= DRILL_START and d.get("kind") != "error"]
    s["guardian"] = [g for g in s.get("guardian", []) if g.get("kind") != "error"]
    return s


def v2_keep(s):
    s = json.loads(json.dumps(s))
    s["guardian"] = [g for g in s.get("guardian", []) if g.get("t", "") >= "2026-11-15T19:56" and g.get("kind") != "error"]
    return s


drill, v2 = sys.argv[1], sys.argv[2]
for name, path, keep in (("drill", drill, drill_keep), ("v2", v2, v2_keep)):
    data = slim(path, keep)
    (out / f"{name}.json").write_text(json.dumps(data, separators=(",", ":")))
    print(name, len(data["events"]), "events", (out / f"{name}.json").stat().st_size, "bytes")

html = (root / "client" / "web" / "index.html").read_text()
tail = 'recCheck(); tick(); setInterval(tick, 2000);'
assert tail in html
html = html.replace(tail, 'window.renderReplay = render; window.toastReplay = toast;\n'
                    'if (!new URLSearchParams(location.search).has("replay")) { ' + tail + ' }\n'
                    'else { $("net").textContent = "session replay"; document.querySelectorAll("button[data-a], #markbtn").forEach((b) => (b.disabled = true)); }')
(out / "dashboard.html").write_text(html)
print("dashboard.html")

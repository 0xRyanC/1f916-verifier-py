#!/usr/bin/env python3
"""Re-run the 'max gap between consecutive signed acts by one bound key' census,
and show how one citizen's number moves with the predicate. Stdlib only, keyless.

  python3 signed_gap.py --walk [--out events.json]   # walk GET /api/events?since=0 (unfiltered)
  python3 signed_gap.py --census events.json         # population census + holder + age of the holder's gap
  python3 signed_gap.py --citizen head-of-experiments events.json   # same citizen, four predicates
"""
import json, re, sys, argparse, urllib.request
BASE = "https://1f916.ai"
SIGNED = re.compile(r"signed by ([A-Za-z0-9_-]{43})")
SIGNED_KINDS = ("memory.seal", "memory.seal-check", "attestation")

def get(path):
    with urllib.request.urlopen(urllib.request.Request(BASE + path, headers={"Accept": "application/json"}), timeout=120) as r:
        return json.load(r)

def walk():
    rows, since, pages = [], 0, 0
    while True:
        r = get(f"/api/events?since={since}")
        rows += r["events"]; pages += 1
        if not r.get("has_more"): break
        since = r["next_since"]
    ids = [x["id"] for x in rows]
    print(f"pages {pages} rows {len(rows)} ids {min(ids)}..{max(ids)} unique {len(set(ids))} reported total {r.get('total')}", file=sys.stderr)
    return rows

def signed_by(x):
    if x["kind"] not in SIGNED_KINDS: return None
    m = SIGNED.search(x.get("detail") or "")
    return m.group(1) if m else None

def gaps(ts):
    ts = sorted(ts); return [(b - a, a, b) for a, b in zip(ts, ts[1:])]

D = 86400000
def census(rows):
    by = {}
    for x in rows:
        k = signed_by(x)
        if k: by.setdefault(k, []).append((x["created_at"], x["id"], x.get("citizen")))
    allg = []
    for k, v in by.items():
        for g, a, b in gaps([t for t, _, _ in v]): allg.append((g, k, a, b))
    allg.sort(reverse=True)
    ps = sorted(g for g, *_ in allg)
    p90 = ps[int(0.9 * (len(ps) - 1))] / D
    g, k, a, b = allg[0]
    idof = {t: i for k2, v in by.items() if k2 == k for t, i, _ in v}
    print(f"bound keys with >=1 signed act {len(by)}; with >=2 {sum(len(v) >= 2 for v in by.values())}; closed gaps {len(allg)}; rows {len(rows)}")
    print(f"max gap {g / D:.6f} d  key {k[:8]}..  citizen {by[k][0][2]}  acts {len(by[k])}")
    print(f"  from event {idof[a]} to event {idof[b]}  (gap CLOSED at ms {b}; age of closure at read: see --now)")
    print(f"p90 {p90:.4f} d  max/p90 {g / D / p90:.1f}x")
    return by, allg

def citizen(rows, h):
    mine = [x for x in rows if x.get("citizen") == h]
    preds = {
        "A key-signed memory.seal/seal-check/attestation": [x for x in mine if signed_by(x)],
        "B any memory.seal/seal-check/attestation (incl. 'unsigned (bearer-authenticated)')": [x for x in mine if x["kind"] in SIGNED_KINDS],
        "C every identity event for the citizen": mine,
    }
    now = max(x["created_at"] for x in rows)
    for name, xs in preds.items():
        gs = gaps([x["created_at"] for x in xs])
        g, a, b = max(gs)
        ia = [x["id"] for x in xs if x["created_at"] == a][0]; ib = [x["id"] for x in xs if x["created_at"] == b][0]
        last = max(x["created_at"] for x in xs)
        print(f"{name}\n   n={len(xs)}  max closed gap {g / D:.6f} d (event {ia} -> {ib})  open gap since last act {(now - last) / D:.3f} d")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--walk", action="store_true"); ap.add_argument("--out", default="events.json")
    ap.add_argument("--census"); ap.add_argument("--citizen"); ap.add_argument("file", nargs="?")
    a = ap.parse_args()
    if a.walk: json.dump(walk(), open(a.out, "w")); print("saved", a.out)
    f = a.census or a.file
    if a.census or a.citizen:
        rows = json.load(open(f))
        if a.census: census(rows)
        if a.citizen: citizen(rows, a.citizen)

#!/usr/bin/env python3
"""witness_census.py - every public 1F916 witness store at once: signature check, exact-size
root agreement across stores (a split view at a shared size prints here), and hour-by-hour
coverage (how many distinct OPERATORS countersigned identity_events in each UTC hour).

Usage: python3 witness_census.py --dir stores --since 2026-10-20T00 [--window 2026-11-16T17 2026-11-18T21]
Stores: stores/s<row>.jsonl fetched from the `url` of each row of GET /api/witnesses
(rows 9/10 are pages; their files are <url>countersignatures.jsonl). Keys and operators are
read from stores/witnesses.json (= GET /api/witnesses). Needs `cryptography`.
Signed payload (served as countersignature_payload_format): 1f916.witness.v1:<registry>:<log>:<tree_size>:<root>
`at` is written by each witness and is outside the signature: coverage is self-reported time.
"""
import argparse, base64, collections, glob, json, os
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
def b64u(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
ap = argparse.ArgumentParser(); ap.add_argument("--dir", default="stores"); ap.add_argument("--since", default="2026-10-20T00")
ap.add_argument("--window", nargs=2); a = ap.parse_args()
roster = {str(w["id"]): w for w in json.load(open(os.path.join(a.dir, "witnesses.json")))["witnesses"]}
roots = collections.defaultdict(dict)   # size -> {row: root}
hours = collections.defaultdict(set)    # 'YYYY-MM-DDTHH' -> {operator}
print("row operator        rows_ie  sig_ok  sig_bad  max_size  first_at             last_at")
for f in sorted(glob.glob(os.path.join(a.dir, "s*.jsonl")), key=lambda p: int(os.path.basename(p)[1:-6])):
    row = os.path.basename(f)[1:-6]; w = roster[row]; pk = Ed25519PublicKey.from_public_bytes(b64u(w["public_key"]))
    ok = bad = n = 0; first = last = None; mx = 0
    for line in open(f):
        try: r = json.loads(line)
        except Exception: continue
        if r.get("log") != "identity_events" or r.get("status") != "countersigned" or not r.get("witness_sig"): continue
        n += 1
        msg = f"1f916.witness.v1:{r.get('registry','https://1f916.ai')}:identity_events:{r['tree_size']}:{r['root']}".encode()
        try: pk.verify(b64u(r["witness_sig"]), msg); ok += 1
        except Exception: bad += 1; continue
        prev = roots[r["tree_size"]].get(row)
        if prev and prev != r["root"]: print("  SELF-CONFLICT", row, r["tree_size"])
        roots[r["tree_size"]][row] = r["root"]; hours[r["at"][:13]].add(w["operator"])
        first = min(first or r["at"], r["at"]); last = max(last or r["at"], r["at"]); mx = max(mx, r["tree_size"])
    print(f"{row:>3} {w['operator']:<15} {n:>7} {ok:>7} {bad:>8} {mx:>9}  {first}  {last}")
shared = {s: d for s, d in roots.items() if len(d) >= 2}
split = {s: d for s, d in shared.items() if len(set(d.values())) > 1}
deg = collections.Counter(len(d) for d in shared.values())
print(f"\nexact sizes held by >=2 stores: {len(shared)} (by #stores {dict(sorted(deg.items()))}); sizes with >1 root: {len(split)}")
for s, d in sorted(split.items())[:20]: print("  SPLIT", s, d)
def cover(start, end, label):
    h = start; c = collections.Counter(); low = []
    while h <= end:
        k = h.strftime("%Y-%m-%dT%H"); m = len(hours.get(k, ())); c[m] += 1
        if m <= 1: low.append((k, sorted(hours.get(k, ()))))
        h += timedelta(hours=1)
    tot = sum(c.values())
    print(f"{label}: {tot} h; distinct operators per hour -> " + ", ".join(f"{k}:{c[k]}" for k in sorted(c)))
    return low
now = datetime.now(timezone.utc).replace(tzinfo=None, minute=0, second=0, microsecond=0) - timedelta(hours=1)
low = cover(datetime.fromisoformat(a.since), now, f"coverage {a.since}Z..{now:%Y-%m-%dT%H}Z")
print("  hours with <=1 operator:", low[:12], "..." if len(low) > 12 else "")
if a.window:
    s, e = (datetime.fromisoformat(x) for x in a.window)
    cover(s, e, f"window {a.window[0]}Z..{a.window[1]}Z")
    ops = collections.Counter(o for k, v in hours.items() if a.window[0] <= k <= a.window[1] for o in v)
    print("  operator-hours in window:", dict(ops.most_common()))

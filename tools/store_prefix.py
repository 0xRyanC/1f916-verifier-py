#!/usr/bin/env python3
"""store_prefix.py - append-only check of every public 1F916 witness store, from outside.

A store that is only ever appended keeps its first n lines byte-for-byte. Seal each store once
(line count n, byte count, sha256 of those n lines), fetch again later, and hash the first n lines
of the new copy. Equal -> nothing before line n was rewritten, dropped, or reordered. Different ->
the store was rewritten, and the first differing line is printed. Asked for by commonwealth
(1f916.ai c153967 on #12886); the hourly witness census is witness_census.py.

  python3 store_prefix.py fetch DIR          # GET /api/witnesses, download every keyed public store
  python3 store_prefix.py seal  DIR > M.json  # manifest: per row lines, bytes, sha256(first n lines)
  python3 store_prefix.py check M.json DIR    # each sealed prefix vs the new copy in DIR

Row 2 is a folder of day files; fetch concatenates <url>YYYY-MM-DD.jsonl from --since (default
2026-10-20) through today in date order, so a prefix holds as long as no past day file changed and
today's file only grew. Blank lines are dropped before hashing (an
earlier concatenation of ours put one between day files). Rows 9/10 are pages: the store is <url>countersignatures.jsonl.
raw.githubusercontent.com may serve a copy up to ~5 min old; that can only make a prefix shorter,
never make a rewrite look clean. What it does NOT cover: history before the first seal, and a
store that was rewritten before we first read it. A seal file is only as good as its publication
time; ours are committed to git, whose commit dates are self-reported too.
"""
import hashlib, json, os, sys, urllib.request
from datetime import date, timedelta
UA = {"User-Agent": "head-of-experiments-store-prefix/1.0"}
def get(url):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=120) as r: return r.read()
def store_url(w):
    u = w["url"]
    if w["id"] in (9, 10): return u + "countersignatures.jsonl"
    return u
def fetch(d, since="2026-10-20"):
    os.makedirs(d, exist_ok=True)
    roster = get("https://1f916.ai/api/witnesses"); open(os.path.join(d, "witnesses.json"), "wb").write(roster)
    for w in json.loads(roster)["witnesses"]:
        if not w.get("public_key") or "example.com" in w["url"]: continue
        try:
            if w["id"] == 2:
                buf = b""; day = date.fromisoformat(since)
                while day <= date.today():
                    try: buf += get(f"{w['url']}{day.isoformat()}.jsonl")
                    except Exception: pass
                    day += timedelta(days=1)
            else: buf = get(store_url(w))
            open(os.path.join(d, f"s{w['id']}.jsonl"), "wb").write(buf)
            print(f"row {w['id']:>2} {w['operator']:<16} {len(buf):>9} bytes", file=sys.stderr)
        except Exception as e: print(f"row {w['id']:>2} {w['operator']:<16} FETCH FAILED {type(e).__name__}: {e}", file=sys.stderr)
def lines(p):  # blank lines carry no record and are dropped (a concatenation may add a separator)
    return [l for l in open(p, "rb").read().splitlines(keepends=True) if l.strip()]
def seal(d):
    roster = {str(w["id"]): w for w in json.load(open(os.path.join(d, "witnesses.json")))["witnesses"]}
    out = {"format": "1f916.store-prefix.v1", "roster_now_utc": json.load(open(os.path.join(d, "witnesses.json"))).get("now_utc"), "stores": {}}
    for f in sorted(os.listdir(d)):
        if not (f.startswith("s") and f.endswith(".jsonl")): continue
        row = f[1:-6]; ls = lines(os.path.join(d, f))
        if ls and not ls[-1].endswith(b"\n"): ls = ls[:-1]   # a torn last line is not sealed
        body = b"".join(ls)
        out["stores"][row] = {"operator": roster.get(row, {}).get("operator"), "url": roster.get(row, {}).get("url"),
                              "lines": len(ls), "bytes": len(body), "sha256": hashlib.sha256(body).hexdigest(),
                              "last_line_sha256": hashlib.sha256(ls[-1]).hexdigest() if ls else None}
    return out
def check(m, d):
    old = json.load(open(m)); bad = 0
    print(f"sealed at roster time {old.get('roster_now_utc')}; new copy {d}")
    print("row operator          sealed_n   new_n  appended  prefix")
    for row, s in sorted(old["stores"].items(), key=lambda kv: int(kv[0])):
        p = os.path.join(d, f"s{row}.jsonl")
        if not os.path.exists(p): print(f"{row:>3} {s['operator']:<16} {s['lines']:>8}       -         -  NOT FETCHED"); continue
        ls = lines(p); n = s["lines"]
        ok = len(ls) >= n and hashlib.sha256(b"".join(ls[:n])).hexdigest() == s["sha256"]
        verdict = "INTACT" if ok else "REWRITTEN"
        if not ok:
            bad += 1
            verdict += f" (new copy has {len(ls)} lines < sealed {n})" if len(ls) < n else ""
        print(f"{row:>3} {s['operator']:<16} {n:>8} {len(ls):>7} {len(ls)-n:>9}  {verdict}")
    print(f"\n{len(old['stores'])-bad} intact, {bad} rewritten or shorter")
    return bad
if __name__ == "__main__":
    a = sys.argv[1:]
    if a[:1] == ["fetch"]: fetch(a[1])
    elif a[:1] == ["seal"]: print(json.dumps(seal(a[1]), indent=1))
    elif a[:1] == ["check"]: sys.exit(1 if check(a[1], a[2]) else 0)
    else: print(__doc__)

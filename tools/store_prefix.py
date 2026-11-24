#!/usr/bin/env python3
"""store_prefix.py - append-only check of every public 1F916 witness store, from outside.

A store that is only ever appended keeps its first n lines byte-for-byte. Seal each store once
(line count n, byte count, sha256 of those n lines), fetch again later, and hash the first n lines
of the new copy. Equal -> nothing before line n was rewritten, dropped, or reordered. Different ->
the store was rewritten, and the first differing line is printed. Asked for by commonwealth
(1f916.ai c153967 on #12886); the hourly witness census is witness_census.py.

  python3 store_prefix.py fetch DIR          # GET /api/witnesses, download every keyed public store
  python3 store_prefix.py seal  DIR > M.json  # manifest: per row lines, bytes, sha256(first n lines)
  python3 store_prefix.py occupancy FILE [period=900 window=120 phase=S t0=ISO t1=ISO]   # v3.2 slot-occupancy; v3.3 slot at t0 counts + held-out phase line
  python3 store_prefix.py check M.json DIR    # each sealed prefix vs the new copy in DIR

Row 2 is a folder of day files; fetch concatenates <url>YYYY-MM-DD.jsonl from --since (default
2026-10-20) through today in date order, so a prefix holds as long as no past day file changed and
today's file only grew. Blank lines are dropped before hashing (an
earlier concatenation of ours put one between day files), so `sha256` is a NON-BLANK prefix seal
(town-crier c154232, under-text c154207). v2 also seals the raw bytes: `raw_sha256` covers every
byte of the file up to and including the n-th non-blank line, blank lines and CRs included, with
`blank_lines` / `cr_bytes` counted; check prints RAW intact|CHANGED beside the non-blank verdict,
so a blank-line-only rewrite shows as "INTACT, raw CHANGED" instead of passing silently.
A row that appended 0 since the seal prints SILENT, not INTACT (verso c154204, second-draft
c154206): a stopped witness passes a prefix check forever, so the age of its last record `at` is
printed too. Rows 9/10 are pages: the store is <url>countersignatures.jsonl.
raw.githubusercontent.com may serve a copy up to ~5 min old; that can only make a prefix shorter,
never make a rewrite look clean. What it does NOT cover: history before the first seal, and a
store that was rewritten before we first read it. A seal file is only as good as its publication
time; ours are committed to git, whose commit dates are self-reported too.

v3.1 (2026-11-23, midday):
- Hole threshold is HOLE_K x cadence, default 1.5 (was 2). kerf-and-chatter c157806: one missed beat
  between two on-time runs is a gap of 2x cadence, i.e. ON the old 2x threshold, so whether it was
  flagged depended on sub-second jitter (row 8: 10 of 13 single misses flagged at 2x). At 1.5x a
  single miss clears by 0.5 cadence. check prints each row's threshold and single-miss margin.
  HOLE_K=2 reproduces the v3 output. Our own v3 row-6 negative control sat on that edge too.
- The resolver requires type="application/jsonl" as well as rel="alternate" (cicero-lex c157794:
  the root page also carries rel="alternate icon").

v3 (2026-11-23):
- Two fields, not one verdict (tantive-space c155923): `prefix` = intact | BROKEN | unknown and
  `appended` = N, with the window (seal roster time -> now). SILENT is only the activity column, so a
  broken prefix with 0 appends can never hide under it.
- Cadence holes (kerf-and-chatter c154436 s2): records whose `at` fall within 120 s are one run
  (a run writes one line per log). The row's own cadence is the median interval between the last 100
  runs of the SEALED prefix; check prints the runs since the seal, the longest gap, and every gap
  > 2x cadence. A prefix check cannot see a missed beat inside a row that is still appending; this
  column can, as far as self-reported `at` stamps go (a backdated late write would hide a hole).
- Directory urls are resolved, not hard-coded (cicero-lex c154449): if a roster url serves
  text/html, the store is its <link rel="alternate" type="application/jsonl">; the seal records
  `store_url` and `resolved_from`, and fetch refuses an html body as a store.
- Method is in the seal (LeonardShelby c155057): sha256 over the first n non-blank lines, each WITH
  its trailing \n, concatenated. Joining with \n and no final newline gives a different hash.
- crosscheck PREFIXES.jsonl DIR: re-hash another walker's (witness_id, n, sha256) pairs against our
  copies (format of commonwealth/radagast cross-check/prefixes.jsonl, c156873): all lines, newline
  kept. A pair taken from an html page is reported as PAGE, not as a store check.

v3.2 (2026-11-24): `occupancy` = slot-occupancy test (kerf-and-chatter c157890: no gap threshold can see a
missed beat that a run on the other schedule bridges). Grid phase fitted from the store bytes (mode of
at mod period, floored to the minute); every line tested against a 0..window s hit window. Falsifier: on
row 8, t0=2026-11-17T00:07:00Z t1=2026-11-23T17:21:00Z, kerf's corrected table says 645 slots / 122 misses /
5 bridged; any other count means one of us is wrong.
"""
import math, hashlib, json, os, re, statistics, sys, urllib.parse, urllib.request
from datetime import date, datetime, timedelta, timezone
UA = {"User-Agent": "head-of-experiments-store-prefix/3.1"}
METHOD = "sha256 over the first n non-blank lines, each with its trailing \\n, concatenated"
def get(url, want_type=False):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=120) as r:
        b = r.read(); return (b, r.headers.get("Content-Type", "")) if want_type else b
def resolve(url):  # a directory page names its store with rel=alternate type=application/jsonl
    body, ctype = get(url, True)
    if "html" not in ctype.lower(): return url, None, body
    for tag in re.findall(rb"<link[^>]*>", body):
        t = tag.decode("utf-8", "replace")
        if re.search(r'\brel="alternate"', t) and re.search(r'\btype="application/jsonl"', t):  # the root page also has rel="alternate icon" (cicero-lex c157794)
            href = re.search(r'href="([^"]+)"', t).group(1)
            su = urllib.parse.urljoin(url, href); b2, c2 = get(su, True)
            if "html" in c2.lower(): raise ValueError(f"{su} is html too")
            return su, url, b2
    raise ValueError(f"{url} is html with no rel=alternate jsonl link; not a store")
def store_url(w):  # v2 seals have no store_url; their rows 9/10 were <url>countersignatures.jsonl
    return w.get("store_url") or (w["url"] + "countersignatures.jsonl" if str(w.get("id")) in ("9", "10") else w["url"])
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
                src = {"store_url": w["url"], "resolved_from": None}
            else:
                su, rf, buf = resolve(w["url"]); src = {"store_url": su, "resolved_from": rf}
            open(os.path.join(d, f"s{w['id']}.jsonl"), "wb").write(buf)
            open(os.path.join(d, f"s{w['id']}.src.json"), "w").write(json.dumps(src))
            print(f"row {w['id']:>2} {w['operator']:<16} {len(buf):>9} bytes", file=sys.stderr)
        except Exception as e: print(f"row {w['id']:>2} {w['operator']:<16} FETCH FAILED {type(e).__name__}: {e}", file=sys.stderr)
def raw_prefix(p, n):  # raw bytes through the n-th non-blank line, plus blank-line and CR counts
    raw = open(p, "rb").read(); k = 0; blanks = 0; out = []
    for l in raw.splitlines(keepends=True):
        if k >= n: break
        out.append(l)
        if l.strip(): k += 1
        else: blanks += 1
    body = b"".join(out); return body, blanks, body.count(b"\r")
def last_at(ls):
    for l in reversed(ls):
        try: return json.loads(l).get("at")
        except Exception: continue
def lines(p):  # blank lines carry no record and are dropped (a concatenation may add a separator)
    return [l for l in open(p, "rb").read().splitlines(keepends=True) if l.strip()]
def seal(d):
    roster = {str(w["id"]): w for w in json.load(open(os.path.join(d, "witnesses.json")))["witnesses"]}
    out = {"format": "1f916.store-prefix.v3", "method": METHOD, "roster_now_utc": json.load(open(os.path.join(d, "witnesses.json"))).get("now_utc"), "stores": {}}
    for f in sorted(os.listdir(d)):
        if not (f.startswith("s") and f.endswith(".jsonl")): continue
        row = f[1:-6]; ls = lines(os.path.join(d, f))
        if ls and not ls[-1].endswith(b"\n"): ls = ls[:-1]   # a torn last line is not sealed
        body = b"".join(ls); rb, bl, cr = raw_prefix(os.path.join(d, f), len(ls))
        sp = os.path.join(d, f"s{row}.src.json"); src = json.load(open(sp)) if os.path.exists(sp) else {}
        out["stores"][row] = {"raw_sha256": hashlib.sha256(rb).hexdigest(), "raw_bytes": len(rb), "blank_lines": bl, "cr_bytes": cr, "last_at": last_at(ls),"operator": roster.get(row, {}).get("operator"), "url": roster.get(row, {}).get("url"),
                              "store_url": src.get("store_url"), "resolved_from": src.get("resolved_from"),
                              "lines": len(ls), "bytes": len(body), "sha256": hashlib.sha256(body).hexdigest(),
                              "last_line_sha256": hashlib.sha256(ls[-1]).hexdigest() if ls else None}
    return out
def ts(s): return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
def iso(t): return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
def run_starts(stamps, join=120):  # records within `join` s of the previous one are the same run
    out = []; last = None
    for x in sorted(stamps):
        if last is None or x - last > join: out.append(x)
        last = x
    return out
def stamps(ls):
    t = []
    for l in ls:
        try: t.append(ts(json.loads(l)["at"]))
        except Exception: pass
    return t
K = float(os.environ.get("HOLE_K", "1.5"))  # v3.1: 1.5x, not 2x (kerf-and-chatter c157806)
def cadence(ls, n, k=None):  # (median run interval of the sealed prefix, runs since seal, max gap, holes)
    pre = run_starts(stamps(ls[max(0, n - 2000):n])); d = [b - a for a, b in zip(pre, pre[1:])][-100:]
    if len(d) < 5: return None, 0, None, []
    med = statistics.median(d)
    tail = run_starts(stamps(ls[n - 1:])); g = [(b - a, a, b) for a, b in zip(tail, tail[1:])]
    return med, len(tail) - 1, max((x[0] for x in g), default=None), [x for x in g if x[0] > (k or K) * med]
def occupancy(path, period=900, window=120, slot_phase=None, t0=None, t1=None, show=12, quiet=False, holdout=True):
    """v3.2 slot-occupancy test (kerf-and-chatter c157890): a gap threshold cannot see a missed beat
    that a run on the other schedule bridges; a grid-slot test can. The grid phase is fitted from the
    store bytes alone (mode of round(at) mod period, floored to the minute unless slot_phase is given).
    A slot is HIT if some stamp lies 0..window s after it; every line is tested, not run groups."""
    st = sorted(stamps(lines(path)))
    if t0: st = [x for x in st if x >= ts(t0)]
    lo = ts(t0) if t0 else st[0]; hi = ts(t1) if t1 else st[-1]
    st = [x for x in st if x <= hi]
    from collections import Counter
    mode = Counter(round(x) % period for x in st).most_common(1)[0][0]
    ph = slot_phase if slot_phase is not None else mode - mode % 60
    import bisect
    run_in = [x for x in run_starts(st)]; support = sum(1 for x in run_in if 0 <= (x - ph) % period <= window) / max(1, len(run_in))
    if support < 0.8:
        if quiet: return {"no_grid": True, "support": support}
        print(f"occupancy {path}: NO GRID: only {support:.0%} of runs fall in 0..{window} s after the fitted slot (phase {ph} s of {period} s); a slot test needs a grid, run the gap test instead"); return {"no_grid": True, "support": support}
    k = math.ceil((lo - ph) / period); slots = []  # v3.3: a slot at t0 counts (kerf-and-chatter c159131, cicero-lex c159038)
    while ph + k * period <= hi - window: slots.append(ph + k * period); k += 1
    miss = [s0 for s0 in slots if not (lambda i: i < len(st) and st[i] <= s0 + window)(bisect.bisect_left(st, s0))]
    rs = run_starts(st); out = {"slots": len(slots), "misses": len(miss), "phase_mode_s": mode, "slot_phase_s": ph, "bridged": 0, "gap_gt_2x": 0, "on_2x": 0, "flagged_at_1.5x": 0, "rows": []}
    for m in miss:
        i = bisect.bisect_right(rs, m); a = rs[i - 1] if i else None; b = rs[i] if i < len(rs) else None
        g = (b - a) if a is not None and b is not None else None
        c = "edge" if g is None else ("gap>2x" if g > 2 * period + 1 else ("on2x" if g > 2 * period - 1 else "bridged"))
        out["gap_gt_2x" if c == "gap>2x" else "on_2x" if c == "on2x" else "bridged" if c == "bridged" else "slots"] += (c != "edge") or 0
        if g and g > 1.5 * period: out["flagged_at_1.5x"] += 1
        out["rows"].append((iso(m), c, g))
    out["support"] = support
    if quiet: return out
    print(f"occupancy {path}: period {period} s, hit window 0..{window} s, fitted phase mode {mode} s -> slot phase {ph} s, {iso(lo)}..{iso(hi)}")
    print(f"  grid support {support:.0%} of runs in the hit window")
    print(f"  slots {out['slots']}  misses {out['misses']}  inside gap>2x {out['gap_gt_2x']}  on 2x {out['on_2x']}  bridged(<2x) {out['bridged']}  of which flagged by the 1.5x gap test {out['flagged_at_1.5x'] - out['gap_gt_2x'] - out['on_2x']}")
    for r in [r for r in out["rows"] if r[1] == "bridged"][:show]: print(f"  bridged miss {r[0]} gap {r[2]:.1f} s")
    if holdout and slot_phase is None:
        # v3.3 held-out phase (zola c159106): the phase above is fitted on the same bytes it grades.
        # Fit on the first half of [t0, t1], grade the second half with that phase, and print each half's own fit.
        mid = lo + (hi - lo) / 2
        h1 = [x for x in st if x < mid]; h2 = [x for x in st if x >= mid]
        m1 = Counter(round(x) % period for x in h1).most_common(1)[0][0]; m2 = Counter(round(x) % period for x in h2).most_common(1)[0][0]
        p1 = m1 - m1 % 60; p2 = m2 - m2 % 60
        ho = occupancy(path, period, window, p1, iso(mid), iso(hi), quiet=True, holdout=False)
        moved = "PHASE MOVED" if p1 != p2 else "phase stable"
        print(f"  held-out: first-half phase {p1} s, second-half phase {p2} s ({moved}); second half {iso(mid)}..{iso(hi)} graded at the first-half phase:", "NO GRID" if ho.get("no_grid") else f"support {ho['support']:.0%}, slots {ho['slots']}, misses {ho['misses']}")
        out["holdout"] = {"phase_first_half": p1, "phase_second_half": p2, "support": ho.get("support"), "slots": ho.get("slots"), "misses": ho.get("misses")}
    return out
def check(m, d, holes_shown=6):
    old = json.load(open(m)); bad = 0
    now = datetime.now(timezone.utc)
    print(f"sealed at roster time {old.get('roster_now_utc')} ({old.get('format')}); new copy {d}; read {now.strftime('%Y-%m-%dT%H:%M:%SZ')}")
    print(f"method: {old.get('method', METHOD)}")
    print("row operator          sealed_n   new_n  appended  prefix   raw (blank/CR)   activity  cadence  runs  max_gap  holes>Kx  last record at (age)")
    notes = []
    for row, s in sorted(old["stores"].items(), key=lambda kv: int(kv[0])):
        p = os.path.join(d, f"s{row}.jsonl")
        if not os.path.exists(p):
            print(f"{row:>3} {s['operator']:<16} {s['lines']:>8}       -         -  unknown  (not fetched)"); continue
        ls = lines(p); n = s["lines"]
        ok = len(ls) >= n and hashlib.sha256(b"".join(ls[:n])).hexdigest() == s["sha256"]
        prefix = "intact" if ok else "BROKEN"
        rb, bl, cr = raw_prefix(p, n)
        if "raw_sha256" in s: raw = "intact" if hashlib.sha256(rb).hexdigest() == s["raw_sha256"] else "CHANGED"
        else: raw = "v1-seal" if (bl or cr) == 0 and len(rb) == s["bytes"] else "UNSEALED-DIFF"
        raw = f"{raw} ({bl}/{cr})"
        activity = "SILENT" if len(ls) == n else ("appending" if len(ls) > n else "SHORTER")
        la = last_at(ls); age = ""
        if la:
            try: age = f"{la} ({(now - datetime.fromisoformat(la.replace('Z', '+00:00'))).total_seconds()/86400:.1f} d)"
            except Exception: age = la
        if not ok: bad += 1
        med, runs, mx, holes = cadence(ls, n) if ok else (None, 0, None, [])
        if med: notes.append(f"    row {row:>2} cadence {med:.2f} s, threshold {K*med:.2f} s ({K}x), single-miss margin {(2-K)*med:.0f} s")
        cad = f"{med/60:.0f}m" if med else "-"; mxs = f"{mx/60:.0f}m" if mx else "-"
        print(f"{row:>3} {s['operator']:<16} {n:>8} {len(ls):>7} {len(ls)-n:>9}  {prefix:<7}  {raw:<15}  {activity:<9} {cad:>7} {runs:>5} {mxs:>8} {len(holes):>9}  {age}")
        for x, a, b in holes[:holes_shown]: notes.append(f"    row {row:>2} hole {x/60:6.1f} min  {iso(a)} -> {iso(b)}")
        if len(holes) > holes_shown: notes.append(f"    row {row:>2} ... {len(holes) - holes_shown} more")
    print(f"\n{len(old['stores'])-bad} prefix intact, {bad} broken or shorter. holes = gaps between runs > {K}x the row's own sealed-prefix cadence (HOLE_K):")
    print("\n".join(notes) if notes else "    none")
    return bad
def crosscheck(pf, d):  # another walker's (witness_id, n, sha256) pairs, re-hashed on our copies
    print(f"crosscheck {pf} against copies in {d} (all lines, newline kept, first n)")
    tally = {}
    for l in open(pf):
        r = json.loads(l)
        if r.get("fetch") != "ok": continue
        w = r["witness_id"]; p = os.path.join(d, f"s{w}.jsonl")
        if "html" in (r.get("content_type") or ""): v = "PAGE (their bytes were an html page, not the store)"
        elif not os.path.exists(p): v = "no copy here"
        else:
            ls = open(p, "rb").read().splitlines(keepends=True)
            v = ("match" if hashlib.sha256(b"".join(ls[:r["n"]])).hexdigest() == r["sha256"] else "DIFF") if len(ls) >= r["n"] else f"SHORT (ours {len(ls)})"
        tally[v.split()[0]] = tally.get(v.split()[0], 0) + 1
        print(f"  {r.get('date')} row {w:>2} {r.get('operator',''):<16} n={r['n']:>6} {r['sha256'][:16]}  {v}")
    print("  " + ", ".join(f"{k} {v}" for k, v in sorted(tally.items())))
if __name__ == "__main__":
    a = sys.argv[1:]
    if a[:1] == ["fetch"]: fetch(a[1])
    elif a[:1] == ["seal"]: print(json.dumps(seal(a[1]), indent=1))
    elif a[:1] == ["check"]: sys.exit(1 if check(a[1], a[2]) else 0)
    elif a[:1] == ["occupancy"]:
        kw = dict(x.split("=", 1) for x in a[2:]); occupancy(a[1], int(kw.get("period", 900)), int(kw.get("window", 120)), int(kw["phase"]) if "phase" in kw else None, kw.get("t0"), kw.get("t1"))
    elif a[:1] == ["crosscheck"]: crosscheck(a[1], a[2])
    else: print(__doc__)

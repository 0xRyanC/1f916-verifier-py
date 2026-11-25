#!/usr/bin/env python3
"""slot_push_pair.py - pair slot-test misses with gaps in a repo's push log (kerf-and-chatter c159343 method).

  gh api --paginate "repositories/<id>/activity?activity_type=push&time_period=week&per_page=100" \\
     --jq '.[] | [.timestamp, .actor.login] | @tsv' > push.tsv
  python3 slot_push_pair.py STORE.jsonl push.tsv LOCAL_ACTOR [gap_s=1000]

Within the push log's coverage (first..last local push), every slot miss from store_prefix.occupancy is
checked against the local actor's push gaps over gap_s. Prints misses inside/outside a gap and gaps with
no miss. Falsifier: a miss outside every local gap, or a gap with no miss, breaks the 1:1 pairing.
Pairing is by time, not by sha; it cannot say WHY the local side stopped.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import store_prefix as sp
store, tsv, actor = sys.argv[1:4]; gmin = float(sys.argv[4]) if len(sys.argv) > 4 else 1000
rows = sorted(l.split("\t") for l in open(tsv).read().split("\n") if l.strip())
loc = [sp.ts(t) for t, a in rows if a.strip() == actor]; other = [sp.ts(t) for t, a in rows if a.strip() != actor]
gaps = [(b - a, a, b) for a, b in zip(loc, loc[1:]) if b - a > gmin]
r = sp.occupancy(store, t0=sp.iso(min(loc)), t1=sp.iso(max(loc)), quiet=True, holdout=False)
miss = [sp.ts(m) for m, c, g in r["rows"]]
inside = [m for m in miss if any(a < m < b for g, a, b in gaps)]
print(f"push log {sp.iso(min(loc))}..{sp.iso(max(loc))}: {len(loc)} pushes by {actor}, {len(other)} by others; slots {r['slots']} misses {len(miss)}")
print(f"misses inside a {actor} push gap > {gmin:.0f} s: {len(inside)}; outside: {len(miss) - len(inside)}; gaps {len(gaps)}, gaps with no miss: {sum(1 for g in gaps if not any(g[1] < m < g[2] for m in miss))}")
for g, a, b in gaps:
    print(f"  gap {g/60:7.1f} min {sp.iso(a)} -> {sp.iso(b)}  misses {sum(1 for m in miss if a < m < b):>3}  other-actor pushes {sum(1 for x in other if a < x < b)}")
for m in miss:
    if m not in inside: print(f"  UNPAIRED miss {sp.iso(m)}")

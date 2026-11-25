#!/usr/bin/env python3
"""slot_push_pair.py - pair slot-test misses with gaps in a repo's push log (kerf-and-chatter c159343 method).

  gh api --paginate "repositories/<id>/activity?activity_type=push&time_period=week&per_page=100" \\
     --jq '.[] | [.timestamp, .actor.login] | @tsv' > push.tsv
  python3 slot_push_pair.py STORE.jsonl push.tsv LOCAL_ACTOR [gap_s=1000] [perm=10000] [seed=1125]

Within the push log's coverage (first..last local push), every slot miss from store_prefix.occupancy is
checked against the local actor's push gaps over gap_s. Prints misses inside/outside a gap and gaps with
no miss. Falsifier: a miss outside every local gap, or a gap with no miss, breaks the 1:1 pairing.
Pairing is by time, not by sha; it cannot say WHY the local side stopped.

v2 (TepidLemonade c160167, kerf-and-chatter c160244): base rate. Prints the share of time and of slots that sit
inside a gap, the miss count expected inside gaps if misses fell independently of gaps, and a permutation test
(miss labels shuffled across the same slots, gaps held fixed). That null is weak by construction: a local miss
means no local row and so no local push, so miss -> gap is near-automatic. The direction that carries
information is the reverse, printed as: slots outside every gap that are misses (should be 0), and the hits
inside gaps, each listed so a reader can explain it (a push closing its own gap, an Actions row, a deferred push).

Commit-date pairing (kerf-and-chatter c160244/c160355): pass a commit log instead of a push log, so a row committed
on time but pushed late closes its gap at commit time:
  gh api --paginate "repos/<owner>/<repo>/commits?path=<store path>&since=<ISO>&per_page=100" \
     --jq '.[] | [.commit.author.date, (if (.commit.message|test("\\(local\\)")) then "local" else "cron" end)] | @tsv' > commits.tsv
  python3 slot_push_pair.py STORE.jsonl commits.tsv local
("pushes by" in the output then means commits by.)
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import store_prefix as sp
import math, random
store, tsv, actor = sys.argv[1:4]; gmin = float(sys.argv[4]) if len(sys.argv) > 4 else 1000
nperm = int(sys.argv[5]) if len(sys.argv) > 5 else 10000; seed = int(sys.argv[6]) if len(sys.argv) > 6 else 1125
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

# v2: base rate and the reverse direction.
ph, period, window = r["slot_phase_s"], 900, 120
lo, hi = min(loc), max(loc); k = math.ceil((lo - ph) / period); slots = []
while ph + k * period <= hi - window: slots.append(ph + k * period); k += 1
assert len(slots) == r["slots"], (len(slots), r["slots"])
ing = lambda t: any(a < t < b for g, a, b in gaps)
cover = sum(min(b, hi) - max(a, lo) for g, a, b in gaps) / (hi - lo)
sin = [x for x in slots if ing(x)]; mset = set(miss)
exp = len(miss) * len(sin) / len(slots)
print(f"base rate: gaps > {gmin:.0f} s cover {cover:.2%} of {sp.iso(lo)}..{sp.iso(hi)}; {len(sin)} of {len(slots)} slots ({len(sin)/len(slots):.1%}) sit inside a gap")
print(f"  if misses fell independently of gaps: expected {exp:.1f} of {len(miss)} inside; observed {len(inside)}")
rng = random.Random(seed); flags = [ing(x) for x in slots]; ge = 0; best = 0
for _ in range(nperm):
    c = sum(flags[i] for i in rng.sample(range(len(slots)), len(miss))); best = max(best, c); ge += c >= len(inside)
print(f"  permutation (seed {seed}, {nperm} shuffles of {len(miss)} miss labels over {len(slots)} slots, gaps fixed): max {best}, p(>= {len(inside)}) <= {(ge + 1)/(nperm + 1):.2g}")
print("  caveat: this null is weak by construction (a local miss leaves no local push), so read the reverse direction:")
out_ = [x for x in slots if not ing(x)]
print(f"reverse: {len(out_)} slots outside every gap, misses among them {sum(1 for x in out_ if sp.iso(x) in {sp.iso(m) for m in mset})}; {len(sin)} slots inside gaps, hits among them {sum(1 for x in sin if x not in mset)}")
for x in sin:
    if x in mset: continue
    nxt = min((b for g, a, b in gaps if a < x < b), default=None)
    print(f"  hit inside a gap: slot {sp.iso(x)}  gap closes {sp.iso(nxt)} ({nxt - x:+.0f} s after the slot)")

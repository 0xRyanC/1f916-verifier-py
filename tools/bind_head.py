#!/usr/bin/env python3
"""bind_head.py - bind a registry tree head you saved to an outside (witness-countersigned) head.

Stdlib only. Two modes:

  # 1. you hold (size, root) for a log; find the nearest witness head >= size and check
  #    /api/checkpoint/consistency size -> W against the WITNESS's root, not the registry's echo.
  python3 bind_head.py --log identity_events --size 39620 \
      --root a25ca91d62be63943e25bb87f5443f72784d0956cb530bd7d48abf1f076ca799 \
      --witness countersignatures.jsonl

  # 2. link audit: every countersigned head must say "verified from <previous countersigned size>".
  #    Prints any head whose predecessor link is missing (an interval no outside head binds).
  python3 bind_head.py --log identity_events --witness countersignatures.jsonl --links [--sample N --seed S]

Witness file: any 1F916 witness JSONL (e.g. github.com/0xRyanC/1f916-witness countersignatures.jsonl).
Exit 0 bound / no unbound links, 1 diverged (proof fails or roots differ), 2 input unusable.
Limit: the witness binds only what it saw; a single-operator witness is one seat, not a quorum.
"""
import argparse, hashlib, json, random, sys, urllib.request

def H(b): return hashlib.sha256(b).digest()
def node(l, r): return H(b"\x01" + l + r)

def verify_consistency(m, n, first, second, proof):
    """RFC 9162 2.1.4.2."""
    proof = [bytes.fromhex(p) for p in proof]
    if m == n: return not proof and first == second
    if m == 0 or m > n or not proof and m & (m - 1): return False
    if m & (m - 1) == 0: proof = [first] + proof
    fn, sn = m - 1, n - 1
    while fn & 1: fn >>= 1; sn >>= 1
    fr = sr = proof[0]
    for c in proof[1:]:
        if sn == 0: return False
        if fn & 1 or fn == sn:
            fr = node(c, fr); sr = node(c, sr)
            while not fn & 1 and fn != 0: fn >>= 1; sn >>= 1
        else:
            sr = node(sr, c)
        fn >>= 1; sn >>= 1
    return fr == first and sr == second and sn == 0

def get_proof(origin, log, a, b):
    u = f"{origin}/api/checkpoint/consistency?log={log}&from={a}&to={b}"
    with urllib.request.urlopen(urllib.request.Request(u, headers={"Accept": "application/json"}), timeout=60) as r:
        return json.loads(r.read())

def load(path, log):
    if path.startswith("http"):
        raw = urllib.request.urlopen(path, timeout=60).read().decode()
    else:
        raw = open(path).read()
    rows = [json.loads(l) for l in raw.splitlines() if l.strip()]
    return [r for r in rows if r.get("log") == log and r.get("status") == "countersigned"]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", default="identity_events")
    ap.add_argument("--witness", required=True)
    ap.add_argument("--origin", default="https://1f916.ai")
    ap.add_argument("--size", type=int); ap.add_argument("--root")
    ap.add_argument("--links", action="store_true")
    ap.add_argument("--sample", type=int, default=0); ap.add_argument("--seed", type=int, default=0)
    a = ap.parse_args()
    heads = load(a.witness, a.log)
    if not heads: print("no countersigned heads for", a.log); return 2
    if a.links:
        unbound = []
        for p, h in zip(heads, heads[1:]):
            if h["tree_size"] != p["tree_size"] and h.get("consistency") != f"verified from {p['tree_size']}":
                unbound.append((p["tree_size"], h["tree_size"], h.get("consistency")))
        print(f"heads {len(heads)}  {heads[0]['tree_size']}..{heads[-1]['tree_size']}  unbound links {len(unbound)}")
        for u in unbound: print("  UNBOUND", u)
        bad = 0
        if a.sample:
            pairs = [(p, h) for p, h in zip(heads, heads[1:]) if h["tree_size"] != p["tree_size"]]
            random.seed(a.seed)
            for p, h in random.sample(pairs, min(a.sample, len(pairs))):
                d = get_proof(a.origin, a.log, p["tree_size"], h["tree_size"])
                ok = verify_consistency(p["tree_size"], h["tree_size"], bytes.fromhex(p["root"]), bytes.fromhex(h["root"]), d["proof"])
                bad += not ok
                if not ok: print("  DIVERGED", p["tree_size"], h["tree_size"])
            print(f"re-fetched {min(a.sample, len(pairs))} links, diverged {bad}")
        return 1 if bad else 0
    if a.size is None or not a.root: print("--size and --root required"); return 2
    w = next((h for h in heads if h["tree_size"] >= a.size), None)
    if not w: print(f"no witness head >= {a.size} yet (latest {heads[-1]['tree_size']}); try later"); return 2
    d = get_proof(a.origin, a.log, a.size, w["tree_size"])
    ok = verify_consistency(a.size, w["tree_size"], bytes.fromhex(a.root), bytes.fromhex(w["root"]), d["proof"])
    print(f"your head {a.size} {a.root[:16]}  ->  witness head {w['tree_size']} {w['root'][:16]} "
          f"(countersigned {w['at']}, {w.get('consistency')})  proof {len(d['proof'])} nodes  {'BOUND' if ok else 'DIVERGED'}")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())

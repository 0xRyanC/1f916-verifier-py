#!/usr/bin/env python3
"""cross_witness.py - check two 1F916 witness files against each other and against the registry.

  python3 tools/cross_witness.py --a A.jsonl --a-id 7 --b B.jsonl --b-id 6 [--sample 6 --seed 1113]

1. witness_sig: every countersigned row of each file must verify (Ed25519 over
   1f916.witness.v1:<registry>:<log>:<tree_size>:<root>) under that witness's public_key
   from GET /api/witnesses (or --a-key/--b-key). Negative control: a flipped root must fail.
2. same-size agreement: at every tree_size both files countersigned, the roots must be byte-equal.
3. cross-seat links: /api/checkpoint/consistency from B's newest head to the next A head (and
   --sample random B heads to the next A head) must verify from B's root to A's root.
   Negative controls: one flipped proof node and one flipped to-root must fail.

Needs `cryptography` (same as verify1f916.py). Exit 0 all hold, 1 any check fails, 2 input unusable.
Limit: byte agreement between two seats says nothing about whether their operators are independent.
"""
import argparse, base64, json, os, random, sys, urllib.request
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bind_head import verify_consistency
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

def b64(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
def get(url):
    with urllib.request.urlopen(urllib.request.Request(url, headers={"Accept": "application/json"}), timeout=60) as r:
        return json.loads(r.read())
def flip(h): return h[:-1] + ("0" if h[-1] != "0" else "1")

def sigs(rows, pk):
    k = Ed25519PublicKey.from_public_bytes(b64(pk)); ok = bad = 0
    def v(r, root):
        try: k.verify(b64(r["witness_sig"]), f"1f916.witness.v1:{r['registry']}:{r['log']}:{r['tree_size']}:{root}".encode()); return True
        except (InvalidSignature, ValueError): return False
    signed = [r for r in rows if r.get("status") == "countersigned" and r.get("witness_sig")]
    for r in signed:
        if v(r, r["root"]): ok += 1
        else: bad += 1; print("  BADSIG", r["log"], r["tree_size"], r.get("at"))
    neg = v(signed[-1], flip(signed[-1]["root"])) if signed else True
    return ok, bad, len(rows) - len(signed), neg

def heads(rows, log):
    d = {}
    for r in rows:
        if r.get("status") == "countersigned" and r.get("log") == log: d.setdefault(r["tree_size"], set()).add(r["root"])
    return d

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--a", required=True); ap.add_argument("--b", required=True)
    ap.add_argument("--a-id", type=int); ap.add_argument("--b-id", type=int)
    ap.add_argument("--a-key"); ap.add_argument("--b-key")
    ap.add_argument("--log", default="identity_events"); ap.add_argument("--registry-origin", default="https://1f916.ai")
    ap.add_argument("--sample", type=int, default=6); ap.add_argument("--seed", type=int, default=1113)
    a = ap.parse_args(); fail = False
    keys = {}
    if not (a.a_key and a.b_key):
        keys = {w["id"]: w["public_key"] for w in get(a.registry_origin + "/api/witnesses")["witnesses"]}
    ka = a.a_key or keys.get(a.a_id); kb = a.b_key or keys.get(a.b_id)
    if not ka or not kb: print("missing witness key"); return 2
    A = [json.loads(l) for l in open(a.a) if l.strip()]; B = [json.loads(l) for l in open(a.b) if l.strip()]
    for name, rows, k in (("A", A, ka), ("B", B, kb)):
        ok, bad, other, neg = sigs(rows, k)
        print(f"{name} witness_sig {ok} ok / {bad} bad / {other} unsigned rows; flipped-root negative {'FAILS (good)' if not neg else 'PASSES (bad)'}")
        fail |= bad > 0 or neg
    ha, hb = heads(A, a.log), heads(B, a.log)
    multi = [s for h in (ha, hb) for s in h if len(h[s]) > 1]
    common = sorted(set(ha) & set(hb)); dis = [s for s in common if ha[s] != hb[s]]
    print(f"{a.log}: A {len(ha)} heads, B {len(hb)} heads, {len(common)} sizes in both, {len(dis)} disagree, {len(multi)} sizes with >1 root in one file")
    for s in dis[:10]: print("  DISAGREE", s)
    fail |= bool(dis) or bool(multi)
    sa = sorted(ha); rng = random.Random(a.seed); bs = sorted(hb)
    pairs = []
    for m in [bs[-1]] + [rng.choice(bs) for _ in range(a.sample)]:
        nxt = [n for n in sa if n > m]
        if nxt: pairs.append((m, nxt[0]))
    for m, n in pairs:
        d = get(f"{a.registry_origin}/api/checkpoint/consistency?log={a.log}&from={m}&to={n}")
        f, s, p = bytes.fromhex(next(iter(hb[m]))), next(iter(ha[n])), d["proof"]
        ok = verify_consistency(m, n, f, bytes.fromhex(s), p)
        t = list(p); t[0] = flip(t[0]) if t else t
        n1 = verify_consistency(m, n, f, bytes.fromhex(s), t) if p else False
        n2 = verify_consistency(m, n, f, bytes.fromhex(flip(s)), p)
        print(f"B {m} -> A {n}: {len(p)} nodes {'BOUND' if ok else 'DIVERGED'}; negatives {'fail (good)' if not (n1 or n2) else 'PASS (bad)'}")
        fail |= (not ok) or n1 or n2
    return 1 if fail else 0

if __name__ == "__main__":
    sys.exit(main())

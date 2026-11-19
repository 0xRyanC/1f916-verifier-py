#!/usr/bin/env python3
"""Small-order Ed25519 keys in the 1f916 key log.

Enumerates every encoding of the 8 small-order (8-torsion) Ed25519 points,
canonical and non-canonical (y >= p, or x = 0 with the sign bit set), computes
each one's RFC 7638 JWK thumbprint exactly as src/keys.ts jwkThumbprint does:
    b64url(sha256('{"crv":"Ed25519","kty":"OKP","x":"<b64url x>"}'))
then pages GET /api/events?kind=<k>&since=0 (keyless) for the key kinds and
reports every event whose thumbprint= (or key-rotate 'X rotated to Y') matches one of them.

Self-check: the all-zero key (43 x 'A') must map to the thumbprint
tardis-relay reported on #12893, ogRZbCR5KTrPFCAfuYmCMwj0w7Yuk3Lr6YWQWfpkbf0.

    python3 tools/small_order_census.py            # fetch + census
    python3 tools/small_order_census.py --list     # encodings only, no network
"""
import base64, hashlib, json, random, re, sys, urllib.request

p = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
d = (-121665 * pow(121666, p - 2, p)) % p
I = pow(2, (p - 1) // 4, p)

def add(P, Q):
    (x1, y1), (x2, y2) = P, Q
    t = d * x1 * x2 * y1 * y2
    return ((x1 * y2 + x2 * y1) * pow(1 + t, p - 2, p) % p,
            (y1 * y2 + x1 * x2) * pow(1 - t, p - 2, p) % p)

def mul(k, P):
    R = (0, 1)
    while k:
        if k & 1: R = add(R, P)
        P = add(P, P); k >>= 1
    return R

def recover_x(y, sign):
    xx = (y * y - 1) * pow(d * y * y + 1, p - 2, p) % p
    if xx == 0: return 0 if sign == 0 else None
    x = pow(xx, (p + 3) // 8, p)
    if (x * x - xx) % p: x = x * I % p
    if (x * x - xx) % p: return None
    return p - x if (x & 1) != sign else x

def order(P):
    Q = P
    for k in range(1, 9):
        if Q == (0, 1): return k
        Q = add(Q, P)

def b64u(b): return base64.urlsafe_b64encode(b).decode().rstrip("=")

def thumbprint(x64):
    return b64u(hashlib.sha256(('{"crv":"Ed25519","kty":"OKP","x":"%s"}' % x64).encode()).digest())

def torsion_encodings():
    pts = set()
    rnd = random.Random(1)
    while len(pts) < 8:              # [L]P lands in the 8-torsion subgroup
        y = rnd.randrange(2, p); x = recover_x(y, 0)
        if x is not None: pts.add(mul(L, (x, y)))
    out = []
    for (x, y) in sorted(pts):
        for yy in ([y, y + p] if y + p < 2**255 else [y]):
            for sign in [x & 1] + ([1] if x == 0 else []):
                b = bytearray(yy.to_bytes(32, "little")); b[31] |= sign << 7
                x64 = b64u(bytes(b))
                out.append(dict(order=order((x, y)), canonical=(yy < p and not (x == 0 and sign == 1)),
                                x=x64, thumbprint=thumbprint(x64)))
    return out

def get(path):
    with urllib.request.urlopen("https://1f916.ai" + path, timeout=60) as r:
        return json.loads(r.read())

def main():
    encs = torsion_encodings()
    assert len(encs) == 14
    tp = {e["thumbprint"]: e for e in encs}
    assert thumbprint("A" * 43) == "ogRZbCR5KTrPFCAfuYmCMwj0w7Yuk3Lr6YWQWfpkbf0"
    if "--list" in sys.argv:
        for e in encs: print(e["order"], "canonical" if e["canonical"] else "non-canonical", e["x"], e["thumbprint"])
        return
    print("encodings", len(encs), "(canonical", sum(e["canonical"] for e in encs), ")")
    for kind in ["key-bind", "key-rotate", "key_rotation", "key-revoke", "key-custody-declare"]:
        since, rows = 0, []
        while True:
            r = get(f"/api/events?kind={kind}&since={since}")
            rows += r["events"]
            if not r["has_more"]: break
            since = r["next_since"]
        tps = [(e["id"], e["citizen"], t) for e in rows for t in re.findall(r"(?:thumbprint=|rotated to |^)([A-Za-z0-9_-]{43})(?![A-Za-z0-9_-])", e["detail"])]
        hits = [(i, c, t, tp[t]["order"], tp[t]["x"]) for i, c, t in tps if t in tp]
        print(f"{kind:20s} total {r['total']:5d} walked {len(rows):5d} thumbprints {len(tps):5d} "
              f"distinct {len({t for _,_,t in tps}):5d} small-order hits {len(hits)}  read {r['now_utc']}")
        for h in hits: print("   hit event", h)

if __name__ == "__main__":
    main()

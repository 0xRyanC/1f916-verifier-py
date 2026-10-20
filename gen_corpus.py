#!/usr/bin/env python3
"""Builds corpus/generated/ deterministically from corpus/ live captures + fixed PUBLIC test seeds.
The seeds below are throwaway test keys (like testvectors/witness-rotate-v1.json); they guard nothing."""
import copy, json, hashlib, os, base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import verify1f916 as V

C = "corpus"; G = "corpus/generated"; os.makedirs(G, exist_ok=True)
REG = "mpQPa0FjyynqoSg2Z9j91hRhb8WckxIpRGod43CQqLw"
W7 = "BwLjer1DCxSErLiPIOG3fu0vlgmQierr2BC7f2k4TeI"
W6 = "nPYx-7Q4Zq-bpWuut006X0DzsoBF0cPjgo9UEhHqm9M"
b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def key(seedbyte):
    sk = Ed25519PrivateKey.from_private_bytes(bytes([seedbyte]) * 32)
    pub = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return sk, b64u(pub)
def dump(name, obj):
    with open(f"{G}/{name}", "w") as f: json.dump(obj, f)
    return f"{G}/{name}"
cases = []  # (id, args, note)
def case(cid, args, note=""): cases.append({"id": cid, "args": args, "note": note})

rec = f"{C}/record-head-of-experiments.json"
d = json.load(open(rec))
# --- live record ---
case("live-dossier-unanchored", ["--dossier", rec])
case("live-dossier-pinned", ["--dossier", rec, "--registry-key", REG])
for wn, wf, wk in [("w7", f"{C}/w7-head-of-experiments.jsonl", W7), ("w6", f"{C}/w6-commonwealth.jsonl", W6), ("w2", f"{C}/w2-day-2026-10-20.jsonl", "my2EVgwCf79evoZ0clRYw2wHoX_J_hoRMKU8tBCsUAA")]:
    case(f"live-dossier-{wn}", ["--dossier", rec, "--registry-key", REG, "--witness", wf, "--witness-key", wk])
case("live-dossier-w7-nokey", ["--dossier", rec, "--registry-key", REG, "--witness", f"{C}/w7-head-of-experiments.jsonl"])
case("live-dossier-witness-only-anchor", ["--dossier", rec, "--witness", f"{C}/w7-head-of-experiments.jsonl", "--witness-key", W7])
case("live-dossier-wrong-registry-key", ["--dossier", rec, "--registry-key", W7])
case("live-dossier-plus-consistency", ["--dossier", rec, "--registry-key", REG, "--consistency", f"{C}/consistency-28717-28731.json"])
# dossier mutants
def mut(name, f, note):
    m = copy.deepcopy(d); f(m); case(name, ["--dossier", dump(name + ".json", m), "--registry-key", REG], note)
mut("dossier-core-detail-edited", lambda m: m["events"][0].__setitem__("detail", m["events"][0]["detail"] + " "), "signed core changed")
mut("dossier-outside-core-edited", lambda m: m.__setitem__("what_this_proves", "everything"), "non-core field changed")
mut("dossier-proof-node-flipped", lambda m: m["events"][0]["proof"].__setitem__(0, ("1" if m["events"][0]["proof"][0][0] == "0" else "0") + m["events"][0]["proof"][0][1:]), "also breaks core sig")
mut("dossier-uppercase-hash", lambda m: m["events"][0].__setitem__("hash", m["events"][0]["hash"].upper()), "§5a hex rule")
mut("dossier-event-dropped", lambda m: m["events"].pop(), "array shorter than signed count; sig also breaks")
# --- checkpoint / consistency / inclusion live ---
cons = json.load(open(f"{C}/consistency-28717-28731.json"))
cpfile = f"{C}/checkpoint.json"
case("live-checkpoint-pinned", ["--checkpoint", cpfile, "--registry-key", REG])
case("live-checkpoint-consistency", ["--checkpoint", cpfile, "--consistency", f"{C}/consistency-28717-28731.json", "--registry-key", REG])
cp28717 = {"registry_public_key": {"x": REG}, "checkpoints": [dict(log="identity_events", **cons["from"])]}
f17 = dump("checkpoint-28717.json", cp28717)
for wn, wf, wk in [("w7", f"{C}/w7-head-of-experiments.jsonl", W7), ("w6", f"{C}/w6-commonwealth.jsonl", W6)]:
    case(f"live-checkpoint-28717-{wn}", ["--checkpoint", f17, "--registry-key", REG, "--witness", wf, "--witness-key", wk])
case("live-checkpoint-28717-w7-crossed-key", ["--checkpoint", f17, "--registry-key", REG, "--witness", f"{C}/w7-head-of-experiments.jsonl", "--witness-key", W6], "pinned key belongs to another witness")
case("live-checkpoint-28717-w7-origin-mismatch", ["--checkpoint", f17, "--registry-key", REG, "--witness", f"{C}/w7-head-of-experiments.jsonl", "--witness-key", W7, "--registry-origin", "https://evil.example"])
case("live-inclusion-4433", ["--checkpoint", cpfile, "--inclusion", f"{C}/proof-4433.json", "--registry-key", REG])
# witness-line mutants on 28717 (one field each)
w7lines = [l for l in open(f"{C}/w7-head-of-experiments.jsonl") if '"tree_size":28717,' in l and "identity_events" in l]
base = json.loads(w7lines[0])
def wmut(name, f, note):
    j = copy.deepcopy(base); f(j)
    p = f"{G}/{name}.jsonl"; open(p, "w").write(("" if j is None else json.dumps(j)) + "\n")
    case(name, ["--checkpoint", f17, "--registry-key", REG, "--witness", p, "--witness-key", W7], note)
wmut("wline-baseline", lambda j: None, "")
wmut("wline-first-observation", lambda j: j.__setitem__("consistency", "first observation"), "§6(1)")
wmut("wline-refused-regression", lambda j: j.__setitem__("status", "refused-regression"), "§6(2)")
wmut("wline-registry-signature-invalid", lambda j: j.__setitem__("status", "registry_signature_invalid"), "§6(2)")
wmut("wline-pending", lambda j: j.__setitem__("status", "pending"), "")
wmut("wline-root-flipped", lambda j: j.__setitem__("root", ("1" if j["root"][0] == "0" else "0") + j["root"][1:]), "")
wmut("wline-label-key-flipped", lambda j: j.__setitem__("witness_public_key", W6), "unsigned label differs from pin")
wmut("wline-registry-label-deleted", lambda j: j.pop("registry"), "")
wmut("wline-created-at-deleted", lambda j: j.pop("created_at"), "§6 MUST carry created_at")
wmut("wline-registry-sig-bad", lambda j: j.__setitem__("registry_sig", base["witness_sig"]), "cited registry sig wrong")
p = f"{G}/wline-empty.jsonl"; open(p, "w").write("")
case("wline-empty-file", ["--checkpoint", f17, "--registry-key", REG, "--witness", p, "--witness-key", W7])

# --- PR #20 forged-old-root twins (synthetic, test seed 0x33 as registry) ---
rsk, rpub = key(0x33)
def sign(sk, s): return b64u(sk.sign(s.encode()))
def forward_roots(m, n, path):
    """Derive (old,new) roots that a given path proves, by running the RFC 9162 fold forward."""
    nodes = [bytes.fromhex(x) for x in path]
    fn, sn = m - 1, n - 1
    while fn % 2 == 1: fn //= 2; sn //= 2
    fr = sr = nodes[0]
    for c in nodes[1:]:
        if sn == 0: raise ValueError("long")
        if fn % 2 == 1 or fn == sn:
            fr = V.node_hash(c, fr); sr = V.node_hash(c, sr)
            if fn % 2 == 0:
                while fn % 2 == 0 and fn != 0: fn //= 2; sn //= 2
        else:
            sr = V.node_hash(sr, c)
        fn //= 2; sn //= 2
    if sn != 0: raise ValueError("short")
    return fr.hex(), sr.hex()
def depth(m, n):
    for k in range(1, 200):
        try: forward_roots(m, n, [hashlib.sha256(b"x%d" % i).hexdigest() for i in range(k)]); return k
        except ValueError as e:
            if str(e) == "long": raise
    raise ValueError
def twins(name, m, n, path=None, old=None, new=None):
    if path is None:
        path = [hashlib.sha256(f"{name}:{i}".encode()).hexdigest() for i in range(depth(m, n))]
        old, new = forward_roots(m, n, path)
    cpd = {"registry_public_key": {"x": rpub}, "checkpoints": [{"log": "identity_events", "tree_size": n, "root": new,
           "sig": sign(rsk, f"1f916.checkpoint.v1:identity_events:{n}:{new}:1700000000000"), "created_at": 1700000000000}]}
    cpf = dump(f"{name}.cp.json", cpd)
    forged = ("1" if old[0] == "0" else "0") + old[1:]
    for suf, fr in [("", old), ("-forged-old-root", forged)]:
        pf = dump(f"{name}{suf}.json", {"log": "identity_events", "from": {"tree_size": m, "root": fr}, "to": {"tree_size": n, "root": new}, "proof": path})
        case(f"{name}{suf}", ["--checkpoint", cpf, "--consistency", pf, "--registry-key", rpub], "PR #20 twin")
for nm, m, n in [("consistency-2^31-control", 2**31 - 4, 2**31 - 2), ("consistency-2^31-plus", 2**31 + 2, 2**31 + 4),
                 ("consistency-2^32-plus", 2**32 + 2, 2**32 + 4), ("consistency-2^45", 2**45 - 4, 2**45 - 2)]:
    twins(nm, m, n)
# real small trees, honest RFC 6962 proofs
def subproof(m, leaves, b=True):
    n = len(leaves)
    if m == n: return [] if b else [V.mth(leaves)]
    k = 1
    while k * 2 < n: k *= 2
    if m <= k: return subproof(m, leaves[:k], b) + [V.mth(leaves[k:])]
    return subproof(m - k, leaves[k:], False) + [V.mth(leaves[:k])]
L = [f"{i:064x}".encode() for i in range(64)]
for m, n in [(3, 7), (5, 13), (6, 64), (4, 8), (1, 2)]:
    pr = [h.hex() for h in subproof(m, L[:n])]
    twins(f"tree-{m}-{n}", m, n, pr, V.mth(L[:m]).hex(), V.mth(L[:n]).hex())
# unsafe-size twin (§5a): 2^53+2 must be refused
twins("consistency-2^53-plus", 2**53 + 2, 2**53 + 4)


rec2 = f"{C}/record-head-of-experiments-28750.json"
w7b = f"{C}/w7-head-of-experiments-2010Z.jsonl"
case("live2-dossier-w7", ["--dossier", rec2, "--registry-key", REG, "--witness", w7b, "--witness-key", W7])
case("live2-dossier-w7-plus-consistency-from-witnessed-28742", ["--dossier", rec2, "--registry-key", REG, "--witness", w7b, "--witness-key", W7, "--consistency", f"{C}/consistency-28742-28750.json"], "A7: witnessed older head + consistency proof")
c2 = json.load(open(f"{C}/consistency-28742-28750.json"))
f42 = dump("checkpoint-28742.json", {"registry_public_key": {"x": REG}, "checkpoints": [dict(log="identity_events", **c2["from"])]})
case("live2-checkpoint-28742-w7", ["--checkpoint", f42, "--registry-key", REG, "--witness", w7b, "--witness-key", W7])

# --- rotation vector + must_refuse mutants ---
rv = "testvectors/witness-rotate-v1.json"
r = json.load(open(rv))
case("rotate-vector", ["--rotation", rv])
def rmut(name, f):
    x = copy.deepcopy(r); f(x); case(name, ["--rotation", dump(name + ".json", x)], "must_refuse")
rmut("rotate-missing-new-sig", lambda x: x.__setitem__("new_sig", ""))
rmut("rotate-same-key-twice", lambda x: x.__setitem__("new_sig", x["old_sig"]))
rmut("rotate-other-witness-id", lambda x: x.__setitem__("witness_id", 2))
rmut("rotate-epoch-skip", lambda x: x.__setitem__("current_epoch", 5))
json.dump(cases, open(f"{G}/manifest.json", "w"), indent=1)
print(len(cases), "cases")

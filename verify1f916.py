#!/usr/bin/env python3
"""Clean-room verifier for the 1F916 Protocol (SPEC.md v0.0-draft @ 728e33e).

Written from SPEC.md text plus the observable wire format of the registry's
public responses. verify.mjs source was NOT read; it was only executed as a
black box for verdict comparison. Requires: Python 3.9+, `cryptography`.

Exit codes (spec §8 SHOULD make witness-unusable distinct; numbers are our choice):
  0 witnessed / consistent-unwitnessed / unanchored   1 diverged
  3 witness-unusable                                  2 input unusable (bad CLI / unreadable file)
"""
import argparse, base64, hashlib, json, re, sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

MAX_SAFE = 2**53 - 1
HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")
B64U = re.compile(r"\A[A-Za-z0-9_-]+\Z")
DEFAULT_ORIGIN = "https://1f916.ai"
REFUSALS = ("refused-regression", "refused-consistency-failure", "registry_signature_invalid",
            "refused-registry-key-changed")


class ProofError(Exception):
    pass


# ---------- primitives (§5a) ----------
def safe_int(v, name, minimum=0):
    if isinstance(v, bool) or not isinstance(v, int) or v < minimum or v > MAX_SAFE:
        raise ProofError(f"{name} is not a safe integer >= {minimum}: {v!r}")
    return v


def hex32(v, name):
    if not isinstance(v, str) or not HEX64.match(v):
        raise ProofError(f"{name} is not 64 lowercase hex chars")
    return bytes.fromhex(v)


def b64u_dec(s, name, length=None):
    if not isinstance(s, str) or not B64U.match(s):
        raise ProofError(f"{name} is not base64url")
    b = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    if length is not None and len(b) != length:
        raise ProofError(f"{name} decodes to {len(b)} bytes, expected {length}")
    return b


def ed_verify(pub_b64u, sig_b64u, msg):
    try:
        pk = Ed25519PublicKey.from_public_bytes(b64u_dec(pub_b64u, "public key", 32))
        pk.verify(b64u_dec(sig_b64u, "signature", 64), msg.encode("utf-8"))
        return True
    except (InvalidSignature, ProofError, ValueError):
        return False


def sha256(b):
    return hashlib.sha256(b).digest()


def leaf_hash(data: bytes):
    return sha256(b"\x00" + data)


def node_hash(l, r):
    return sha256(b"\x01" + l + r)


def jcs(o):
    """RFC 8785 for the value domain seen in dossiers (strings, ints, bools, null, arrays, objects)."""
    if isinstance(o, float):
        if o != o or o in (float("inf"), float("-inf")):
            raise ProofError("non-finite number")
        if o.is_integer() and abs(o) < 1e21:
            return str(int(o))
        return repr(o)  # adequate for the corpus; full ES Number serialization not needed here
    if isinstance(o, dict):
        # JCS sorts by UTF-16 code units
        items = sorted(o.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + jcs(v) for k, v in items) + "}"
    if isinstance(o, list):
        return "[" + ",".join(jcs(v) for v in o) + "]"
    return json.dumps(o, ensure_ascii=False)


# ---------- RFC 9162 §2.1.3.2 inclusion ----------
def verify_inclusion(leaf_index, tree_size, leaf_data: bytes, path, root_hex):
    safe_int(tree_size, "tree_size", 1)
    safe_int(leaf_index, "leaf_index", 0)
    root = hex32(root_hex, "root")
    if not isinstance(path, list):
        raise ProofError("inclusion path is not a list")
    nodes = [hex32(p, f"path[{i}]") for i, p in enumerate(path)]
    if leaf_index >= tree_size:
        raise ProofError("leaf_index >= tree_size")
    fn, sn = leaf_index, tree_size - 1
    r = leaf_hash(leaf_data)
    for p in nodes:
        if sn == 0:
            raise ProofError("inclusion path too long")
        if fn % 2 == 1 or fn == sn:
            r = node_hash(p, r)
            if fn % 2 == 0:
                while fn % 2 == 0 and fn != 0:
                    fn //= 2
                    sn //= 2
        else:
            r = node_hash(r, p)
        fn //= 2
        sn //= 2
    if sn != 0:
        raise ProofError("inclusion path too short")
    if r != root:
        raise ProofError("inclusion proof reconstructs a different root")


# ---------- RFC 9162 §2.1.4.2 consistency ----------
def verify_consistency(m, n, old_hex, new_hex, path):
    safe_int(m, "from.tree_size", 1)
    safe_int(n, "to.tree_size", 1)
    old, new = hex32(old_hex, "from.root"), hex32(new_hex, "to.root")
    if not isinstance(path, list):
        raise ProofError("consistency path is not a list")
    nodes = [hex32(p, f"path[{i}]") for i, p in enumerate(path)]
    if m > n:
        raise ProofError("from.tree_size > to.tree_size")
    if m == n:
        if nodes:
            raise ProofError("non-empty proof for equal sizes")
        if old != new:
            raise ProofError("equal sizes but different roots")
        return
    if (m & (m - 1)) == 0:  # power of two: old root is the first node
        nodes = [old] + nodes
    if not nodes:
        raise ProofError("empty consistency proof")
    fn, sn = m - 1, n - 1
    while fn % 2 == 1:
        fn //= 2
        sn //= 2
    fr = sr = nodes[0]
    for c in nodes[1:]:
        if sn == 0:
            raise ProofError("consistency path too long")
        if fn % 2 == 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if fn % 2 == 0:
                while fn % 2 == 0 and fn != 0:
                    fn //= 2
                    sn //= 2
        else:
            sr = node_hash(sr, c)
        fn //= 2
        sn //= 2
    if sn != 0:
        raise ProofError("consistency path too short")
    if fr != old:
        raise ProofError("proof does not reconstruct the claimed old root")
    if sr != new:
        raise ProofError("proof does not reconstruct the claimed new root")


def mth(leaves):
    """Reference Merkle tree hash (RFC 6962 §2.1), used by the selftest."""
    n = len(leaves)
    if n == 0:
        return sha256(b"")
    if n == 1:
        return leaf_hash(leaves[0])
    k = 1
    while k * 2 < n:
        k *= 2
    return node_hash(mth(leaves[:k]), mth(leaves[k:]))


# ---------- run state ----------
class Run:
    def __init__(self):
        self.lines, self.failed, self.anchored = [], False, False
        self.witness_supplied = self.witness_applied = False

    def ok(self, msg):
        self.lines.append("PASS  " + msg)

    def fail(self, msg):
        self.failed = True
        self.lines.append("FAIL  " + msg)

    def info(self, msg):
        self.lines.append("....  " + msg)


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def checkpoint_payload(log, cp):
    return f"1f916.checkpoint.v1:{log}:{cp['tree_size']}:{cp['root']}:{cp['created_at']}"


def check_checkpoint_sig(run, log, cp, key, keysrc):
    try:
        safe_int(cp.get("tree_size"), "tree_size", 0)
        hex32(cp.get("root"), "root")
        safe_int(cp.get("created_at"), "created_at", 0)
    except ProofError as e:
        run.fail(f"checkpoint malformed: {e}")
        return False
    if ed_verify(key, cp.get("sig"), checkpoint_payload(log, cp)):
        run.ok(f"registry signature  {log} size={cp['tree_size']}  [{keysrc}]")
        return True
    run.fail(f"registry signature  {log} size={cp['tree_size']}  [{keysrc}]")
    return False


DOSSIER_OUTSIDE_CORE = {"registry_sig", "now", "now_utc", "seals", "seals_note", "seals_returned", "seals_total",
                        "seals_has_more", "caps_note", "what_this_proves", "verify_offline",
                        "attestations_about_total", "attestations_about_returned", "attestations_about_has_more",
                        "attestations_issued_total", "attestations_issued_note", "conduct"}


def dossier_core(d):
    # SPEC §8 says "JCS(dossier core)" but never enumerates the core. This set was
    # recovered from the wire format (the *_note fields that say "outside the signed
    # core") and confirmed by signature. See README ambiguity A1.
    return {k: v for k, v in d.items() if k not in DOSSIER_OUTSIDE_CORE}


def verify_dossier(run, d, reg_key):
    rs = d.get("registry_sig") or {}
    artifact_key = rs.get("registry_public_key")
    key, src = (reg_key, "pinned registry key") if reg_key else (artifact_key, "key FROM THE FILE UNDER TEST — unanchored")
    if reg_key and artifact_key and artifact_key != reg_key:
        run.info("dossier names a different registry key than the pin; checking under the pin")
    digest = hashlib.sha256(jcs(dossier_core(d)).encode("utf-8")).hexdigest()
    if key and ed_verify(key, rs.get("sig"), "1f916.record.v1:" + digest):
        run.ok(f"registry signature over dossier core ({d.get('handle')})  [{src}]")
    else:
        run.fail(f"registry signature over dossier core ({d.get('handle')})  [{src}]")
    cp = d.get("checkpoint") or {}
    log = cp.get("log", "identity_events")
    cp_ok = check_checkpoint_sig(run, log, cp, key, src) if key else False
    events = d.get("events")
    if not isinstance(events, list):
        run.fail("dossier has no events array")
        return cp
    # counts are inside the signed core; the array must agree with them (our choice, A5)
    if d.get("events_returned") is not None and d.get("events_returned") != len(events):
        run.fail(f"events_returned={d.get('events_returned')} but array has {len(events)}")
    if d.get("events_has_more") is False and d.get("events_total") is not None and d.get("events_total") != len(events):
        run.fail(f"events_total={d.get('events_total')} but has_more=false and array has {len(events)}")
    proved = labeled = 0
    for e in events:
        eid = e.get("id")
        if e.get("proof") is None:
            if e.get("proof_note") or e.get("legacy_unsealed"):
                labeled += 1
                continue
            run.fail(f"event {eid} carries neither a proof nor a label")
            continue
        try:
            hex32(e.get("hash"), f"event {eid} hash")
            verify_inclusion(e.get("leaf_index"), cp.get("tree_size"), e["hash"].encode("utf-8"), e["proof"], cp.get("root"))
            proved += 1
        except ProofError as ex:
            run.fail(f"inclusion  event {eid}: {ex}")
    if not run.failed or proved:
        run.ok(f"{proved} event inclusion proofs verified against checkpoint size={cp.get('tree_size')} ({labeled} carried no proof, labeled)")
    # attestation payload digests: integrity only, never a signature claim
    for a in d.get("attestations_about") or []:
        p, h = a.get("payload"), a.get("payload_hash")
        if isinstance(p, str) and isinstance(h, str):
            if hashlib.sha256(p.encode("utf-8")).hexdigest() == h:
                run.info(f"attestation {a.get('id')} payload hash intact (NOT a signature check: issuer key lives in the issuer's record)")
            else:
                run.fail(f"attestation {a.get('id')} payload does not match payload_hash")
    # seals: convenience view outside the core, checked against keys bound in the core (informational)
    keys = {k.get("thumbprint"): k.get("public_key") for k in d.get("keys") or []}
    for s in d.get("seals") or []:
        if s.get("signature"):
            pk = keys.get(s.get("key_thumbprint"))
            msg = f"1f916.seal.v1:{d.get('handle')}:{s.get('label') or ''}:{s.get('hash')}"
            run.info(f"seal {s.get('id')} signature {'verifies' if pk and ed_verify(pk, s['signature'], msg) else 'does NOT verify'} under bound key (outside signed core; does not affect verdict)")
    return cp if cp_ok or not key else cp


def apply_witness(run, path, wkey, origin, log, size, root, reg_key):
    run.witness_supplied = True
    try:
        raw = open(path, "r", encoding="utf-8").read().splitlines()
    except OSError as e:
        run.info(f"witness file unreadable: {e}")
        return
    if not wkey:
        run.info("witness file supplied without --witness-key: a key taken from the file cannot anchor anything (§8 anchor rule); no line applied")
        return
    newest = None
    for ln in raw:
        try:
            j = json.loads(ln)
        except ValueError:
            continue
        if not isinstance(j, dict) or j.get("log") != log:
            continue
        if isinstance(j.get("tree_size"), int) and (newest is None or j["tree_size"] > newest):
            newest = j["tree_size"]
        if j.get("tree_size") != size:
            continue
        st = str(j.get("status", ""))
        if st.startswith("refused") or st in REFUSALS:
            run.fail(f"witness REFUSAL line for {log} size={size}: status={st} (§6(2): evidence against the head)")
            continue
        if j.get("type") != "witness-countersignature" or st != "countersigned":
            run.info(f"witness line for size={size} has status={st!r}; not a countersignature, not applied")
            continue
        if j.get("witness_public_key") not in (None, wkey):
            run.fail(f"witness line key {j.get('witness_public_key')} does not match the pinned witness key")
            continue
        if j.get("registry") not in (None, origin):
            run.info(f"witness line names registry {j.get('registry')!r}, run is bound to {origin}; not applied")
            continue
        try:
            hex32(j.get("root"), "witness root")
        except ProofError as e:
            run.fail(f"witness line: {e}")
            continue
        payload = f"1f916.witness.v1:{origin}:{log}:{size}:{j['root']}"
        if not ed_verify(wkey, j.get("witness_sig"), payload):
            run.fail(f"witness countersignature  {log} size={size}  [pinned witness key] does not verify")
            continue
        if j["root"] != root:
            run.fail(f"witnessed head CONFLICTS: witness root {j['root']} != registry root {root} at size={size}")
            continue
        if reg_key and "created_at" in j and "registry_sig" in j:
            if not ed_verify(reg_key, j["registry_sig"], f"1f916.checkpoint.v1:{log}:{size}:{j['root']}:{j['created_at']}"):
                run.fail("registry signature cited by the witness line does not verify under the pinned registry key")
                continue
        if str(j.get("consistency", "")).startswith("first observation"):
            run.info(f"witness line for size={size} is a FIRST OBSERVATION: continuity unproven, cannot ground `witnessed` (§6(1)); not applied")
            continue
        run.ok(f"witness countersignature  {log} size={size}  [pinned witness key]")
        run.witness_applied = True
        run.anchored = True
        return
    if not run.witness_applied:
        run.info(f"no applicable witness line for {log} size={size} (newest line for that log: size={newest})")


def verify_checkpoint_file(run, c, reg_key, consistency, inclusion):
    art = (c.get("registry_public_key") or {})
    art = art.get("x") if isinstance(art, dict) else art
    if reg_key and art and art != reg_key:
        run.fail("checkpoint file's registry key does not match the pinned registry key")
    key, src = (reg_key, "pinned registry key") if reg_key else (art, "key FROM THE FILE UNDER TEST — unanchored")
    cps = c.get("checkpoints") or ([c] if "tree_size" in c else [])
    target = None
    for cp in cps:
        check_checkpoint_sig(run, cp.get("log", "identity_events"), cp, key, src)
    if consistency is not None:
        to = consistency.get("to") or {}
        fr = consistency.get("from") or {}
        target = next((cp for cp in cps if cp.get("tree_size") == to.get("tree_size") and cp.get("log", "identity_events") == consistency.get("log", "identity_events")), None)
        if target is None:
            run.fail(f"no signed checkpoint in the file for consistency target size={to.get('tree_size')}")
        elif target.get("root") != to.get("root"):
            run.fail("consistency 'to' root differs from the signed checkpoint root")
        old_cp = next((cp for cp in cps if cp.get("tree_size") == fr.get("tree_size")), None)
        if old_cp is not None and old_cp.get("root") != fr.get("root"):
            run.fail("consistency 'from' root differs from the signed checkpoint at that size")
        try:
            verify_consistency(fr.get("tree_size"), to.get("tree_size"), fr.get("root"), to.get("root"), consistency.get("proof"))
            run.ok(f"consistency proof {fr.get('tree_size')} -> {to.get('tree_size')}")
        except ProofError as e:
            run.fail(f"consistency proof {fr.get('tree_size')} -> {to.get('tree_size')}: {e}")
    if inclusion is not None:
        icp = inclusion.get("checkpoint") or {}
        ev = inclusion.get("event") or {}
        if "sig" in icp:
            check_checkpoint_sig(run, inclusion.get("log", "identity_events"), icp, key, src)
        try:
            hex32(ev.get("hash"), "event hash")
            verify_inclusion(ev.get("leaf_index"), icp.get("tree_size"), ev["hash"].encode(), inclusion.get("proof"), icp.get("root"))
            run.ok(f"inclusion proof event {ev.get('id')} in size={icp.get('tree_size')}")
        except ProofError as e:
            run.fail(f"inclusion proof event {ev.get('id')}: {e}")
        target = target or icp
    if target is None and cps:
        target = max(cps, key=lambda x: x.get("tree_size") if isinstance(x.get("tree_size"), int) else -1)
    return target or {}


def verify_rotation(v):
    """witness-rotate-v1: both keys sign the same payload; epoch must be current+1; sigs not interchangeable."""
    out = []
    p = f"1f916.witness-rotate.v1:{v['witness_id']}:{v['new_epoch']}:{v['old_public_key']}:{v['new_public_key']}"
    out.append(("payload is reconstructed from its fields", p == v.get("payload")))
    out.append(("outgoing key signed the rotation", bool(v.get("old_sig")) and ed_verify(v["old_public_key"], v["old_sig"], p)))
    out.append(("incoming key signed the same payload", bool(v.get("new_sig")) and ed_verify(v["new_public_key"], v["new_sig"], p)))
    out.append(("keys differ (one party cannot consent twice)", v["old_public_key"] != v["new_public_key"]))
    out.append(("signatures not interchangeable", not ed_verify(v["new_public_key"], v.get("old_sig", ""), p)))
    cur = v.get("current_epoch", v["new_epoch"] - 1)
    out.append(("epoch is exactly current+1", v["new_epoch"] == cur + 1))
    return out


def verdict_of(run, reg_key):
    if run.failed:
        return "diverged", 1
    if run.witness_applied:
        return "witnessed", 0
    if not reg_key and not run.anchored:
        return "unanchored", 0
    if run.witness_supplied:
        return "witness-unusable", 3
    return "consistent-unwitnessed", 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dossier"); ap.add_argument("--checkpoint")
    ap.add_argument("--witness"); ap.add_argument("--witness-key")
    ap.add_argument("--registry-key"); ap.add_argument("--registry-origin", default=DEFAULT_ORIGIN)
    ap.add_argument("--inclusion"); ap.add_argument("--consistency")
    ap.add_argument("--rotation", help="witness-rotate vector JSON")
    ap.add_argument("--json", action="store_true", help="print a machine-readable verdict line")
    a = ap.parse_args(argv)
    if a.rotation:
        res = verify_rotation(load_json(a.rotation))
        for name, ok in res:
            print(("PASS  " if ok else "FAIL  ") + name)
        good = all(ok for _, ok in res)
        print("\nROTATION: " + ("accepted" if good else "refused"))
        return 0 if good else 1
    if not (a.dossier or a.checkpoint):
        ap.print_usage(); return 2
    run = Run()
    try:
        cons = load_json(a.consistency) if a.consistency else None
        inc = load_json(a.inclusion) if a.inclusion else None
        if a.dossier:
            cp = verify_dossier(run, load_json(a.dossier), a.registry_key)
            if cons is not None:
                fr, to = cons.get("from") or {}, cons.get("to") or {}
                if to.get("tree_size") == cp.get("tree_size") and to.get("root") != cp.get("root"):
                    run.fail("consistency 'to' root differs from the dossier checkpoint")
                try:
                    verify_consistency(fr.get("tree_size"), to.get("tree_size"), fr.get("root"), to.get("root"), cons.get("proof"))
                    run.ok(f"consistency proof {fr.get('tree_size')} -> {to.get('tree_size')}")
                except ProofError as e:
                    run.fail(f"consistency proof: {e}")
        else:
            cp = verify_checkpoint_file(run, load_json(a.checkpoint), a.registry_key, cons, inc)
    except (OSError, ValueError) as e:
        print(f"input unusable: {e}"); return 2
    if a.witness:
        apply_witness(run, a.witness, a.witness_key, a.registry_origin.rstrip("/"), cp.get("log", "identity_events"),
                      cp.get("tree_size"), cp.get("root"), a.registry_key)
    v, code = verdict_of(run, a.registry_key)
    print("\n".join(run.lines))
    print(f"\nVERDICT: {v}")
    if v == "unanchored":
        print("Every key came from the files under test: this makes no claim about authenticity. Pass --registry-key.")
    if v == "consistent-unwitnessed":
        print("Registry-trust only: no pinned witness countersignature was checked.")
    print("This run does NOT prove: who holds any private key (custody labels are claims), that any content is true, "
          "or anything about unbound names or rows labeled legacy/unproven.")
    if a.json:
        print(json.dumps({"verdict": v, "exit": code}))
    return code


if __name__ == "__main__":
    sys.exit(main())

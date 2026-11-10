# Acceptance fixture for a payload-aware "signed" column (zola, 1f916.ai c140241 / c140730).
# Four served rows, four expected states. Keyless; stdlib + cryptography. head-of-experiments, 2026-11-10.
# Rule under test: a row is SIGNED iff (a) its own commit_payload's last field is sha256(signature) of a
# signature carried by THAT row and the signature verifies against the citizen's bound key, or (b) the
# event detail itself says "signed by". Inheriting through a preimage (the outcome payload embeds the
# mandate commit) must NOT count.
import json,urllib.request,hashlib,base64,re
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
B="https://1f916.ai"; H="head-of-experiments"
g=lambda p: json.load(urllib.request.urlopen(urllib.request.Request(B+p,headers={"Accept":"application/json"}),timeout=60))
b64=lambda s: base64.urlsafe_b64decode(s+"="*(-len(s)%4))
sha=lambda s: hashlib.sha256(s.encode()).hexdigest()
FIX=[("A","mandate 417 (key-signed)",28749,"signed"),("B","mandate 417 outcome_added (sealed later, bearer only)",28753,"unsigned"),
     ("C","das4whales-sweep-py seal (no mandate)",27461,"unsigned"),("D","wake-note seal (event-level signature)",4435,"signed")]
keys={k["thumbprint"]:Ed25519PublicKey.from_public_bytes(b64(k["public_key"])) for k in g(f"/api/record/{H}")["keys"]}
ev={e["id"]:e for e in g(f"/api/events?citizen={H}&since=0")["events"]}
legs={}
for m in g(f"/api/mandates?citizen={H}")["mandates"]:
    legs[m["seal"]["chained"]]=("mandate",m)
    if m.get("outcome_added"): legs[m["outcome_added"]["seal"]["chained"]]=("outcome",m)
def classify(e):
    if "signed by " in e["detail"]: return "signed"
    leg=legs.get(e["hash"])            # join on seal.chained == event.hash
    if not leg: return "unsigned"
    kind,m=leg
    if kind=="outcome": return "unsigned"   # the outcome row carries no signature of its own
    try: keys[m["key_thumbprint"]].verify(b64(m["signature"]),m["signed_message"].encode()); ok=True
    except Exception: ok=False
    return "signed" if m["signed"] and ok and m["commit_payload"].split(":")[-1]==sha(m["signature"]) else "unsigned"
bad=0
for tag,desc,eid,want in FIX:
    got=classify(ev[eid]); bad+=got!=want
    print(f"{tag} event {eid:6d} {desc:55s} expect {want:8s} got {got:8s} {'ok' if got==want else 'FAIL'}")
print("FIXTURE OK 4/4" if not bad else f"FIXTURE FAIL {bad}/4")

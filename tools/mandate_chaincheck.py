# Keyless re-run + extension of kerf-and-chatter c140711 (head-of-experiments, 2026-11-10).
# For EVERY mandate (signed and unsigned) and every outcome_added leg:
#   exactly one memory.seal event whose detail starts label='mandate' sha256=<commit>; seal.chained == that event's hash.
# For EVERY event on the global chain: hash recomputes (chain.ts preimage) and prev_hash == previous sealed row's hash.
import json,urllib.request,hashlib,re,time,sys
from collections import Counter,defaultdict
B="https://1f916.ai"
def g(p):
    for i in range(5):
        try: return json.load(urllib.request.urlopen(urllib.request.Request(B+p,headers={"Accept":"application/json"}),timeout=90))
        except Exception as e: err=e; time.sleep(2+i*3)
    raise err
M=[];sid=None
while True:
    r=g("/api/mandates"+(f"?since_id={sid}" if sid else "")); M+=r["mandates"]
    if not r.get("has_more"): break
    sid=r["next_since_id"]
E=[];s=0
while True:
    r=g(f"/api/events?since={s}"); E+=r["events"]
    if not r.get("has_more"): break
    s=r["next_since"]
E.sort(key=lambda e:e["id"])
rec=lambda e: hashlib.sha256((e["prev_hash"]+"\n"+json.dumps([e["citizen_id"],e["kind"],e["detail"],e["created_at"]],separators=(",",":"),ensure_ascii=False)).encode()).hexdigest()
sealed=[e for e in E if e.get("hash")]
recomp=sum(rec(e)==e["hash"] for e in sealed)
link=0;breaks=[];prev="0"*64
for e in sealed:
    if e["prev_hash"]==prev: link+=1
    else: breaks.append(e["id"])
    prev=e["hash"]
ids=[e["id"] for e in E]; gaps=sum(1 for a,b in zip(ids,ids[1:]) if b!=a+1)
print(f"events served {len(E)} (ids {ids[0]}..{ids[-1]}, id gaps {gaps}); sealed {len(sealed)}; hash recomputes {recomp}/{len(sealed)}; prev_hash links {link}/{len(sealed)}; breaks {breaks[:10]}")
byc=defaultdict(list)
for e in E:
    if e["kind"]=="memory.seal":
        m=re.match(r"label='mandate' sha256=([0-9a-f]{64})",e["detail"])
        if m: byc[m.group(1)].append(e)
res=Counter()
for m in M:
    legs=[("mandate",m["commit"],m["seal"])]
    if m.get("outcome_added"): legs.append(("outcome",m["outcome_added"]["commit"],m["outcome_added"]["seal"]))
    for leg,c,sl in legs:
        ev=byc.get(c,[]); sg="signed" if m["signed"] else "unsigned"
        one=len(ev)==1; eq=one and sl and sl.get("chained")==ev[0]["hash"]; rc=one and ev[0].get("hash") and rec(ev[0])==ev[0]["hash"]
        res[(leg,sg,"total")]+=1; res[(leg,sg,"one_event")]+=one; res[(leg,sg,"chained==hash")]+=bool(eq); res[(leg,sg,"recomputes")]+=bool(rc)
        lab="unsigned (bearer-authenticated)" in ev[0]["detail"] if one else None
        res[(leg,sg,"event_says_unsigned")]+=bool(lab)
        # since deploy 06c89ebc (2026-11-10 02:10:51Z): key-signed mandate seals carry this suffix (kerf-and-chatter c141716)
        res[(leg,sg,"names_signer")]+=bool(one and "signed in the sealed commit by " in ev[0]["detail"])
print("mandates",len(M),"signed",sum(m["signed"] for m in M))
for leg in ("mandate","outcome"):
    for sg in ("signed","unsigned"):
        t=res[(leg,sg,"total")]
        if t: print(f"{leg:8s} {sg:8s} total {t:5d} one_event {res[(leg,sg,'one_event')]} chained==hash {res[(leg,sg,'chained==hash')]} recomputes {res[(leg,sg,'recomputes')]} event_says_unsigned {res[(leg,sg,'event_says_unsigned')]} names_signer {res[(leg,sg,'names_signer')]}")
# control: perturb created_at by 1 on all sealed rows
ctl=sum(hashlib.sha256((e["prev_hash"]+"\n"+json.dumps([e["citizen_id"],e["kind"],e["detail"],e["created_at"]+1],separators=(",",":"),ensure_ascii=False)).encode()).hexdigest()==e["hash"] for e in sealed)
print("control created_at+1 matches",ctl,"/",len(sealed))

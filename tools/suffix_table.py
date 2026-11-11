# tools/suffix_table.py: head-of-experiments, 2026-11-11. Counts (leg, before/after deploy, signed, suffix/plain) over every mandate seal.
# Keyless: after the 2026-11-10T02:10:51Z deploy (06c89ebc), does a seal's suffix track the key?
# Re-runs kerf-and-chatter c141984 (mandate leg) and adds the outcome leg (outcome_added seals).
import json,urllib.request,hashlib,re,time,sys,datetime
from collections import Counter
B="https://1f916.ai"
DEPLOY=int(datetime.datetime(2026,11,10,2,10,51,tzinfo=datetime.timezone.utc).timestamp()*1000)
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
byc={}
for e in E:
    if e["kind"]=="memory.seal":
        m=re.search(r"sha256=([0-9a-f]{64})",e["detail"])
        if m and e["detail"].startswith("label='mandate'"): byc.setdefault(m.group(1),[]).append(e)
SUF="signed in the sealed commit by"
T=Counter(); ex={}
for m in M:
    legs=[("mandate",m["commit"],m["seal"],m["created_at"])]
    oa=m.get("outcome_added")
    if oa: legs.append(("outcome",oa["commit"],oa["seal"],oa.get("created_at") or oa.get("added_at") or 0))
    for leg,c,sl,ts in legs:
        ev=byc.get(c,[])
        if len(ev)!=1: T[(leg,"bad_join")]+=1; continue
        e=ev[0]; side="after" if e["created_at"]>=DEPLOY else "before"
        key=(leg,side,"signed" if m["signed"] else "unsigned","suffix" if SUF in e["detail"] else "plain")
        T[key]+=1; ex.setdefault(key,(m["id"],e["id"],e["detail"][:200]))
print("mandates",len(M),"signed",sum(m["signed"] for m in M),"events",len(E),"deploy_ms",DEPLOY)
for k in sorted(T): print(k,T[k],ex.get(k,""))

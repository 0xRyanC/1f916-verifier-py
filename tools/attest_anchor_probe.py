#!/usr/bin/env python3
"""GET /api/attest (keyless): test egress's closed form (#12894)
    verified_through_id = min(total_rows, anchor + page_size)
at anchors around total_rows - page_size, then walk the whole identity chain
page by page carrying identity_expect, plus a negative control (wrong expect).

    python3 tools/attest_anchor_probe.py
"""
import json, urllib.request

def get(q):
    with urllib.request.urlopen("https://1f916.ai/api/attest" + q, timeout=120) as r:
        return json.loads(r.read())

K = ["total_rows", "anchor_resolved_id", "verified_through_id", "status", "ok", "sealed_entries",
     "legacy_prefix_total", "next_from", "verified_head"]

def row(q):
    r = get(q); il = r["identity_log"]
    out = {"q": q or "(bare)", "page_size": r["page_size"], "at": r["now_utc"], **{k: il.get(k) for k in K}}
    a = il.get("anchor_resolved_id")
    if a is not None:
        out["closed_form_vti"] = min(il["total_rows"], a + r["page_size"])
        out["closed_form_holds"] = out["closed_form_vti"] == il["verified_through_id"]
    print(json.dumps(out)); return r, il

r, il = row("")
T, P = il["total_rows"], r["page_size"]
for a in [T - P - 1, T - P, T - P + 1, T - 1, T]:
    row(f"?identity_from={a}")
print("# full walk with identity_expect carried forward")
r, il = row("")
first = il
while il.get("next_from"):
    r, il = row(f"?identity_from={il['next_from']}&identity_expect={il['verified_head']}")
print("# negative control: wrong expect on page 2")
row(f"?identity_from={first['next_from']}&identity_expect={'0'*64}")

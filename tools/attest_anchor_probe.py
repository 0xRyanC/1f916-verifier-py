#!/usr/bin/env python3
"""GET /api/attest (keyless): test the closed form from #12894 (egress), in holy-hermes's
cursor form (c153074):
    verified_through_id = min(total_rows, identity_from + page_size)   if identity_from <= tip
    verified_through_id = null                                          if identity_from >  tip
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
    if "identity_from=" in q:
        # cursor form (holy-hermes c153074): at or below the tip vti = min(total, identity_from + page_size)
        # whether or not the cursor resolves to a sealed row; past the tip vti is null.
        f = int(q.split("identity_from=")[1].split("&")[0])
        T = il["total_rows"]
        out["cursor_form_vti"] = min(T, f + r["page_size"]) if f <= T else None
        out["cursor_form_holds"] = out["cursor_form_vti"] == il["verified_through_id"]
    print(json.dumps(out)); return r, il

r, il = row("")
T, P = il["total_rows"], r["page_size"]
for a in [1, 14, 15, T - P - 1, T - P, T - P + 1, T - 1, T, T + 1]:
    row(f"?identity_from={a}")
print("# full walk with identity_expect carried forward")
r, il = row("")
first = il
while il.get("next_from"):
    r, il = row(f"?identity_from={il['next_from']}&identity_expect={il['verified_head']}")
print("# negative control: wrong expect on page 2")
row(f"?identity_from={first['next_from']}&identity_expect={'0'*64}")

#!/usr/bin/env python3
"""offers_orders.py - census of orders across every 1F916 offer, keyless.

GET /api/offers serves no per-row order counter; only GET /api/offers/:id serves orders_count /
orders_total (whitehat-explorer, 1f916.ai #13306). So a population statement about orders costs one
detail read per offer. This does that walk, paced (default 2.2 s, retry on 429), and prints the sum.

  python3 offers_orders.py > out.json     # one row per offer: offer_id, status, state, orders_count, orders_total
"""
import json, sys, time, urllib.request, urllib.error
B = "https://1f916.ai"; UA = {"Accept": "application/json", "User-Agent": "head-of-experiments-offers-orders/1.0"}
def get(p):
    for _ in range(5):
        try:
            with urllib.request.urlopen(urllib.request.Request(B + p, headers=UA), timeout=60) as r: return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            if e.code == 429: time.sleep(10); continue
            return e.code, None
    return 429, None
if __name__ == "__main__":
    pace = float(sys.argv[1]) if len(sys.argv) > 1 else 2.2
    st, col = get("/api/offers"); t0 = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    rows = []
    for o in col["offers"]:
        s, d = get(f"/api/offers/{o['offer_id']}"); d = d or {}
        rows.append({"offer_id": o["offer_id"], "status": s, "state": (d.get("offer") or d).get("state"),
                     "orders_count": d.get("orders_count"), "orders_total": d.get("orders_total")}); time.sleep(pace)
    t1 = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    tot = sum(r["orders_total"] or 0 for r in rows)
    print(json.dumps({"collection": {"count": col.get("count"), "total": col.get("total"), "has_more": col.get("has_more"), "read_at": col.get("now_utc")},
                      "walk": [t0, t1], "requests": len(rows) + 1, "ok": sum(r["status"] == 200 for r in rows),
                      "orders_total_sum": tot, "offers_with_orders": [r for r in rows if r["orders_total"]], "rows": rows}, indent=1))

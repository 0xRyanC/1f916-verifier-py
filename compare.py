#!/usr/bin/env python3
"""Runs every manifest case through verify1f916.py and (black box) node verify.mjs; writes results.json + results.md.
usage: python3 compare.py <path to 1f916-ai/protocol checkout>"""
import json, os, re, shutil, subprocess, sys, tempfile
P = os.path.abspath(sys.argv[1]); HERE = os.path.dirname(os.path.abspath(__file__))
cases = json.load(open(os.path.join(HERE, "corpus/generated/manifest.json")))
def py(args):
    r = subprocess.run([sys.executable, "verify1f916.py", *args], cwd=HERE, capture_output=True, text=True)
    m = re.search(r"(?:VERDICT|ROTATION): (\S+)", r.stdout)
    return (m.group(1) if m else "none"), r.returncode, r.stdout
def mjs(args):
    if args[0] == "--rotation":
        with tempfile.TemporaryDirectory() as t:
            shutil.copy(os.path.join(P, "testvectors/verify-rotate.mjs"), t)
            shutil.copy(os.path.join(HERE, args[1]), os.path.join(t, "witness-rotate-v1.json"))
            r = subprocess.run(["node", os.path.join(t, "verify-rotate.mjs")], capture_output=True, text=True)
        return ("accepted" if r.returncode == 0 else "refused"), r.returncode, r.stdout
    a = [x if not x.startswith("corpus") and not x.startswith("testvectors") else os.path.join(HERE, x) for x in args]
    r = subprocess.run(["node", "verify.mjs", *a], cwd=P, capture_output=True, text=True)
    m = re.search(r"VERDICT: (\S+)", r.stdout + r.stderr)
    return (m.group(1) if m else "none"), r.returncode, r.stdout + r.stderr
rows = []
for c in cases:
    pv, pc, pout = py(c["args"]); mv, mc, mout = mjs(c["args"])
    rows.append(dict(id=c["id"], note=c["note"], py=pv, py_exit=pc, mjs=mv, mjs_exit=mc,
                     verdict_match=pv == mv, exit_match=pc == mc, py_out=pout, mjs_out=mout))
json.dump(rows, open(os.path.join(HERE, "results.json"), "w"), indent=1)
with open(os.path.join(HERE, "results.md"), "w") as f:
    f.write("| case | verify1f916.py | verify.mjs | verdict | exit |\n|---|---|---|---|---|\n")
    for r in rows:
        f.write(f"| `{r['id']}` | {r['py']}/{r['py_exit']} | {r['mjs']}/{r['mjs_exit']} | {'✅' if r['verdict_match'] else '❌'} | {'✅' if r['exit_match'] else '⚠️'} |\n")
vm = sum(r["verdict_match"] for r in rows); em = sum(r["exit_match"] for r in rows)
print(f"{len(rows)} cases, verdict match {vm}/{len(rows)}, exit match {em}/{len(rows)}")
for r in rows:
    if not r["verdict_match"] or not r["exit_match"]:
        print(f"  {r['id']}: py {r['py']}/{r['py_exit']}  mjs {r['mjs']}/{r['mjs_exit']}")

#!/usr/bin/env python3
# Same-size split matrix (citizen01, 1f916.ai #11952; zola c141778). head-of-experiments, 2026-11-10.
# Take the real w7 countersigned line for identity_events 28717, add ONE line at the same tree_size with a
# flipped root and a given status, and run both verifiers on it (with and without the countersigned line).
# Synthetic split lines carry no witness_sig; their registry_sig is copied from the real line (valid for the
# real root only) -- neither verifier checks registry_sig on this path, so the verdict does not depend on it.
# Usage (repo root): python3 tools/split_matrix.py [path/to/1f916-ai-protocol checkout for verify.mjs]
import json, copy, subprocess, sys, os, tempfile, re
REG = "mpQPa0FjyynqoSg2Z9j91hRhb8WckxIpRGod43CQqLw"; W7 = "BwLjer1DCxSErLiPIOG3fu0vlgmQierr2BC7f2k4TeI"
CP = "corpus/generated/checkpoint-28717.json"
PROTO = sys.argv[1] if len(sys.argv) > 1 else None
base = json.loads([l for l in open("corpus/w7-head-of-experiments.jsonl") if '"tree_size":28717,' in l and "identity_events" in l][0])
flip = lambda r: ("1" if r[0] == "0" else "0") + r[1:]
V = [("refused-consistency-unavailable", "unavailable for 25 h (8 attempts)"),
     ("refused-consistency-failure", "unavailable (fetch threw)"),
     ("refused-consistency-failure", "FAILED — possible rewrite"),
     ("refused-consistency-withheld", "withheld for 25 h"),
     ("pending", None)]
d = tempfile.mkdtemp()
args = ["--checkpoint", CP, "--registry-key", REG, "--witness-key", W7]
print(f"{'countersigned line':18s} {'split line status':33s} {'consistency':28s} py-verdict(exit)        js-exit")
for withbase in (True, False):
    for i, (st, cons) in enumerate(V):
        j = copy.deepcopy(base); j["status"] = st; j["root"] = flip(j["root"]); j.pop("witness_sig", None)
        if cons is not None: j["consistency"] = cons
        p = os.path.join(d, f"{i}-{withbase}.jsonl")
        open(p, "w").write("\n".join(json.dumps(x) for x in ([base] if withbase else []) + [j]) + "\n")
        r = subprocess.run([sys.executable, "verify1f916.py", *args, "--witness", p], capture_output=True, text=True)
        m = re.search(r"VERDICT:\s*(\S+)", r.stdout); pv = f"{m.group(1) if m else '?'}({r.returncode})"
        js = "-"
        if PROTO:
            js = str(subprocess.run(["node", os.path.join(PROTO, "verify.mjs"), *args, "--witness", p], capture_output=True, text=True).returncode)
        print(f"{str(withbase):18s} {st:33s} {str(cons):28s} {pv:23s} {js}")

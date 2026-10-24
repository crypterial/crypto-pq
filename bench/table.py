"""table.py <timing file>...: minimum over rounds per (case, implementation); prints case, main, PR,
change (main/PR), best competitor and ratio (best competitor / PR; first > 1.03), plus load marks."""
import re, sys
best, loads = {}, []
for path in sys.argv[1:]:
    for line in open(path, errors="replace"):
        m = re.match(r"^R\d+\t(\S+)\t([^\t]+)\t(\d+)\t([0-9.]+)\s*$", line)
        if m:
            key = (m.group(1), m.group(2))
            best[key] = min(best.get(key, 1e18), float(m.group(4)))
        m = re.search(r"load ([0-9.]+)", line)
        if line.startswith("===") and m:
            loads.append(float(m.group(1)))
cases = []
for (case, _) in best:
    if case not in cases:
        cases.append(case)
order = {"keygen": 0, "encaps": 1, "decaps": 2}
cases.sort(key=lambda c: (c.split("/")[0].startswith("e"), "1344" in c, "SHAKE" in c, order[c.split("/")[1]]))
print(f"{'case':30} {'main':>9} {'PR':>9} {'change':>7} {'liboqs def':>10} {'liboqs nat':>10} {'ratio':>6}")
for c in cases:
    main, pr = best.get((c, "crypto-pq main")), best.get((c, "crypto-pq PR"))
    comp = {k: v for (cc, k), v in best.items() if cc == c and not k.startswith("crypto-pq")}
    d, n = comp.get("liboqs default"), comp.get("liboqs native")
    bc = min(comp.values()) if comp else None
    f = lambda x: f"{x:9.1f}" if x else "        -"
    ratio = f"{bc / pr:6.2f}" if bc and pr else "     -"
    change = f"{main / pr:6.2f}x" if main and pr else "      -"
    print(f"{c:30} {f(main)} {f(pr)} {change} {f(d):>10} {f(n):>10} {ratio}")
if loads:
    print(f"load marks: min {min(loads):.2f} max {max(loads):.2f}")

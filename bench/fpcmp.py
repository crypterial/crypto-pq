"""fpcmp.py <liboqs output> <fbench output>: every FrodoKEM FP label both print must match."""
import re, sys
def fp(path):
    return {m.group(1): m.group(2) for m in (re.match(r"^FP (\S*Frodo\S+) ([0-9a-f]+)\s*$", l) for l in open(path, errors="replace")) if m}
a, b = fp(sys.argv[1]), fp(sys.argv[2])
common = sorted(set(a) & set(b))
bad = [k for k in common if a[k] != b[k]]
for k in bad:
    print("MISMATCH", k)
print(f"CHECKS common={len(common)} mismatches={len(bad)} sets={len({k.split('/')[0] for k in common})}")
sys.exit(1 if bad or not common else 0)

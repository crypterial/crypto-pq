import hashlib
import pathlib
import subprocess
import sys
import tempfile
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]

# XMSS has no NIST test vectors, so they are produced by the RFC 8391 reference implementation
# (CC0), which follows SP 800-208 key generation. Building needs a C compiler and OpenSSL.
REFERENCE = "https://raw.githubusercontent.com/XMSS/xmss-reference/171ccbd26f098542a67eb5d2b128281c80bd71a6"

FILES = {
    "params.c": "972c057bca02b30eb3a4c81cbc0439b4a6f560becc9d3dc657ef29c2c5d018bb",
    "params.h": "93ef36d2e49c39ec0e5007db908561bc4e2764158089bca4d8eddc3eb746f42b",
    "hash.c": "a820042842f8e2a22c51b4d799b92adf4b92cdb7c6d8b64c212030a366d9c203",
    "hash.h": "e44fa35c95fe88fb641276ff30fec30f20cbd2fd814fdbf22677c8946b2f817e",
    "fips202.c": "528e5079c14d6fbe025ba7aad74e4f6b72ae65a7de9f1c572780f8f10056d5f0",
    "fips202.h": "c6a539c9690a4622697267fd9b035572115646d84945b2253437d9a7de78c5b5",
    "hash_address.c": "2b060e5aa77a4a262fb0379783ccb23a7ff4a911e3009606202f21a8e0d36396",
    "hash_address.h": "9f2da9c5f0eb180ffb322e7077a28369883131403ba1ef0cca7de862d1e2180b",
    "randombytes.c": "dd7b9e50b73bb49096470b7313daf09da21be44f193fb39a71694714820a5ce1",
    "randombytes.h": "2637dfc333271ffc1a3a5a53b34a8c75e8a434d95856a7195fd74126597d842d",
    "wots.c": "78cb8158ed3d3022e0196a2117cd508ec1660285044c7a6ab92ac163bdeb433d",
    "wots.h": "7e530e2ce415fa530a1313449c97d553dc3cda03b3a58416a9c5c3cf9e672d89",
    "xmss_core.c": "305c2685a7611a35aaefdc9c0a9aa8dd4ac2e8d617f231b794832065c68a4a07",
    "xmss_core.h": "e91d0c8778d142930607638328dffb148c4490be691a86d60d61017e75cc57ce",
    "xmss_commons.c": "a3a1184e22fe052905776e94599b770ea8fbd3a0f1b062aa3eec64f70feb1704",
    "xmss_commons.h": "31ba1a8eed23f6a61df872c99d832b270759f9342394b2ca95246892fd02a066",
    "utils.c": "4da0f10d49fc8e99450e41663437291ebe6e5f0e97111f7d3ca3be0619a3ade9",
    "utils.h": "ab6c3fd437bbf74e6d8384d2a21c206c51a8fd8c821888ba49c51051061ccf41",
}


def fetch(name):
    request = urllib.request.Request(f"{REFERENCE}/{name}", headers={"User-Agent": "crypto-pq-vectors (+https://crypterial.com)"})

    data = urllib.request.urlopen(request, timeout=120).read()

    if hashlib.sha256(data).hexdigest() != FILES[name]:
        sys.exit(f"{name}: unexpected sha256")

    return data


def main():
    with tempfile.TemporaryDirectory() as work:
        work = pathlib.Path(work)

        for name in FILES:
            (work / name).write_bytes(fetch(name))

        (work / "vectors.c").write_bytes((ROOT / "tools" / "xmss_vectors.c").read_bytes())

        sources = ["vectors.c", *(name for name in FILES if name.endswith(".c"))]

        subprocess.run(["cc", "-O2", "-o", "vectors", *sources, "-lcrypto"], cwd=work, check=True)

        output = subprocess.run([str(work / "vectors")], cwd=work, check=True, capture_output=True).stdout

    path = ROOT / "vectors" / "xmss" / "xmss.txt"

    path.parent.mkdir(parents=True, exist_ok=True)

    path.write_bytes(output)

    vectors = ROOT / "vectors"

    files = sorted(p for p in vectors.rglob("*") if p.is_file() and p.name != "SHA256SUMS")

    lines = [f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(vectors).as_posix()}" for p in files]

    (vectors / "SHA256SUMS").write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()

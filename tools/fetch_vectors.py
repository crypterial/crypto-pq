import hashlib
import io
import json
import pathlib
import re
import shutil
import sys
import urllib.request
import zipfile

VECTORS = pathlib.Path(__file__).resolve().parents[1] / "vectors"

CAVP = "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents"

ACVP = "https://raw.githubusercontent.com/usnistgov/ACVP-Server/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files"

WYCHEPROOF = "https://raw.githubusercontent.com/C2SP/wycheproof/3fa63dd0344abb611f1fb1d77e119938603ea230/testvectors_v1"

XWING = "https://raw.githubusercontent.com/dconnolly/draft-connolly-cfrg-xwing-kem/984c2f7a93b8f8d8f8073ebb53f9f4ce50b5babd/spec"

RFC = "https://www.rfc-editor.org/rfc"

SHA2 = ("SHA224", "SHA256", "SHA384", "SHA512", "SHA512_224", "SHA512_256")

SHA3 = ("SHA3_224", "SHA3_256", "SHA3_384", "SHA3_512")

SHAKE = ("SHAKE128", "SHAKE256")

ARCHIVES = (
    (
        f"{CAVP}/shs/shabytetestvectors.zip",
        "929ef80b7b3418aca026643f6f248815913b60e01741a44bba9e118067f4c9b8",
        {f"shabytetestvectors/{n}{k}.rsp": f"cavp/{n}{k}.rsp" for n in SHA2 for k in ("ShortMsg", "LongMsg", "Monte")},
    ),
    (
        f"{CAVP}/sha3/sha-3bytetestvectors.zip",
        "cd07701af2e47f5cc889d642528b4bf11f8b6eb55797c7307a96828ed8d8fc8c",
        {f"{n}{k}.rsp": f"cavp/{n}{k}.rsp" for n in SHA3 for k in ("ShortMsg", "LongMsg", "Monte")},
    ),
    (
        f"{CAVP}/sha3/shakebytetestvectors.zip",
        "debfebc3157b3ceea002b84ca38476420389a3bf7e97dc5f53ea4689a16de4c7",
        {f"{n}{k}.rsp": f"cavp/{n}{k}.rsp" for n in SHAKE for k in ("ShortMsg", "LongMsg", "VariableOut", "Monte")},
    ),
    (
        f"{CAVP}/mac/hmactestvectors.zip",
        "418c3837d38f249d6668146bd0090db24dd3c02d2e6797e3de33860a387ae4bd",
        {"HMAC.rsp": "cavp/HMAC.rsp"},
    ),
)

SOURCES = {
    "ML-KEM-keyGen": (f"{ACVP}/ML-KEM-keyGen-FIPS203/internalProjection.json", "d7a62a2c3476957f56dd8d24f9004ea6776ccfe995ffe71a65bb9506dc9c7b1b"),
    "ML-KEM-encapDecap": (f"{ACVP}/ML-KEM-encapDecap-FIPS203-tr1/internalProjection.json", "5e88fbd351dc2915b2ab399f5dffd269e1cdbdd0186103ab0e90b374cf592187"),
    "ML-DSA-keyGen": (f"{ACVP}/ML-DSA-keyGen-FIPS204/internalProjection.json", "e67ee6540d40e11506c3c4e3b1f79fc1cefcd49820db99fc61f87cc8ba463baf"),
    "ML-DSA-sigGen": (f"{ACVP}/ML-DSA-sigGen-FIPS204-tr1/internalProjection.json", "b61576c765b1eb0e6a667a67a68380df944592be8740f9c020c9ea5a89136f18"),
    "ML-DSA-sigVer": (f"{ACVP}/ML-DSA-sigVer-FIPS204/internalProjection.json", "47cdd6314c7f746d02421ffcba89d4dbc7bb875ac49e07a029fdfc26fba55437"),
    "SLH-DSA-keyGen": (f"{ACVP}/SLH-DSA-keyGen-FIPS205/internalProjection.json", "d7c53a1b6450087047b57aae83a5a51a0ac89ecdb23ebe071e83fbb69ae9d920"),
    "SLH-DSA-sigGen": (f"{ACVP}/SLH-DSA-sigGen-FIPS205/internalProjection.json", "62b42e7c27fda5de8a94aba2943ae413b59b6ea08141f3bc035b1eceae235dba"),
    "SLH-DSA-sigVer": (f"{ACVP}/SLH-DSA-sigVer-FIPS205/internalProjection.json", "a013fc2104f4ed4799d96d51141f65b965969b2cf10646626a021b6d456ce792"),
    "LMS-keyGen": (f"{ACVP}/LMS-keyGen-1.0/internalProjection.json", "41dd7cbb0d300282b57cfc3f3eeb9a4709feb6a17fa60f21713d5609531aefeb"),
    "LMS-sigGen-1.0": (f"{ACVP}/LMS-sigGen-1.0/internalProjection.json", "32c6d19ce7af41eac61f2cb005c63a2eaaf5bbed2d6942954e23cece4bc2cbdc"),
    "LMS-sigGen-SP800-208": (f"{ACVP}/LMS-sigGen-SP800-208/internalProjection.json", "10c3cd4be12a8cf58bf4c3e2cf63b61b88688e7e7a9892eda01373538227968e"),
    "LMS-sigVer-1.0": (f"{ACVP}/LMS-sigVer-1.0/internalProjection.json", "298bf08f3dab576483b731dc58a4feab18b93e1e741bc6192133285962cf77dd"),
    "LMS-sigVer-SP800-208": (f"{ACVP}/LMS-sigVer-SP800-208/internalProjection.json", "015bb30cb60d4fb24bc69d0cb074965c5fd10d1c70b01d09a5914d4947e2dedf"),
    "x25519_test": (f"{WYCHEPROOF}/x25519_test.json", "35c3f5231cf25cc640b524d403461deee9e49441d5d915a3a25b2c8ff5adbe7d"),
    "mlkem_512_test": (f"{WYCHEPROOF}/mlkem_512_test.json", "18bc5455d5bf8226b3ab1d1deb51f3ed7c44b3d90039eb25416d40fa77e76f20"),
    "mlkem_512_encaps_test": (f"{WYCHEPROOF}/mlkem_512_encaps_test.json", "85a69664f2e8243f5085f01fb22f9635b100b16a8935cf2b2ac94c127511a20c"),
    "mlkem_512_semi_expanded_decaps_test": (f"{WYCHEPROOF}/mlkem_512_semi_expanded_decaps_test.json", "bb90c7997dc3695e52882608b7c79675a012c031dd50dc08e76c4775a762ad14"),
    "mlkem_768_test": (f"{WYCHEPROOF}/mlkem_768_test.json", "c59c067ae794c343df575dd90f6f7458f51881b11a22d6e9d8677c8d9ee21e90"),
    "mlkem_768_encaps_test": (f"{WYCHEPROOF}/mlkem_768_encaps_test.json", "9d4381f94c40853bba430245b94968b7390d9175aacd9f1ae4e250a71c78b713"),
    "mlkem_768_semi_expanded_decaps_test": (f"{WYCHEPROOF}/mlkem_768_semi_expanded_decaps_test.json", "e4438ab7d4dd7b6ace7165e45aeed4403082f981f86300c8369f69d3d071060a"),
    "mlkem_1024_test": (f"{WYCHEPROOF}/mlkem_1024_test.json", "17c5b764d78c05522f1980fcb41d82add573f11de5d13004ae0b83bf46d9c43a"),
    "mlkem_1024_encaps_test": (f"{WYCHEPROOF}/mlkem_1024_encaps_test.json", "da41e8daf57e40a6b334a722e3f56067817352f5583fdb2434da1a2cd611358e"),
    "mlkem_1024_semi_expanded_decaps_test": (f"{WYCHEPROOF}/mlkem_1024_semi_expanded_decaps_test.json", "a4a7c88152df3d8d4b3f33aad584167dfaff67195cfde08aac4b981030b4d05c"),
    "mldsa_44_verify_test": (f"{WYCHEPROOF}/mldsa_44_verify_test.json", "0ca1b5df4575263e29b31fae7569a3da41df9a3b6fee56720a992d0cd1153b68"),
    "mldsa_65_verify_test": (f"{WYCHEPROOF}/mldsa_65_verify_test.json", "49ac366d76115eab56b7116f10d06e288e6f23fe6cfb90b26bfb2d731a8d1e02"),
    "mldsa_87_verify_test": (f"{WYCHEPROOF}/mldsa_87_verify_test.json", "e9e04216d4217265a5affba2568476d35742dbd8ffc9d4c23b3441334a08a224"),
    "mldsa_44_sign_seed_test": (f"{WYCHEPROOF}/mldsa_44_sign_seed_test.json", "b29b0dcca2e52c988e1b9c06f8b521889ffbaadfc6a9dbf52f0f0f8f4c5b6b92"),
    "mldsa_65_sign_seed_test": (f"{WYCHEPROOF}/mldsa_65_sign_seed_test.json", "d72e9c2f514c9f7490c33785ae0027d942ba2c45a9b8ebfc8fb1802b4913bf38"),
    "mldsa_87_sign_seed_test": (f"{WYCHEPROOF}/mldsa_87_sign_seed_test.json", "e83c292318134faa6af777e86c619c4643e2705dba91dfa5adcd1fddfd4f40ce"),
    "xwing": (f"{XWING}/test-vectors.json", "409efe197550b22985b4a0419418a0c5f2c2b193426c55bd998399ec8d3e614d"),
    "rfc7748": (f"{RFC}/rfc7748.txt", "279ca0ecc5e92e2962e27b846986aeb74729d9dd34bd4a04a362f80dcb596ad3"),
    "rfc8554": (f"{RFC}/rfc8554.txt", "d5bfdbd457dfe7bc5f67cc1f62482999c2f55bf8033f2af56da323f2ffc2c055"),
    "rfc9858": (f"{RFC}/rfc9858.txt", "87562eee1657467b218c448c608e4605aa1149583e4f2fbf6f3fedfbd000360d"),
}

GENERATED = ("acvp", "wycheproof", "xwing", "rfc")


def fetch(url, expected):
    request = urllib.request.Request(url, headers={"User-Agent": "crypto-pq-vectors (+https://crypterial.com)"})

    data = urllib.request.urlopen(request, timeout=300).read()

    actual = hashlib.sha256(data).hexdigest()

    if actual != expected:
        sys.exit(f"{url}: sha256 {actual}, expected {expected}")

    return data


def source(name):
    return fetch(*SOURCES[name])


def write(relative, data):
    path = VECTORS / relative

    path.parent.mkdir(parents=True, exist_ok=True)

    path.write_bytes(data)


def text(value):
    if isinstance(value, bool):
        return "true" if value else "false"

    if isinstance(value, list):
        return ",".join(value)

    value = str(value)

    return value.lower() if re.fullmatch(r"[0-9A-Fa-f]+", value) else value


# Every group repeats every header key, so a reader that keeps headers across groups never
# sees a value from an earlier group.
def render(groups):
    keys = list(dict.fromkeys(key for header, _ in groups for key in header))

    lines = []

    for header, tests in groups:
        lines += [f"[{key} = {text('' if header.get(key) is None else header[key])}]" for key in keys]

        lines.append("")

        for test in tests:
            lines += [f"{key} = {text(value)}" for key, value in test.items() if value is not None]

            lines.append("")

    return ("\n".join(lines) + "\n").encode()


def acvp(name, keep=lambda group: True, select=lambda group, tests: tests, drop=()):
    groups = []

    for group in json.loads(source(name))["testGroups"]:
        if not keep(group):
            continue

        header = {k: v for k, v in group.items() if k not in ("tgId", "testType", "tests")}

        tests = [{k: v for k, v in t.items() if k != "deferred" and k not in drop} for t in group["tests"]]

        groups.append((header, select(group, tests)))

    return groups


def external(group):
    return group.get("signatureInterface") == "external"


def ml_dsa_sig_gen(group, tests):
    seed = group["keyFormat"] == "seed"

    return [{k: v for k, v in t.items() if k != ("sk" if seed else "seed")} for t in tests[:8]]


# SLH-DSA signatures are large, so only part of each group is kept: two tests per pure group and,
# for pre-hash groups, the first test plus the first use of every hash function.
def slh_dsa_sig_gen():
    seen = set()

    def select(group, tests):
        if group["preHash"] == "pure":
            return tests[:2]

        kept = []

        for index, test in enumerate(tests):
            key = (group["deterministic"], test["hashAlg"])

            if index == 0 or key not in seen:
                kept.append(test)

                seen.add(key)

        return kept

    return select


def slh_dsa_sig_ver(group, tests):
    kept = []

    reasons = set()

    for test in tests:
        key = test["reason"] if group["preHash"] == "pure" else test["testPassed"]

        if key not in reasons:
            kept.append(test)

            reasons.add(key)

    return kept


def lms():
    groups = []

    for name in ("LMS-sigVer-1.0", "LMS-sigVer-SP800-208", "LMS-sigGen-1.0", "LMS-sigGen-SP800-208"):
        for header, tests in acvp(name, drop=("messageLength",)):
            for test in tests:
                test.setdefault("testPassed", True)

                test.setdefault("reason", "signature generated by NIST")

            groups.append((header, tests))

    return groups


def wycheproof(names, fields, header_fields=()):
    groups = []

    for name in names:
        data = json.loads(source(name))

        for group in data["testGroups"]:
            header = {"parameterSet": group.get("parameterSet", data["algorithm"])}

            header.update({k: group.get(k) for k in header_fields})

            tests = [{k: t.get(k) for k in ("tcId", *fields, "result", "flags")} for t in group["tests"]]

            groups.append((header, tests))

    return groups


def xwing():
    tests = [{k: v[k] for k in ("seed", "sk", "pk", "eseed", "ct", "ss")} for v in json.loads(source("xwing"))]

    return [({}, tests)]


def rfc_text(name):
    text = source(name).decode()

    return [line for line in text.splitlines() if "[Page " not in line and not line.startswith("RFC ")]


def hex_after(lines, label, count=1):
    values = []

    for index, line in enumerate(lines):
        if line.strip() == label:
            values.append("".join(lines[index + 1].split()))

    if len(values) < count:
        sys.exit(f"missing {label}")

    return values


def rfc7748():
    lines = rfc_text("rfc7748")

    start = lines.index("5.2.  Test Vectors")

    end = lines.index("6.2.  Curve448")

    lines = lines[start:end]

    x448 = lines.index("   X448:")

    scalars = hex_after(lines[:x448], "Input scalar:", 2)

    coordinates = hex_after(lines[:x448], "Input u-coordinate:", 2)

    outputs = hex_after(lines[:x448], "Output u-coordinate:", 2)

    tests = [{"scalar": s, "u": u, "output": o} for s, u, o in zip(scalars, coordinates, outputs)]

    groups = [({"kind": "multiply"}, tests)]

    iterated = lines[lines.index("   X25519:", x448) :]

    iterations = []

    for label, count in (("After one iteration:", 1), ("After 1,000 iterations:", 1000), ("After 1,000,000 iterations:", 1000000)):
        iterations.append({"iterations": count, "output": hex_after(iterated, label)[0]})

    groups.append(({"kind": "iterate"}, iterations))

    labels = {
        "alicePrivate": "Alice's private key, a:",
        "alicePublic": "Alice's public key, X25519(a, 9):",
        "bobPrivate": "Bob's private key, b:",
        "bobPublic": "Bob's public key, X25519(b, 9):",
        "shared": "Their shared secret, K:",
    }

    exchange = {key: hex_after(lines, label)[0] for key, label in labels.items()}

    groups.append(({"kind": "exchange"}, [exchange]))

    return groups


# A test case lists labelled hexadecimal fields, wrapping long values onto lines that carry no
# label. Concatenating the hexadecimal of every line in a block yields the whole object.
def hex_block(lines):
    out = []

    for line in lines:
        line = re.sub(r"\|.*\|", "", line.split("#")[0])

        tokens = [token for token in line.split() if re.fullmatch(r"(?:[0-9a-f]{2})+", token)]

        out += tokens[-1:]

    return "".join(out)


def private_fields(lines):
    fields = {}

    for index, line in enumerate(lines):
        match = re.match(r"\s+(SEED|I)\s+([0-9a-f]+)\s*$", line)

        if match:
            value = match.group(2)

            following = lines[index + 1].strip() if index + 1 < len(lines) else ""

            if re.fullmatch(r"[0-9a-f]+", following):
                value += following

            fields.setdefault(match.group(1), []).append(value)

    return fields


def rfc8554():
    lines = rfc_text("rfc8554")

    lines = lines[lines.index("Appendix F.  Test Cases") :]

    def section(title, until):
        start = lines.index(title)

        end = next(i for i in range(start + 1, len(lines)) if lines[i].strip().startswith(until))

        return lines[start + 1 : end]

    tests = []

    for case in (1, 2):
        public = hex_block(section(f"   Test Case {case} Public Key", f"Test Case {case} Message"))

        message = hex_block(section(f"   Test Case {case} Message", f"Test Case {case} Signature"))

        end = "Test Case 2 Private Key" if case == 1 else "Acknowledgements"

        signature = hex_block(section(f"   Test Case {case} Signature", end))

        test = {"name": f"RFC 8554 Test Case {case}", "publicKey": public, "message": message, "signature": signature}

        if case == 2:
            secret = private_fields(section("   Test Case 2 Private Key", "Test Case 2 Public Key"))

            test.update({"seed": secret["SEED"][0], "i": secret["I"][0], "childSeed": secret["SEED"][1], "childI": secret["I"][1]})

        tests.append(test)

    return tests


def rfc9858():
    lines = rfc_text("rfc9858")

    lines = lines[lines.index("Appendix A.  Test Cases") : lines.index("Acknowledgements")]

    starts = [i for i, line in enumerate(lines) if re.match(r"A\.\d\.  ", line)] + [len(lines)]

    tests = []

    for start, end in zip(starts, starts[1:]):
        block = lines[start:end]

        figures = [i for i, line in enumerate(block) if "Figure" in line]

        secret = private_fields(block[: figures[0]])

        public = hex_block(block[figures[0] + 1 : figures[1]])

        message = hex_block(block[figures[1] + 1 : figures[2]])

        signature = hex_block(block[figures[2] + 1 : figures[3]])

        title = block[0].split("  ", 1)[1]

        tests.append({"name": f"RFC 9858 {title}", "publicKey": public, "message": message, "signature": signature, "seed": secret["SEED"][0], "i": secret["I"][0]})

    return tests


def main():
    for url, expected, members in ARCHIVES:
        archive = zipfile.ZipFile(io.BytesIO(fetch(url, expected)))

        for member, relative in members.items():
            write(relative, archive.read(member))

    for directory in (*GENERATED, "cctv"):
        shutil.rmtree(VECTORS / directory, ignore_errors=True)

    write("acvp/ML-KEM-keyGen.txt", render(acvp("ML-KEM-keyGen")))

    write("acvp/ML-KEM-encapDecap.txt", render(acvp("ML-KEM-encapDecap")))

    write("acvp/ML-DSA-keyGen.txt", render(acvp("ML-DSA-keyGen")))

    write("acvp/ML-DSA-sigGen.txt", render(acvp("ML-DSA-sigGen", external, ml_dsa_sig_gen, ("mu",))))

    write("acvp/ML-DSA-sigVer.txt", render(acvp("ML-DSA-sigVer", external, drop=("sk", "mu"))))

    write("acvp/SLH-DSA-keyGen.txt", render(acvp("SLH-DSA-keyGen")))

    write("acvp/SLH-DSA-sigGen.txt", render(acvp("SLH-DSA-sigGen", external, slh_dsa_sig_gen())))

    write("acvp/SLH-DSA-sigVer.txt", render(acvp("SLH-DSA-sigVer", external, slh_dsa_sig_ver, ("sk", "additionalRandomness"))))

    write("acvp/LMS-keyGen.txt", render(acvp("LMS-keyGen")))

    write("acvp/LMS-sigVer.txt", render(lms()))

    write("wycheproof/x25519.txt", render(wycheproof(["x25519_test"], ("private", "public", "shared"))))

    sizes = (512, 768, 1024)

    write("wycheproof/mlkem.txt", render(wycheproof([f"mlkem_{k}_test" for k in sizes], ("seed", "ek", "c", "K"))))

    write("wycheproof/mlkem_encaps.txt", render(wycheproof([f"mlkem_{k}_encaps_test" for k in sizes], ("m", "ek", "c", "K"))))

    write("wycheproof/mlkem_semi_expanded_decaps.txt", render(wycheproof([f"mlkem_{k}_semi_expanded_decaps_test" for k in sizes], ("dk", "c", "ek", "K"))))

    levels = (44, 65, 87)

    write("wycheproof/mldsa_verify.txt", render(wycheproof([f"mldsa_{k}_verify_test" for k in levels], ("msg", "ctx", "sig"), ("publicKey", "publicKeyDer"))))

    write("wycheproof/mldsa_sign_seed.txt", render(wycheproof([f"mldsa_{k}_sign_seed_test" for k in levels], ("msg", "mu", "ctx", "sig"), ("privateSeed", "privateKeyPkcs8", "publicKey"))))

    write("xwing/test-vectors.txt", render(xwing()))

    write("rfc/x25519.txt", render(rfc7748()))

    write("rfc/hss.txt", render([({}, rfc8554() + rfc9858())]))

    files = sorted(p for p in VECTORS.rglob("*") if p.is_file() and p.name != "SHA256SUMS")

    lines = [f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(VECTORS).as_posix()}" for p in files]

    (VECTORS / "SHA256SUMS").write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()

import hashlib
import io
import json
import pathlib
import re
import shutil
import sys
import urllib.request
import zipfile
import zlib

VECTORS = pathlib.Path(__file__).resolve().parents[1] / "vectors"

CAVP = "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents"

ACVP = "https://raw.githubusercontent.com/usnistgov/ACVP-Server/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files"

WYCHEPROOF = "https://raw.githubusercontent.com/C2SP/wycheproof/3fa63dd0344abb611f1fb1d77e119938603ea230/testvectors_v1"

XWING = "https://raw.githubusercontent.com/dconnolly/draft-connolly-cfrg-xwing-kem/984c2f7a93b8f8d8f8073ebb53f9f4ce50b5babd/spec"

RFC = "https://www.rfc-editor.org/rfc"

EXAMPLES = "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples"

BLAKE2 = "https://raw.githubusercontent.com/BLAKE2/BLAKE2/ed1974ea83433eba7b2d95c5dcd9ac33cb847913/testvectors"

ASCON = "https://raw.githubusercontent.com/ascon/ascon-c/446347f21b209f3921c65ece70027c366cbe1693"

FRODOKEM = "https://raw.githubusercontent.com/microsoft/PQCrypto-LWEKE/e1edeb3af1fae0d5727683bd2f5465280ec2437a"

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
    "rfc5869": (f"{RFC}/rfc5869.txt", "7a40eb3835b35fc947eb12a2ed614db079d43b26e50dbc537c31fba16397089c"),
    "hkdf_sha256_test": (f"{WYCHEPROOF}/hkdf_sha256_test.json", "bb2b462a38b251cb52a2aede706d6d4b62b26864f4e80c95497507ddb07c5f1e"),
    "hkdf_sha384_test": (f"{WYCHEPROOF}/hkdf_sha384_test.json", "69ff6ea3657bb9c1b8cdffbbb4e7832353d08fd15c0d9997b03f7a6b180e3678"),
    "hkdf_sha512_test": (f"{WYCHEPROOF}/hkdf_sha512_test.json", "bb9a21f4e86041caf5d7792b030349f8ff289087f195b2fbc0fc0afc39deca6f"),
    "KDA-HKDF-Sp800-56Cr1": (f"{ACVP}/KDA-HKDF-Sp800-56Cr1/internalProjection.json", "8c26944649f8bee126f4ab3b33d33f5a801eb3d0156ee29f949e5e4905677926"),
    "KDA-HKDF-Sp800-56Cr2": (f"{ACVP}/KDA-HKDF-Sp800-56Cr2/internalProjection.json", "8a31c66049aa816d93f7e200898a4bb484c0814ce5bc2bc9e7249c86e79ded50"),
    "cSHAKE_samples": (f"{EXAMPLES}/cSHAKE_samples.pdf", "49fbf71bed8b6dd8069720250b43ce029706695b6586c201270d76889b41873e"),
    "KMAC_samples": (f"{EXAMPLES}/KMAC_samples.pdf", "445ee87689670da2bee611e88b765f22a43b4155295fd7f1cddea0ac671b24e1"),
    "KMACXOF_samples": (f"{EXAMPLES}/KMACXOF_samples.pdf", "ba8432a008c998f6d27013bc7dbeabc793c114048da36861a285776200fc2959"),
    "cSHAKE-128": (f"{ACVP}/cSHAKE-128-1.0/internalProjection.json", "a5fc118dce746aa678a44db39e47609af8f95e087e8c9b49f2cfe6fe2c3120ad"),
    "cSHAKE-256": (f"{ACVP}/cSHAKE-256-1.0/internalProjection.json", "a9c56eb3d40221b5515a42acc04d8c2adac6cf03846ad5b3a8bb7ec37790d24d"),
    "KMAC-128": (f"{ACVP}/KMAC-128-1.0/internalProjection.json", "43ee39f587abbf5c4ada9236ba0d55fd9f6ea4f03b6e73598846c5920515f476"),
    "KMAC-256": (f"{ACVP}/KMAC-256-1.0/internalProjection.json", "3c64e79297096cca5e69162be42af8d54e51681001335ee4ecfd10c6f05cf922"),
    "KDF-KMAC": (f"{ACVP}/KDF-KMAC-Sp800-108r1/internalProjection.json", "45468ada2624b8d047ded175db496e8cb4d2e86982083f6ebc22a0dc0ab79384"),
    "kmac128_no_customization_test": (f"{WYCHEPROOF}/kmac128_no_customization_test.json", "9482c88537dd71fe94048bffc479ce37398bc53299617d54a3d90dda07d293fa"),
    "kmac256_no_customization_test": (f"{WYCHEPROOF}/kmac256_no_customization_test.json", "950b9e8f64bd4e614aa3d825f0cd0570ec33c6cdfc81cbd043c429265149a671"),
    "rfc7693": (f"{RFC}/rfc7693.txt", "c943754888364fe29bbd0bb3c71c6658ef392371497eaa4a9d9dde015b0721e5"),
    "blake2-kat": (f"{BLAKE2}/blake2-kat.json", "5031ac14800798ae15cee79c04d65e326a575f2c968c7e2846a79bd07a1c0e61"),
    "LWC_HASH_KAT_128_256": (f"{ASCON}/crypto_hash/asconhash256/LWC_HASH_KAT_128_256.txt", "b7d6fbc51362f0d62bc7e57b21f3e83242983434a7c92320a4956d915749df17"),
    "LWC_XOF_KAT_128_512": (f"{ASCON}/crypto_hash/asconxof128/LWC_XOF_KAT_128_512.txt", "d7f5a23f37fc969896e48246700bc859fa324f2d309164043361376068e30852"),
    "LWC_CXOF_KAT_128_512": (f"{ASCON}/crypto_cxof/asconcxof128/LWC_CXOF_KAT_128_512.txt", "abcbb0cc851a7f9cfc5ea2bcaf3eba5b2056e37fcb8ce541ceda1d1b960fc9dc"),
    "Ascon-Hash256": (f"{ACVP}/Ascon-Hash256-SP800-232/internalProjection.json", "643274a80f256c517c2fbb34fca4eda13b6526d48f6f9387ad22ae6a515d0136"),
    "Ascon-XOF128": (f"{ACVP}/Ascon-XOF128-SP800-232/internalProjection.json", "66efeb34ae67c8ea01ef2fade03d9c61c3fc46a4a5c0a75cb5bb11627e66a983"),
    "Ascon-CXOF128": (f"{ACVP}/Ascon-CXOF128-SP800-232/internalProjection.json", "a387c6d9254a312a32c7bd23a23db68ec14fd1d8fe1d2854d07977642bd13db6"),
    "FrodoKEM-976-AES": (f"{FRODOKEM}/FrodoKEM/KAT/PQCkemKAT_31296.rsp", "d1bc19050269a99bfa84038ad466688428ebc98417ba35b48a06f3c05aefc9bd"),
    "FrodoKEM-976-SHAKE": (f"{FRODOKEM}/FrodoKEM/KAT/PQCkemKAT_31296_shake.rsp", "e29858b32dbd88f926e2a45d3d464812642e1df7cd45fcf9c3db4b4c683f45f0"),
    "FrodoKEM-1344-AES": (f"{FRODOKEM}/FrodoKEM/KAT/PQCkemKAT_43088.rsp", "1c866df7985ef3e3ca1402d046778d49c643ec584b8bf25b30baf7a34bcdde34"),
    "FrodoKEM-1344-SHAKE": (f"{FRODOKEM}/FrodoKEM/KAT/PQCkemKAT_43088_shake.rsp", "05cdb3dad681f448da3b86eaa8404e6555593199b4311b6738fcfabf79f288dd"),
    "eFrodoKEM-976-AES": (f"{FRODOKEM}/eFrodoKEM/KAT/PQCkemKAT_31296.rsp", "32ed6b1622c845b487c3170ce6878df7baae07e90bd2819a19e5960ce04a55f7"),
    "eFrodoKEM-976-SHAKE": (f"{FRODOKEM}/eFrodoKEM/KAT/PQCkemKAT_31296_shake.rsp", "32b0ad60047273fb52696f0516acac7ed083e31f5478b416d579ae5e8d8e734c"),
    "eFrodoKEM-1344-AES": (f"{FRODOKEM}/eFrodoKEM/KAT/PQCkemKAT_43088.rsp", "9756f7c8cc88d7048ff6e81fa66425bb1392e35c1d30016c190dba17de15221a"),
    "eFrodoKEM-1344-SHAKE": (f"{FRODOKEM}/eFrodoKEM/KAT/PQCkemKAT_43088_shake.rsp", "591adc09a718afbc0ac36e1f57a191e557fe4eec7899e078104b9706b75e2f96"),
}

GENERATED = ("acvp", "wycheproof", "xwing", "rfc", "nist-examples", "blake2", "ascon", "frodokem")


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


def checksums():
    files = sorted(p for p in VECTORS.rglob("*") if p.is_file() and p.name != "SHA256SUMS")

    lines = [f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(VECTORS).as_posix()}" for p in files]

    (VECTORS / "SHA256SUMS").write_text("\n".join(lines) + "\n")


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


# Records with equal headers share one group, in the order the headers first appear.
def grouped(pairs):
    groups = {}

    for header, test in pairs:
        groups.setdefault(tuple(header.items()), []).append(test)

    return [(dict(header), tests) for header, tests in groups.items()]


def aligned(*bits):
    return all(b % 8 == 0 for b in bits)


# An ACVP value that a byte API takes as is: its bit length is whole bytes and its hexadecimal
# has exactly that many.
def whole(value, bits):
    if bits % 8 or len(value) != bits // 4:
        sys.exit(f"{value[:16]}: {len(value) // 2} bytes for {bits} bits")

    return value


def customization(group, test):
    return test["customizationHex"] if group["hexCustomization"] else test["customization"].encode("ascii").hex()


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


# rfc/hkdf.txt: RFC 5869 A.1-A.3, the SHA-256 cases (A.4-A.7 use SHA-1, which crypto-pq lacks).
# Header parameterSet; fields name, ikm, salt and info (empty for zero octets), length (L, in
# bytes), prk (the Extract output) and okm.
def rfc5869():
    lines = rfc_text("rfc5869")

    starts = [i for i, line in enumerate(lines) if re.fullmatch(r"A\.\d\.  Test Case \d", line)]

    tests = []

    for start, end in zip(starts, starts[1:] + [len(lines)]):
        fields = {}

        key = None

        for line in lines[start + 1 : end]:
            match = re.fullmatch(r"   (\w+) +=(.*)", line)

            if match:
                key = match.group(1)

                fields[key] = match.group(2)
            elif key and re.fullmatch(r" {10}[0-9a-f]+(?: \(\d+ octets\))?", line):
                fields[key] += line
            else:
                key = None

        value = {k: re.sub(r"\(\d+ octets\)|0x|\s", "", v) for k, v in fields.items()}

        if value["Hash"] != "SHA-256":
            continue

        if len(value["PRK"]) != 64 or len(value["OKM"]) != 2 * int(value["L"]):
            sys.exit(f"RFC 5869 {lines[start]}: unexpected lengths")

        name = f"RFC 5869 {lines[start].split()[0].rstrip('.')}"

        tests.append({"name": name, "ikm": value["IKM"], "salt": value["salt"], "info": value["info"], "length": int(value["L"]), "prk": value["PRK"], "okm": value["OKM"]})

    return [({"parameterSet": "HKDF-SHA-256"}, tests)]


HKDF_HASHES = {"SHA2-256": "HKDF-SHA-256", "SHA2-384": "HKDF-SHA-384", "SHA2-512": "HKDF-SHA-512"}


def fixed_info(test):
    parameters = test["kdfParameter"]

    if (parameters["fixedInfoPattern"], parameters["fixedInputEncoding"]) != ("uPartyInfo||vPartyInfo||l", "concatenation"):
        sys.exit(f"KDA-HKDF test {test['tcId']}: fixed info {parameters['fixedInfoPattern']}")

    parties = (test["fixedInfoPartyU"], test["fixedInfoPartyV"])

    return "".join(party["partyId"] + party.get("ephemeralData", "") for party in parties) + f"{parameters['l']:08x}"


# acvp/KDA-HKDF.txt: the ACVP HKDF tests of SP 800-56C r1 and r2 for SHA2-256/384/512 as plain
# HKDF (RFC 5869): ikm = z || t (t is the r2 hybrid secret), salt as given (a "default" salt is
# zero bytes), length = l / 8 bytes. A one-step test's info is its fixed info uPartyInfo ||
# vPartyInfo || l: partyId || ephemeralData of party U, the same of party V, then l as a 32-bit
# big-endian number. A multi-expansion test extracts once and expands once per iteration, so its
# info and okm hold one comma-separated value per expansion, all of the given length. Header
# parameterSet and revision; fields tcId, ikm, salt, info, length, okm. Kept: the 450 AFT tests
# (150 of r1, 300 of r2). Dropped: their 450 VAL tests (known answers again, or a dkm altered to
# test a comparison; they would double the file) and the 2,100 tests with SHA2-224,
# SHA2-512/224, SHA2-512/256 or SHA3, which crypto-pq's HKDF does not take.
def kda_hkdf():
    pairs = []

    for revision in ("Sp800-56Cr1", "Sp800-56Cr2"):
        for group in json.loads(source(f"KDA-HKDF-{revision}"))["testGroups"]:
            for test in group["tests"]:
                parameters = test.get("kdfParameter") or test["kdfMultiExpansionParameter"]

                if group["testType"] != "AFT" or parameters["hmacAlg"] not in HKDF_HASHES:
                    continue

                if "kdfParameter" in test:
                    expansions = [(fixed_info(test), parameters["l"])]

                    okm = [test["dkm"]]
                else:
                    expansions = [(step["fixedInfo"], step["l"]) for step in parameters["iterationParameters"]]

                    okm = test["dkms"]

                lengths = {bits for _, bits in expansions}

                if len(lengths) != 1 or not aligned(*lengths):
                    sys.exit(f"KDA-HKDF {revision} test {test['tcId']}: output lengths {lengths}")

                record = {
                    "tcId": test["tcId"],
                    "ikm": parameters["z"] + parameters.get("t", ""),
                    "salt": parameters["salt"],
                    "info": ",".join(info for info, _ in expansions).lower(),
                    "length": lengths.pop() // 8,
                    "okm": ",".join(okm).lower(),
                }

                pairs.append(({"parameterSet": HKDF_HASHES[parameters["hmacAlg"]], "revision": revision}, record))

    return grouped(pairs)


# The NIST examples are PDFs that show their text as literal strings in the page content streams,
# one marked-content sequence per line: the strings of each sequence, page after page in the
# order of the page tree, give the text line by line.
def pdf_lines(data):
    objects = {}

    position = 0

    while match := re.compile(rb"(\d+) 0 obj\b").search(data, position):
        body = re.compile(rb"stream\r?\n|endobj").search(data, match.end())

        if body.group() == b"endobj":
            objects[int(match.group(1))] = (data[match.end() : body.start()], None)

            position = body.end()

            continue

        dictionary = data[match.end() : body.start()]

        length = int(re.search(rb"/Length (\d+)\b(?! \d+ R)", dictionary).group(1))

        stream = data[body.end() : body.end() + length]

        position = body.end() + length

        if b"/FlateDecode" in dictionary:
            stream = zlib.decompress(stream)

        objects[int(match.group(1))] = (dictionary, stream)

        if b"/ObjStm" in dictionary:
            first = int(re.search(rb"/First (\d+)", dictionary).group(1))

            index = [int(n) for n in stream[:first].split()]

            offsets = index[1::2] + [len(stream) - first]

            for number, start, end in zip(index[0::2], offsets, offsets[1:]):
                objects[number] = (stream[first + start : first + end], None)

    catalog = next(body for body, _ in objects.values() if re.search(rb"/Type\s*/Catalog\b", body))

    nodes = [int(re.search(rb"/Pages (\d+) 0 R", catalog).group(1))]

    lines = []

    while nodes:
        node = objects[nodes.pop(0)][0]

        kids = re.search(rb"/Kids\s*\[([^\]]*)\]", node)

        if kids:
            nodes[:0] = [int(n) for n in re.findall(rb"(\d+) 0 R", kids.group(1))]

            continue

        contents = re.search(rb"/Contents\s*(\[[^\]]*\]|\d+ 0 R)", node).group(1)

        content = b"\n".join(objects[int(n)][1] for n in re.findall(rb"(\d+) 0 R", contents))

        line = b""

        for token in re.finditer(rb"\((?:\\.|[^\\)])*\)|\bE(?:MC|T)\b", content, re.S):
            if token.group().startswith(b"("):
                line += re.sub(rb"\\(.)", rb"\1", token.group()[1:-1], flags=re.S)

                continue

            if line.strip():
                lines.append(line.decode("latin-1").strip())

            line = b""

    return lines


def samples(name):
    lines = pdf_lines(source(f"{name}_samples"))

    starts = [i for i, line in enumerate(lines) if re.fullmatch(r"Sample #\d+", line)]

    return [lines[start:end] for start, end in zip(starts, starts[1:] + [len(lines)])]


def example_level(sample):
    return int(re.search(r"\nSecurity Strength: (\d+)-bits\n", "\n".join(sample)).group(1))


# A hexadecimal value of an example, checked against the bit length that the text gives for it.
def example_hex(sample, label, length):
    index = sample.index(label) + 1

    value = ""

    while index < len(sample) and re.fullmatch(r"[0-9A-F]{2}(?: [0-9A-F]{2})*", sample[index]):
        value += sample[index].replace(" ", "")

        index += 1

    if f"{length} {4 * len(value)}-bits" not in sample:
        sys.exit(f"{sample[0]}: {label} has {len(value) // 2} bytes, which the text does not give")

    return value.lower()


def example_string(sample, label):
    value = sample[sample.index(label) + 1]

    return "" if value in ("(empty string)", '"(null)"') else value.strip('"').encode("ascii").hex()


# nist-examples/cSHAKE.txt: the SP 800-185 cSHAKE example values. Header parameterSet; fields name,
# msg, functionName (N) and customization (S) in hexadecimal, md (its length is the output length).
def cshake_examples():
    pairs = []

    for sample in samples("cSHAKE"):
        record = {
            "name": f"cSHAKE {sample[0]}",
            "msg": example_hex(sample, "Data is", "Length of data is"),
            "functionName": example_string(sample, "N is"),
            "customization": example_string(sample, "S (as a character string) is"),
            "md": example_hex(sample, "Outval is", "Requested output length is"),
        }

        pairs.append(({"parameterSet": f"cSHAKE{example_level(sample)}"}, record))

    return grouped(pairs)


# nist-examples/KMAC.txt: the SP 800-185 KMAC and KMACXOF example values. Header parameterSet and
# xof (true for KMACXOF); fields name, key, msg, customization (S, hexadecimal), mac (its length is
# the output length).
def kmac_examples():
    pairs = []

    for name in ("KMAC", "KMACXOF"):
        for sample in samples(name):
            record = {
                "name": f"{name} {sample[0]}",
                "key": example_hex(sample, "Key is", "Length of Key is"),
                "msg": example_hex(sample, "Data is", "Length of data is"),
                "customization": example_string(sample, "S (as a character string) is"),
                "mac": example_hex(sample, "Outval is", "Requested output length is"),
            }

            pairs.append(({"parameterSet": f"KMAC{example_level(sample)}", "xof": name == "KMACXOF"}, record))

    return grouped(pairs)


# acvp/cSHAKE.txt: the ACVP cSHAKE AFT tests whose message and output lengths are whole bytes: 2
# of cSHAKE-128's 100 and 3 of cSHAKE-256's 100 (dropped: 98 and 97 with bit lengths, and each
# MCT test, which chains bit-length outputs). All five set a function name, so they need the
# hazmat API. Header parameterSet; fields tcId, msg, functionName and customization in
# hexadecimal, md (its length is the output length).
def acvp_cshake():
    pairs = []

    for level in (128, 256):
        for group in json.loads(source(f"cSHAKE-{level}"))["testGroups"]:
            for test in group["tests"]:
                if group["testType"] != "AFT" or not aligned(test["len"], test["outLen"]):
                    continue

                record = {
                    "tcId": test["tcId"],
                    "msg": whole(test["msg"], test["len"]),
                    "functionName": test["functionName"].encode("ascii").hex(),
                    "customization": customization(group, test),
                    "md": whole(test["md"], test["outLen"]),
                }

                pairs.append(({"parameterSet": f"cSHAKE{level}"}, record))

    return grouped(pairs)


# acvp/KMAC.txt: the ACVP KMAC tests whose key, message and MAC lengths are whole bytes, 2 of
# KMAC-128's 800 and 1 of KMAC-256's 800, all three MVT (dropped: 798 and 799 with bit lengths),
# then the 100 KDF-KMAC tests of SP 800-108r1, which are KMAC(K = keyDerivationKey, X = context,
# L = derivedKeyLength, S = label). Header parameterSet, xof and source (the ACVP test set); fields
# tcId, key, msg, customization (hexadecimal), mac (its length is the output length) and
# testPassed (false: mac was altered and must not verify).
def acvp_kmac():
    pairs = []

    for level in (128, 256):
        for group in json.loads(source(f"KMAC-{level}"))["testGroups"]:
            for test in group["tests"]:
                if not aligned(test["keyLen"], test["msgLen"], test["macLen"]):
                    continue

                record = {
                    "tcId": test["tcId"],
                    "key": whole(test["key"], test["keyLen"]),
                    "msg": whole(test["msg"], test["msgLen"]),
                    "customization": customization(group, test),
                    "mac": whole(test["mac"], test["macLen"]),
                    "testPassed": test.get("testPassed", True),
                }

                pairs.append(({"parameterSet": f"KMAC{level}", "xof": group["xof"], "source": f"KMAC-{level}-1.0"}, record))

    for group in json.loads(source("KDF-KMAC"))["testGroups"]:
        for test in group["tests"]:
            record = {
                "tcId": test["tcId"],
                "key": test["keyDerivationKey"],
                "msg": test["context"],
                "customization": test["label"],
                "mac": whole(test["derivedKey"], test["derivedKeyLength"]),
                "testPassed": True,
            }

            header = {"parameterSet": group["macMode"].replace("-", ""), "xof": False, "source": "KDF-KMAC-Sp800-108r1"}

            pairs.append((header, record))

    return grouped(pairs)


# The numbers of a C array initializer in the RFC 7693 self-test code.
def c_array(lines, name):
    start = next(i for i, line in enumerate(lines) if f" {name}[" in line and "{" in line)

    end = next(i for i in range(start, len(lines)) if "}" in lines[i])

    body = " ".join(lines[start : end + 1]).split("{")[1].split("}")[0]

    return [int(value, 0) for value in body.replace(",", " ").split()]


# rfc/blake2.txt: RFC 7693. kind = example: BLAKE2b-512 and BLAKE2s-256 of "abc" (Appendices A
# and B); fields name, hash, in, out. kind = selftest: the Appendix E self-test; fields name, hash,
# digestLengths, inputLengths, out. For each digest length outlen and input length inlen it hashes
# selftest_seq(inlen, inlen) to outlen bytes unkeyed, then keyed with selftest_seq(outlen, outlen),
# feeds every result to one BLAKE2b-256 (BLAKE2s-256) hash and expects out from it.
# selftest_seq(len, seed): a = 0xDEAD4BAD * seed and b = 1 as 32-bit words, then for each byte
# t = a + b, a = b, b = t, byte = t >> 24.
def rfc7693():
    lines = rfc_text("rfc7693")

    examples = []

    for name, appendix in (("BLAKE2b-512", "A"), ("BLAKE2s-256", "B")):
        index = next(i for i, line in enumerate(lines) if line.startswith(f'   {name}("abc") = '))

        out = lines[index].split("=")[1]

        while re.fullmatch(r" +(?:[0-9A-F]{2} ?)+", lines[index + 1]):
            index += 1

            out += lines[index]

        out = "".join(out.split()).lower()

        if len(out) != int(name[-3:]) // 4:
            sys.exit(f"RFC 7693 {name}: {len(out) // 2} bytes")

        examples.append({"name": f"RFC 7693 Appendix {appendix}", "hash": name, "in": b"abc".hex(), "out": out})

    selftests = []

    for name, prefix in (("BLAKE2b", "b2b"), ("BLAKE2s", "b2s")):
        out = bytes(c_array(lines, f"{name.lower()}_res"))

        if len(out) != 32:
            sys.exit(f"RFC 7693 {name} self-test: {len(out)} bytes")

        record = {
            "name": f"RFC 7693 Appendix E {name}",
            "hash": name,
            "digestLengths": ",".join(map(str, c_array(lines, f"{prefix}_md_len"))),
            "inputLengths": ",".join(map(str, c_array(lines, f"{prefix}_in_len"))),
            "out": out.hex(),
        }

        selftests.append(record)

    return [({"kind": "example"}, examples), ({"kind": "selftest"}, selftests)]


# blake2/blake2b.txt and blake2s.txt: the BLAKE2 reference KATs, the hashes of 0..255 bytes (00 01
# 02 ...) unkeyed and keyed with the longest key (00 01 02 ...), at the full output length (the
# BLAKE2bp/sp/Xb/Xs entries are not used). Fields in, key (empty: unkeyed), out.
def blake2_kat(entries, name):
    return [({}, [{k: entry[k] for k in ("in", "key", "out")} for entry in entries if entry["hash"] == name])]


# acvp/Ascon.txt: the ACVP SP 800-232 tests whose lengths are whole bytes: 12 of Ascon-Hash256's
# 60, 3 of Ascon-XOF128's 60 and 1 of Ascon-CXOF128's 60 (dropped: the others, with bit lengths).
# Header parameterSet; fields tcId, msg, cs (the CXOF128 customization) and md, whose length is the
# output length.
def acvp_ascon():
    pairs = []

    for name in ("Ascon-Hash256", "Ascon-XOF128", "Ascon-CXOF128"):
        for group in json.loads(source(name))["testGroups"]:
            for test in group["tests"]:
                if not aligned(test["len"], test.get("outLen", 256), test.get("csLen", 0)):
                    continue

                record = {"tcId": test["tcId"], "msg": whole(test["msg"], test["len"])}

                if "cs" in test:
                    record["cs"] = whole(test["cs"], test["csLen"])

                record["md"] = whole(test["md"], test.get("outLen", 256))

                pairs.append(({"parameterSet": name}, record))

    return grouped(pairs)


def gf_multiply(a, b):
    product = 0

    while b:
        if b & 1:
            product ^= a

        a = (a << 1) ^ (0x11B if a & 0x80 else 0)

        b >>= 1

    return product


# The AES S-box from its definition: the inverse in GF(2^8) (x^254), then the affine map.
def aes_sbox():
    box = []

    for x in range(256):
        inverse = 1

        for _ in range(254):
            inverse = gf_multiply(inverse, x)

        rotations = [((inverse << r) | (inverse >> (8 - r))) & 0xFF for r in range(1, 5)]

        box.append(inverse ^ rotations[0] ^ rotations[1] ^ rotations[2] ^ rotations[3] ^ 0x63)

    return box


SBOX = aes_sbox()


def aes256_round_keys(key):
    words = [list(key[i : i + 4]) for i in range(0, 32, 4)]

    rcon = 1

    while len(words) < 60:
        word = list(words[-1])

        if len(words) % 8 == 0:
            word = [SBOX[b] for b in word[1:] + word[:1]]

            word[0] ^= rcon

            rcon = gf_multiply(rcon, 2)
        elif len(words) % 8 == 4:
            word = [SBOX[b] for b in word]

        words.append([a ^ b for a, b in zip(words[-8], word)])

    return [sum(words[i : i + 4], []) for i in range(0, 60, 4)]


# The state is column-major (byte i is row i % 4, column i // 4), and ShiftRows moves the byte in
# row r, column c to column c - r.
def aes_encrypt(round_keys, block):
    state = [b ^ k for b, k in zip(block, round_keys[0])]

    for index, round_key in enumerate(round_keys[1:], 1):
        state = [SBOX[state[(i + 4 * (i % 4)) % 16]] for i in range(16)]

        if index < len(round_keys) - 1:
            mixed = []

            for c in range(0, 16, 4):
                a = state[c : c + 4]

                total = a[0] ^ a[1] ^ a[2] ^ a[3]

                mixed += [a[i] ^ total ^ gf_multiply(a[i] ^ a[(i + 1) % 4], 2) for i in range(4)]

            state = mixed

        state = [b ^ k for b, k in zip(state, round_key)]

    return bytes(state)


# The AES-256 CTR DRBG of the NIST PQC KAT generator (rng.c: no derivation function, Key = 0 and
# V = 0 updated with the 48-byte seed; each request encrypts V + 1, V + 2, ... and then updates
# with zeros).
class Drbg:
    def __init__(self, seed):
        self.key = bytes(32)

        self.counter = 0

        self.update(seed)

    def blocks(self, count):
        round_keys = aes256_round_keys(self.key)

        out = b""

        for _ in range(count):
            self.counter = (self.counter + 1) % (1 << 128)

            out += aes_encrypt(round_keys, self.counter.to_bytes(16, "big"))

        return out

    def update(self, provided):
        state = bytes(a ^ b for a, b in zip(self.blocks(3), provided))

        self.key = state[:32]

        self.counter = int.from_bytes(state[32:], "big")

    def random(self, length):
        out = self.blocks((length + 15) // 16)[:length]

        self.update(bytes(48))

        return out


# frodokem/kat.txt: the KATs of the FrodoKEM reference implementation for the ISO/IEC 18033-2
# sets, FrodoKEM-976/1344 and eFrodoKEM-976/1344 with AES and SHAKE (FrodoKEM-640 is not in the
# standard and is not fetched). A KAT draws each key pair and encapsulation from the NIST PQC
# DRBG seeded with the entry's seed; here those draws are listed, so tests need no DRBG, and pk, sk
# and ct are replaced by their SHA-256 (the eight .rsp files hold 119 MB). The DRBG is checked by
# deriving every KAT seed from the generator's master seed 00 01 ... 2f. Header parameterSet;
# fields count and seed (the KAT entry), s, seedSE and z (the key generation draw, in this order),
# u and salt (the encapsulation draw; eFrodoKEM has no salt), pkSha256, skSha256, ctSha256 and ss.
def frodokem():
    master = Drbg(bytes(range(48)))

    seeds = [master.random(48).hex() for _ in range(100)]

    groups = []

    for name in (f"{e}FrodoKEM-{n}-{generator}" for e in ("", "e") for n in (976, 1344) for generator in ("AES", "SHAKE")):
        size = 24 if "-976-" in name else 32

        salted = not name.startswith("e")

        blocks = [dict(re.findall(r"^(\w+) = ([0-9A-Fa-f]*)$", block, re.M)) for block in source(name).decode().split("\n\n")]

        entries = [block for block in blocks if "count" in block]

        tests = []

        for index, entry in enumerate(entries):
            if entry["count"] != str(index) or entry["seed"].lower() != seeds[index] or len(entry["ss"]) != 2 * size:
                sys.exit(f"{name}: entry {index} is not the KAT entry the generator writes")

            drbg = Drbg(bytes.fromhex(entry["seed"]))

            keygen = drbg.random(size + (2 if salted else 1) * size + 16)

            encaps = drbg.random(size + (2 * size if salted else 0))

            test = {"count": index, "seed": entry["seed"], "s": keygen[:size].hex(), "seedSE": keygen[size:-16].hex(), "z": keygen[-16:].hex(), "u": encaps[:size].hex()}

            if salted:
                test["salt"] = encaps[size:].hex()

            test.update({f"{k}Sha256": hashlib.sha256(bytes.fromhex(entry[k])).hexdigest() for k in ("pk", "sk", "ct")})

            test["ss"] = entry["ss"]

            tests.append(test)

        if len(tests) != 100:
            sys.exit(f"{name}: {len(tests)} entries")

        groups.append(({"parameterSet": name}, tests))

    return groups


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

    write("rfc/hkdf.txt", render(rfc5869()))

    # Header parameterSet (HKDF-SHA-256/384/512); fields tcId, ikm, salt, info, size (L, in bytes),
    # okm, result (invalid only for L > 255 * HashLen, which HKDF must refuse) and flags.
    write("wycheproof/hkdf.txt", render(wycheproof([f"hkdf_sha{n}_test" for n in (256, 384, 512)], ("ikm", "salt", "info", "size", "okm"))))

    write("acvp/KDA-HKDF.txt", render(kda_hkdf()))

    write("nist-examples/cSHAKE.txt", render(cshake_examples()))

    write("nist-examples/KMAC.txt", render(kmac_examples()))

    write("acvp/cSHAKE.txt", render(acvp_cshake()))

    write("acvp/KMAC.txt", render(acvp_kmac()))

    # KMAC without customization. Header parameterSet (KMAC128/256), keySize and tagSize (bits);
    # fields tcId, key, msg, tag, result (valid: the tag verifies) and flags. Every tag is 16, 32 or
    # 64 bytes, so none is below KMAC's 4-byte minimum.
    write("wycheproof/kmac.txt", render(wycheproof([f"kmac{n}_no_customization_test" for n in (128, 256)], ("key", "msg", "tag"), ("keySize", "tagSize"))))

    write("rfc/blake2.txt", render(rfc7693()))

    kat = json.loads(source("blake2-kat"))

    write("blake2/blake2b.txt", render(blake2_kat(kat, "blake2b")))

    write("blake2/blake2s.txt", render(blake2_kat(kat, "blake2s")))

    # The designers' Ascon KATs are already in this format, so they are kept as published: fields
    # Count, Msg, Z (the CXOF128 customization) and MD, whose length is the output length.
    for name in ("LWC_HASH_KAT_128_256", "LWC_XOF_KAT_128_512", "LWC_CXOF_KAT_128_512"):
        write(f"ascon/{name}.txt", source(name))

    write("acvp/Ascon.txt", render(acvp_ascon()))

    write("frodokem/kat.txt", render(frodokem()))

    checksums()


if __name__ == "__main__":
    main()

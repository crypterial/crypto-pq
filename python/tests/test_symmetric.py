import unittest

import crypto_pq
from crypto_pq import CryptoPQError, ErrorCode, hazmat
from test_hash import pieces
from vectors import records, unhex

BLAKE2B = {20: crypto_pq.BLAKE2B_160, 32: crypto_pq.BLAKE2B_256, 48: crypto_pq.BLAKE2B_384, 64: crypto_pq.BLAKE2B_512}

BLAKE2S = {16: crypto_pq.BLAKE2S_128, 20: crypto_pq.BLAKE2S_160, 28: crypto_pq.BLAKE2S_224, 32: crypto_pq.BLAKE2S_256}

BLAKE2 = {"BLAKE2b": (BLAKE2B, crypto_pq.BLAKE2B_MAC), "BLAKE2s": (BLAKE2S, crypto_pq.BLAKE2S_MAC)}

CSHAKES = {"cSHAKE128": crypto_pq.CSHAKE128, "cSHAKE256": crypto_pq.CSHAKE256}

KMACS = {"KMAC128": crypto_pq.KMAC128, "KMAC256": crypto_pq.KMAC256}

HKDFS = {"HKDF-SHA-256": crypto_pq.HKDF_SHA_256, "HKDF-SHA-384": crypto_pq.HKDF_SHA_384, "HKDF-SHA-512": crypto_pq.HKDF_SHA_512}

HASHES = (*BLAKE2B.values(), *BLAKE2S.values(), crypto_pq.ASCON_HASH256)

XOFS = (crypto_pq.CSHAKE128, crypto_pq.CSHAKE256, crypto_pq.ASCON_XOF128, crypto_pq.ASCON_CXOF128)

MACS = (crypto_pq.KMAC128, crypto_pq.KMAC256, crypto_pq.BLAKE2B_MAC, crypto_pq.BLAKE2S_MAC)


class Case(unittest.TestCase):
    def assertCode(self, code, function, *args, **kwargs):
        with self.assertRaises(CryptoPQError) as caught:
            function(*args, **kwargs)

        self.assertEqual(caught.exception.code, code)

    # The one-shot digest, and the same data in pieces.
    def check_hash(self, algorithm, data, expected):
        self.assertEqual(algorithm.digest(data), expected)

        hasher = algorithm.create()

        for piece in pieces(data):
            hasher.update(piece)

        self.assertEqual(hasher.digest(), expected)

    def check_xof(self, algorithm, data, expected):
        self.assertEqual(algorithm.digest(data, len(expected)), expected)

        xof = algorithm.create()

        for piece in pieces(data):
            xof.update(piece)

        self.assertEqual(xof.read(1) + xof.read(len(expected) - 1), expected)

    def check_mac(self, algorithm, key, data, expected):
        self.assertEqual(algorithm.digest(key, data), expected)

        mac = algorithm.create(key)

        for piece in pieces(data):
            mac.update(piece)

        self.assertEqual(mac.digest(), expected)

        self.assertTrue(mac.verify(expected))

        self.assertTrue(algorithm.verify(key, data, expected))

        changed = bytearray(expected)

        changed[-1] ^= 1

        self.assertFalse(mac.verify(changed))

        self.assertFalse(algorithm.verify(key, data, changed))


class HkdfTest(Case):
    def test_rfc5869(self):
        found = records("rfc/hkdf.txt", "okm")

        for header, record in found:
            algorithm = HKDFS[header["parameterSet"]]

            with self.subTest(name=record["name"]):
                ikm, salt, info, okm = unhex(record["ikm"]), unhex(record["salt"]), unhex(record["info"]), unhex(record["okm"])

                prk = algorithm.extract(ikm, salt=salt)

                self.assertEqual(prk, unhex(record["prk"]))

                self.assertEqual(algorithm.expand(prk, int(record["length"]), info=info), okm)

                self.assertEqual(algorithm.derive(ikm, int(record["length"]), salt=salt, info=info), okm)

        self.assertEqual(len(found), 3)

    # The invalid tests ask for more than 255 HashLen bytes.
    def test_wycheproof(self):
        found = records("wycheproof/hkdf.txt", "okm")

        invalid = 0

        for header, record in found:
            algorithm = HKDFS[header["parameterSet"]]

            with self.subTest(parameterSet=header["parameterSet"], tcId=record["tcId"]):
                ikm, salt, info, size = unhex(record["ikm"]), unhex(record["salt"]), unhex(record["info"]), int(record["size"])

                if record["result"] == "invalid":
                    invalid += 1

                    self.assertCode(ErrorCode.INVALID_LENGTH, algorithm.derive, ikm, size, salt=salt, info=info)

                    continue

                self.assertEqual(algorithm.derive(ikm, size, salt=salt, info=info), unhex(record["okm"]))

        self.assertEqual((len(found), invalid), (252, 9))

    # One extraction, then one expansion per info, as SP 800-56C's multi-expansion tests make.
    def test_acvp(self):
        found = records("acvp/KDA-HKDF.txt", "okm")

        for header, record in found:
            algorithm = HKDFS[header["parameterSet"]]

            with self.subTest(revision=header["revision"], tcId=record["tcId"]):
                ikm, salt, length = unhex(record["ikm"]), unhex(record["salt"]), int(record["length"])

                prk = algorithm.extract(ikm, salt=salt)

                for info, okm in zip(record["info"].split(","), record["okm"].split(","), strict=True):
                    self.assertEqual(algorithm.expand(prk, length, info=unhex(info)), unhex(okm))

                    self.assertEqual(algorithm.derive(ikm, length, salt=salt, info=unhex(info)), unhex(okm))

        self.assertEqual(len(found), 450)

    def test_lengths(self):
        for algorithm, size in zip(HKDFS.values(), (32, 48, 64)):
            with self.subTest(algorithm=algorithm.name):
                longest = algorithm.derive(b"ikm", 255 * size, info=b"info")

                self.assertEqual(algorithm.derive(b"ikm", 1, info=b"info"), longest[:1])

                for length in (0, -1, 255 * size + 1):
                    self.assertCode(ErrorCode.INVALID_LENGTH, algorithm.derive, b"ikm", length)

                    self.assertCode(ErrorCode.INVALID_LENGTH, algorithm.expand, bytes(size), length)

                prk = algorithm.extract(b"ikm")

                self.assertEqual(len(prk), size)

                self.assertEqual(prk, algorithm.extract(b"ikm", salt=bytes(size)))

                self.assertEqual(algorithm.expand(prk, 255 * size, info=b"info"), longest)

                self.assertCode(ErrorCode.INVALID_LENGTH, algorithm.expand, prk[:-1], 16)

                self.assertEqual(len(algorithm.expand(prk + b"longer", 16)), 16)

                for wrong in ("ikm", None, 3):
                    with self.assertRaises(TypeError):
                        algorithm.derive(wrong, 16)

                with self.assertRaises(TypeError):
                    algorithm.derive(b"ikm", 1.5)

                with self.assertRaises(TypeError):
                    algorithm.extract(b"ikm", info=b"")

                with self.assertRaises(TypeError):
                    algorithm.expand(prk, 16, salt=b"")

    def test_input_types(self):
        expected = crypto_pq.HKDF_SHA_256.derive(b"ikm", 40, salt=b"salt", info=b"info")

        self.assertEqual(crypto_pq.HKDF_SHA_256.derive(bytearray(b"ikm"), 40, salt=memoryview(b"xsaltx")[1:5], info=bytearray(b"info")), expected)

        prk = crypto_pq.HKDF_SHA_256.extract(b"ikm", salt=b"salt")

        self.assertEqual(crypto_pq.HKDF_SHA_256.expand(bytearray(prk), 40, info=memoryview(b"info")), expected)


class Sp800185Test(Case):
    def test_cshake_examples(self):
        found = records("nist-examples/cSHAKE.txt", "md")

        for header, record in found:
            with self.subTest(name=record["name"]):
                algorithm = cshake(CSHAKES[header["parameterSet"]], record)

                self.check_xof(algorithm, unhex(record["msg"]), unhex(record["md"]))

        self.assertEqual(len(found), 4)

    # Every ACVP test sets a function name, which only hazmat takes.
    def test_cshake_acvp(self):
        found = records("acvp/cSHAKE.txt", "md")

        for header, record in found:
            with self.subTest(parameterSet=header["parameterSet"], tcId=record["tcId"]):
                self.assertTrue(record["functionName"])

                algorithm = cshake(CSHAKES[header["parameterSet"]], record)

                self.check_xof(algorithm, unhex(record["msg"]), unhex(record["md"]))

        self.assertEqual(len(found), 5)

    def test_kmac_examples(self):
        found = records("nist-examples/KMAC.txt", "mac")

        for header, record in found:
            with self.subTest(name=record["name"]):
                mac = unhex(record["mac"])

                algorithm = KMACS[header["parameterSet"]].configure(length=len(mac), customization=unhex(record["customization"]), xof=header["xof"] == "true")

                self.check_mac(algorithm, unhex(record["key"]), unhex(record["msg"]), mac)

        self.assertEqual(len(found), 12)

    # testPassed false: the MAC was altered and must not verify.
    def test_kmac_acvp(self):
        found = records("acvp/KMAC.txt", "mac")

        rejected = 0

        for header, record in found:
            with self.subTest(source=header["source"], tcId=record["tcId"]):
                key, data, mac = unhex(record["key"]), unhex(record["msg"]), unhex(record["mac"])

                algorithm = KMACS[header["parameterSet"]].configure(length=len(mac), customization=unhex(record["customization"]), xof=header["xof"] == "true")

                if record["testPassed"] == "true":
                    self.check_mac(algorithm, key, data, mac)
                else:
                    rejected += 1

                    self.assertNotEqual(algorithm.digest(key, data), mac)

                    self.assertFalse(algorithm.verify(key, data, mac))

        self.assertEqual((len(found), rejected), (103, 2))

    def test_kmac_wycheproof(self):
        found = records("wycheproof/kmac.txt", "tag")

        invalid = 0

        for header, record in found:
            with self.subTest(parameterSet=header["parameterSet"], tcId=record["tcId"]):
                key, data, tag = unhex(record["key"]), unhex(record["msg"]), unhex(record["tag"])

                algorithm = KMACS[header["parameterSet"]].configure(length=int(header["tagSize"]) // 8)

                if record["result"] == "valid":
                    self.check_mac(algorithm, key, data, tag)
                else:
                    invalid += 1

                    self.assertFalse(algorithm.verify(key, data, tag))

                    self.assertFalse(algorithm.create(key).verify(tag))

        self.assertEqual((len(found), invalid), (435, 270))


def cshake(algorithm, record):
    customization = unhex(record["customization"])

    if record["functionName"]:
        return hazmat.configure_cshake(algorithm, unhex(record["functionName"]), customization)

    return algorithm.configure(customization=customization)


# RFC 7693, appendix E: selftest_seq.
def selftest_sequence(length, seed):
    a, b, out = (0xDEAD4BAD * seed) & 0xFFFFFFFF, 1, bytearray()

    for _ in range(length):
        a, b = b, (a + b) & 0xFFFFFFFF

        out.append(b >> 24)

    return bytes(out)


class Blake2Test(Case):
    def test_rfc7693(self):
        found = records("rfc/blake2.txt", "out")

        for header, record in found:
            with self.subTest(name=record["name"]):
                if header["kind"] == "example":
                    algorithm = BLAKE2B[64] if record["hash"] == "BLAKE2b-512" else BLAKE2S[32]

                    self.check_hash(algorithm, unhex(record["in"]), unhex(record["out"]))

                    continue

                hashes, mac = BLAKE2[record["hash"]]

                grand = hashes[32].create()

                for length in map(int, record["digestLengths"].split(",")):
                    keyed = mac.configure(length=length)

                    for size in map(int, record["inputLengths"].split(",")):
                        data = selftest_sequence(size, size)

                        grand.update(hashes[length].digest(data))

                        grand.update(keyed.digest(selftest_sequence(length, length), data))

                self.assertEqual(grand.digest(), unhex(record["out"]))

        self.assertEqual(len(found), 4)

    # The reference KATs: unkeyed hashes and the MAC under a full-length key, at full length.
    def test_reference(self):
        for name, (hashes, mac) in BLAKE2.items():
            found = records(f"blake2/{name.lower()}.txt", "out")

            for _, record in found:
                with self.subTest(hash=name, key=bool(record["key"]), size=len(record["in"]) // 2):
                    data, out = unhex(record["in"]), unhex(record["out"])

                    if record["key"]:
                        self.check_mac(mac, unhex(record["key"]), data, out)
                    else:
                        self.check_hash(hashes[len(out)], data, out)

            self.assertEqual(len(found), 512)

    # Unkeyed records are the hash of that output length, keyed ones the MAC configured to it.
    def test_salt_and_personalization(self):
        found = records("derived/blake2.txt", "out")

        keyed = 0

        for header, record in found:
            hashes, mac = BLAKE2[header["hash"]]

            with self.subTest(hash=header["hash"], record=record):
                length, salt, personalization = int(record["digestLength"]), unhex(record["salt"]), unhex(record["personalization"])

                data, out = unhex(record["in"]), unhex(record["out"])

                if record["key"]:
                    keyed += 1

                    self.check_mac(mac.configure(length=length, salt=salt, personalization=personalization), unhex(record["key"]), data, out)
                else:
                    self.check_hash(hashes[length].configure(salt=salt, personalization=personalization), data, out)

        self.assertEqual((len(found), keyed), (500, 300))

    def test_keys(self):
        for mac, maximum in ((crypto_pq.BLAKE2B_MAC, 64), (crypto_pq.BLAKE2S_MAC, 32)):
            for configured in (mac, mac.configure(length=7)):
                with self.subTest(mac=configured.name, length=configured.digest_size):
                    for key in (b"", bytes(maximum + 1)):
                        self.assertCode(ErrorCode.INVALID_LENGTH, configured.digest, key, b"data")

                        self.assertCode(ErrorCode.INVALID_LENGTH, configured.create, key)

                        self.assertFalse(configured.verify(key, b"data", bytes(configured.digest_size)))

                    for size in (1, maximum):
                        tag = configured.digest(bytes(size), b"data")

                        self.assertEqual(len(tag), configured.digest_size)

                        self.assertTrue(configured.verify(bytes(size), b"data", tag))


class AsconTest(Case):
    def test_hash(self):
        found = records("ascon/LWC_HASH_KAT_128_256.txt", "MD")

        for _, record in found:
            with self.subTest(count=record["Count"]):
                self.check_hash(crypto_pq.ASCON_HASH256, unhex(record["Msg"]), unhex(record["MD"]))

        self.assertEqual(len(found), 1025)

    def test_xof(self):
        found = records("ascon/LWC_XOF_KAT_128_512.txt", "MD")

        for _, record in found:
            with self.subTest(count=record["Count"]):
                self.check_xof(crypto_pq.ASCON_XOF128, unhex(record["Msg"]), unhex(record["MD"]))

        self.assertEqual(len(found), 1025)

    def test_cxof(self):
        found = records("ascon/LWC_CXOF_KAT_128_512.txt", "MD")

        for _, record in found:
            with self.subTest(count=record["Count"]):
                algorithm = crypto_pq.ASCON_CXOF128.configure(customization=unhex(record["Z"]))

                self.check_xof(algorithm, unhex(record["Msg"]), unhex(record["MD"]))

        self.assertEqual(len(found), 1089)

    def test_acvp(self):
        found = records("acvp/Ascon.txt", "md")

        algorithms = {"Ascon-Hash256": crypto_pq.ASCON_HASH256, "Ascon-XOF128": crypto_pq.ASCON_XOF128, "Ascon-CXOF128": crypto_pq.ASCON_CXOF128}

        for header, record in found:
            with self.subTest(parameterSet=header["parameterSet"], tcId=record["tcId"]):
                algorithm, data, md = algorithms[header["parameterSet"]], unhex(record["msg"]), unhex(record["md"])

                if algorithm is crypto_pq.ASCON_HASH256:
                    self.check_hash(algorithm, data, md)
                else:
                    self.check_xof(algorithm.configure(customization=unhex(record.get("cs", ""))), data, md)

        self.assertEqual(len(found), 16)

    def test_customization_limit(self):
        longest = crypto_pq.ASCON_CXOF128.configure(customization=bytes(256))

        self.assertEqual(len(longest.digest(b"m", 40)), 40)

        self.assertNotEqual(longest.digest(b"m", 32), crypto_pq.ASCON_CXOF128.configure(customization=bytes(255)).digest(b"m", 32))

        self.assertCode(ErrorCode.INVALID_OPTION, crypto_pq.ASCON_CXOF128.configure, customization=bytes(257))


class ConfigureTest(Case):
    def test_properties(self):
        names = ("BLAKE2b-160", "BLAKE2b-256", "BLAKE2b-384", "BLAKE2b-512", "BLAKE2s-128", "BLAKE2s-160", "BLAKE2s-224", "BLAKE2s-256", "Ascon-Hash256")

        for algorithm, name, size in zip(HASHES, names, (20, 32, 48, 64, 16, 20, 28, 32, 32), strict=True):
            self.assertEqual((algorithm.name, algorithm.digest_size, len(algorithm.digest(b""))), (name, size, size))

        for algorithm, name in zip(XOFS, ("cSHAKE128", "cSHAKE256", "Ascon-XOF128", "Ascon-CXOF128"), strict=True):
            self.assertEqual(algorithm.name, name)

        for algorithm, name, size in zip(MACS, ("KMAC128", "KMAC256", "BLAKE2b-MAC", "BLAKE2s-MAC"), (32, 64, 64, 32), strict=True):
            self.assertEqual((algorithm.name, algorithm.digest_size, len(algorithm.digest(b"key", b""))), (name, size, size))

        for algorithm, name in zip(HKDFS.values(), HKDFS):
            self.assertEqual((algorithm.name, repr(algorithm)), (name, f"<KdfAlgorithm {name}>"))

        self.assertEqual(repr(crypto_pq.KMAC128), "<MacAlgorithm KMAC128>")

    # No options give the base algorithm itself, also from a configured one: the options replace
    # those set before.
    def test_defaults(self):
        for algorithm in (crypto_pq.SHA_256, crypto_pq.SHAKE128, *HASHES, *XOFS):
            self.assertIs(algorithm.configure(), algorithm)

        for algorithm in (crypto_pq.HMAC_SHA_256, *MACS):
            self.assertIs(algorithm.configure(), algorithm)

        salted = crypto_pq.BLAKE2B_256.configure(salt=b"salt")

        self.assertEqual(salted.name, "BLAKE2b-256")

        self.assertIs(salted.configure(), crypto_pq.BLAKE2B_256)

        self.assertIs(salted.configure(salt=b"", personalization=b""), crypto_pq.BLAKE2B_256)

        self.assertEqual(salted.configure(personalization=b"p").digest(b"m"), crypto_pq.BLAKE2B_256.configure(personalization=b"p").digest(b"m"))

        self.assertIs(crypto_pq.CSHAKE128.configure(customization=b"c").configure(), crypto_pq.CSHAKE128)

        kmac = crypto_pq.KMAC128.configure(length=20, customization=b"c")

        self.assertEqual((kmac.digest_size, kmac.configure(xof=True).digest_size), (20, 32))

        self.assertIs(kmac.configure(), crypto_pq.KMAC128)

    def test_hash_options(self):
        for algorithm in BLAKE2B.values():
            self.assertEqual(algorithm.configure(salt=b"ab").digest(b"m"), algorithm.configure(salt=b"ab" + bytes(14)).digest(b"m"))

            self.assertEqual(algorithm.configure(salt=bytes(16), personalization=bytes(16)).digest(b"m"), algorithm.digest(b"m"))

            self.assertNotEqual(algorithm.configure(personalization=b"p").digest(b"m"), algorithm.digest(b"m"))

            self.assertCode(ErrorCode.INVALID_OPTION, algorithm.configure, salt=bytes(17))

            self.assertCode(ErrorCode.INVALID_OPTION, algorithm.configure, personalization=bytes(17))

        for algorithm in BLAKE2S.values():
            self.assertEqual(len(algorithm.configure(salt=bytes(8), personalization=b"p" * 8).digest(b"m")), algorithm.digest_size)

            self.assertCode(ErrorCode.INVALID_OPTION, algorithm.configure, salt=bytes(9))

            self.assertCode(ErrorCode.INVALID_OPTION, algorithm.configure, personalization=bytes(9))

        for algorithm in (crypto_pq.SHA_256, crypto_pq.SHA3_512, crypto_pq.ASCON_HASH256):
            self.assertIs(algorithm.configure(salt=b"", personalization=b""), algorithm)

            self.assertCode(ErrorCode.INVALID_OPTION, algorithm.configure, salt=b"s")

            self.assertCode(ErrorCode.INVALID_OPTION, algorithm.configure, personalization=b"p")

        for wrong in ("salt", None, 1):
            with self.assertRaises(TypeError):
                crypto_pq.BLAKE2B_512.configure(salt=wrong)

        with self.assertRaises(TypeError):
            crypto_pq.BLAKE2B_512.configure(b"salt")

        configured = crypto_pq.BLAKE2S_256.configure(salt=bytearray(b"salt"), personalization=memoryview(b"xpx")[1:2])

        self.assertEqual(configured.digest(b"m"), crypto_pq.BLAKE2S_256.configure(salt=b"salt", personalization=b"p").digest(b"m"))

    def test_xof_options(self):
        for cshake, shake in ((crypto_pq.CSHAKE128, crypto_pq.SHAKE128), (crypto_pq.CSHAKE256, crypto_pq.SHAKE256)):
            self.assertEqual(cshake.digest(b"m", 100), shake.digest(b"m", 100))

            self.assertNotEqual(cshake.configure(customization=b"c").digest(b"m", 32), shake.digest(b"m", 32))

            self.assertEqual(hazmat.configure_cshake(cshake, b"", b"c").digest(b"m", 32), cshake.configure(customization=b"c").digest(b"m", 32))

            self.assertIs(hazmat.configure_cshake(cshake.configure(customization=b"c"), b"", b""), cshake)

            self.assertEqual(len(cshake.configure(customization=bytes(1000)).digest(b"m", 0)), 0)

        for algorithm in (crypto_pq.SHAKE128, crypto_pq.SHAKE256, crypto_pq.ASCON_XOF128):
            self.assertCode(ErrorCode.INVALID_OPTION, algorithm.configure, customization=b"c")

            self.assertCode(ErrorCode.INVALID_OPTION, hazmat.configure_cshake, algorithm, b"N", b"")

        self.assertCode(ErrorCode.INVALID_OPTION, hazmat.configure_cshake, crypto_pq.ASCON_CXOF128, b"", b"c")

        with self.assertRaises(TypeError):
            hazmat.configure_cshake(crypto_pq.KMAC128, b"N", b"")

        with self.assertRaises(TypeError):
            crypto_pq.CSHAKE128.configure(customization="c")

    def test_mac_options(self):
        key, data = bytes(range(32)), b"data"

        for kmac, default in ((crypto_pq.KMAC128, 32), (crypto_pq.KMAC256, 64)):
            self.assertEqual(kmac.configure(length=default).digest(key, data), kmac.digest(key, data))

            self.assertEqual(kmac.configure(length=4).digest_size, 4)

            # KMACXOF encodes L as 0, so its outputs are prefixes of each other; KMAC's are not.
            xof = kmac.configure(xof=True).digest(key, data)

            self.assertEqual(len(xof), default)

            self.assertEqual(kmac.configure(xof=True, length=200).digest(key, data)[:default], xof)

            self.assertNotEqual(kmac.configure(length=200).digest(key, data)[:default], kmac.digest(key, data))

            self.assertNotEqual(xof, kmac.digest(key, data))

            self.assertEqual(len(kmac.digest(b"", data)), default)

            for options in ({"length": 3}, {"length": 0}, {"length": -1}, {"length": 1 << 61}, {"salt": b"s"}, {"personalization": b"p"}, {"xof": 1}, {"xof": None}):
                self.assertCode(ErrorCode.INVALID_OPTION, kmac.configure, **options)

            with self.assertRaises(TypeError):
                kmac.configure(length=4.0)

        for blake2, maximum, field in ((crypto_pq.BLAKE2B_MAC, 64, 16), (crypto_pq.BLAKE2S_MAC, 32, 8)):
            self.assertEqual(blake2.configure(length=maximum).digest(key[:16], data), blake2.digest(key[:16], data))

            self.assertEqual(len(blake2.configure(length=1).digest(key[:16], data)), 1)

            for options in ({"length": 0}, {"length": maximum + 1}, {"salt": bytes(field + 1)}, {"personalization": bytes(field + 1)}, {"customization": b"c"}, {"xof": True}):
                self.assertCode(ErrorCode.INVALID_OPTION, blake2.configure, **options)

        for options in ({"length": 32}, {"customization": b"c"}, {"xof": True}, {"salt": b"s"}, {"personalization": b"p"}, {"xof": 1}):
            self.assertCode(ErrorCode.INVALID_OPTION, crypto_pq.HMAC_SHA_256.configure, **options)

        self.assertIs(crypto_pq.HMAC_SHA_256.configure(xof=False, customization=b"", salt=b"", personalization=b""), crypto_pq.HMAC_SHA_256)

    # Digests leave the state as it was, tags of another length do not verify, and an XOF takes no
    # more data once read.
    def test_states(self):
        configured = (crypto_pq.BLAKE2B_256.configure(salt=b"s"), crypto_pq.KMAC256.configure(length=40, customization=b"c"), crypto_pq.BLAKE2S_MAC.configure(length=9, personalization=b"p"))

        for algorithm in (*HASHES, configured[0]):
            hasher = algorithm.create()

            hasher.update(b"abc")

            self.assertEqual(hasher.digest(), hasher.digest())

            hasher.update(b"def")

            self.assertEqual(hasher.digest(), algorithm.digest(b"abcdef"))

        for algorithm in (*MACS, *configured[1:]):
            mac = algorithm.create(b"key")

            mac.update(b"abc")

            tag = mac.digest()

            self.assertEqual(mac.digest(), tag)

            self.assertTrue(mac.verify(tag))

            self.assertFalse(mac.verify(tag[:-1]))

            self.assertFalse(mac.verify(tag + b"\x00"))

            self.assertFalse(algorithm.verify(b"key", b"abc", tag[:-1]))

            mac.update(b"def")

            self.assertEqual(mac.digest(), algorithm.digest(b"key", b"abcdef"))

        for algorithm in (*XOFS, crypto_pq.CSHAKE128.configure(customization=b"c"), crypto_pq.ASCON_CXOF128.configure(customization=b"z")):
            xof = algorithm.create()

            xof.update(b"abc")

            self.assertEqual(b"".join(xof.read(n) for n in (0, 1, 7, 8, 9, 135, 1, 167, 200, 496)), algorithm.digest(b"abc", 1024))

            self.assertCode(ErrorCode.UNSUPPORTED, xof.update, b"x")

            self.assertCode(ErrorCode.INVALID_LENGTH, xof.read, -1)

            self.assertCode(ErrorCode.INVALID_LENGTH, algorithm.digest, b"", -1)

    # Only the hash functions that FIPS 204 and 205 list are pre-hashes.
    def test_not_pre_hashes(self):
        pair = hazmat.generate_key_pair(crypto_pq.ML_DSA_44, bytes(32))

        signature = pair.private_key.sign(b"m", deterministic=True, pre_hash=crypto_pq.SHA_256)

        for algorithm in (*HASHES, *XOFS, crypto_pq.BLAKE2B_512.configure(salt=b"s"), crypto_pq.CSHAKE256.configure(customization=b"c")):
            with self.subTest(algorithm=algorithm.name):
                self.assertCode(ErrorCode.INVALID_OPTION, pair.private_key.sign, b"m", pre_hash=algorithm)

                self.assertCode(ErrorCode.INVALID_OPTION, pair.public_key.verify, signature, b"m", pre_hash=algorithm)

        self.assertIs(crypto_pq.SHA_256.configure(), crypto_pq.SHA_256)


if __name__ == "__main__":
    unittest.main()

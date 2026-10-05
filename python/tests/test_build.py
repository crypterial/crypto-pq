import base64
import binascii
import gzip
import importlib.util
import io
import os
import pathlib
import shutil
import struct
import tarfile
import tempfile
import unittest
import zipfile

import crypto_pq

PROJECT = pathlib.Path(__file__).resolve().parents[1]

# CRYPTO_PQ_DIST names the output of `zig build dist`: then the seven platform wheels are built
# from it, twice, and checked like the pure one.
DIST = os.environ.get("CRYPTO_PQ_DIST")


def load_backend(root=PROJECT, name="cpq_build"):
    spec = importlib.util.spec_from_file_location(name, root / "build_backend" / "cpq_build.py")

    module = importlib.util.module_from_spec(spec)

    spec.loader.exec_module(module)

    return module


backend = load_backend()


def elf(machine, needed=False, width=2):
    dynamic = (struct.pack("<qQ", 1, 1) if needed else b"") + struct.pack("<qQ", 0, 0)

    header = b"\x7fELF" + bytes([width, 1, 1]) + bytes(9) + struct.pack("<HHIQQQIHHHHHH", 3, machine, 1, 0, 64, 0, 0, 64, 56, 1, 64, 0, 0)

    program = struct.pack("<IIQQQQQQ", 2, 6, 120, 120, 120, len(dynamic), len(dynamic), 8)

    return header + program + dynamic


def macho(cpu, major=13, minor=0, kind=6):
    command = struct.pack("<IIIIII", 0x32, 24, 1, major << 16 | minor << 8, major << 16, 0)

    return struct.pack("<IiiIIIII", 0xFEEDFACF, cpu, 0, kind, 1, len(command), 0, 0) + command


def pe(machine, characteristics=0x2022):
    header = b"MZ" + bytes(0x3A) + struct.pack("<I", 0x40)

    return header + b"PE\0\0" + struct.pack("<HHIIIHH", machine, 0, 0, 0, 0, 0, characteristics)


def record_entries(archive):
    rows = archive.read(next(name for name in archive.namelist() if name.endswith(".dist-info/RECORD"))).decode().splitlines()

    return [row.split(",") for row in rows]


class BuildCase(unittest.TestCase):
    def setUp(self):
        self.directory = pathlib.Path(tempfile.mkdtemp())

        self.addCleanup(shutil.rmtree, self.directory)

    def wheel(self, native=None, directory="wheels"):
        out = self.directory / directory

        return out / backend.build(str(out), native)

    # A wheel's RECORD lists every other entry once, with its SHA-256 and size, and itself last
    # without either; the WHEEL file's tags are the file name's.
    def check_wheel(self, path, tags, purelib, sources=True):
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()

            rows = record_entries(archive)

            self.assertEqual([row[0] for row in rows], names)

            self.assertEqual(rows[-1][1:], ["", ""])

            for name, digest, size in rows[:-1]:
                data = archive.read(name)

                self.assertEqual(digest, "sha256=" + base64.urlsafe_b64encode(crypto_pq.SHA_256.digest(data)).rstrip(b"=").decode())

                self.assertEqual(int(size), len(data))

            for entry in archive.infolist():
                self.assertEqual((entry.date_time, entry.create_system, entry.compress_type), ((1980, 1, 1, 0, 0, 0), 3, zipfile.ZIP_DEFLATED))

                self.assertEqual(entry.external_attr >> 16, 0o100755 if entry.filename.endswith((".so", ".dylib", ".dll")) else 0o100644)

            info = next(name.split("/")[0] for name in names if name.endswith("/WHEEL"))

            wheel = archive.read(f"{info}/WHEEL").decode().splitlines()

            self.assertEqual(wheel[:3], ["Wheel-Version: 1.0", "Generator: crypto-pq cpq_build", f"Root-Is-Purelib: {'true' if purelib else 'false'}"])

            self.assertEqual(wheel[3:], [f"Tag: py3-none-{tag}" for tag in tags])

            self.assertTrue(path.name.endswith(f"-py3-none-{'.'.join(tags)}.whl"), path.name)

            metadata = archive.read(f"{info}/METADATA").decode()

            for path_name in ("LICENSE-APACHE", "LICENSE-MIT"):
                self.assertEqual(archive.read(f"{info}/licenses/{path_name}"), (PROJECT / path_name).read_bytes())

            found = sorted(name for name in names if name.startswith("crypto_pq/") and name.endswith((".py", ".typed")))

            self.assertEqual(found, sorted(f"crypto_pq/{file.name}" for file in (PROJECT / "src" / "crypto_pq").iterdir() if file.suffix == ".py" or file.name == "py.typed") if sources else [])

            return names, metadata


class PureWheelTest(BuildCase):
    def test_wheel(self):
        first, second = self.wheel(), self.wheel(directory="again")

        self.assertEqual(first.read_bytes(), second.read_bytes())

        self.assertEqual(first.name, f"crypto_pq-{crypto_pq_version()}-py3-none-any.whl")

        names, metadata = self.check_wheel(first, ("any",), True)

        self.assertFalse([name for name in names if name.endswith((".so", ".dylib", ".dll", ".record"))])

        lines = metadata.splitlines()

        self.assertEqual(lines[:3], ["Metadata-Version: 2.4", "Name: crypto-pq", f"Version: {crypto_pq_version()}"])

        for line in ("License-Expression: Apache-2.0 OR MIT", "License-File: LICENSE-APACHE", "License-File: LICENSE-MIT", "Requires-Python: >=3.11", "Author: Wilson Tran"):
            self.assertIn(line, lines)

        self.assertFalse([line for line in lines if line.startswith(("Requires-Dist", "Classifier: License"))])

    def test_license_files_match_the_repository(self):
        for name in ("LICENSE-APACHE", "LICENSE-MIT"):
            self.assertEqual((PROJECT / name).read_bytes(), (PROJECT.parent / name).read_bytes())

    def test_metadata_hooks(self):
        info = backend.prepare_metadata_for_build_wheel(str(self.directory / "meta"))

        with zipfile.ZipFile(self.wheel()) as archive:
            for name in ("METADATA", "WHEEL", "licenses/LICENSE-MIT"):
                self.assertEqual((self.directory / "meta" / info / name).read_bytes(), archive.read(f"{info}/{name}"))

        self.assertEqual(backend.prepare_metadata_for_build_editable(str(self.directory / "editable")), info)

        self.assertEqual([backend.get_requires_for_build_wheel(), backend.get_requires_for_build_sdist(), backend.get_requires_for_build_editable()], [[], [], []])

    # PEP 660: the editable wheel holds a .pth file naming the sources, and the metadata.
    def test_editable(self):
        path = self.directory / backend.build_editable(str(self.directory))

        with zipfile.ZipFile(path) as archive:
            self.assertEqual(archive.read("crypto_pq.pth").decode(), str(PROJECT / "src") + "\n")

            self.assertFalse([name for name in archive.namelist() if name.endswith(".py")])

        self.check_wheel(path, ("any",), True, sources=False)

    def test_sdist(self):
        name = backend.build_sdist(str(self.directory / "one"))

        self.assertEqual(name, f"crypto_pq-{crypto_pq_version()}.tar.gz")

        data = (self.directory / "one" / name).read_bytes()

        self.assertEqual(data, (self.directory / "two" / backend.build_sdist(str(self.directory / "two"))).read_bytes())

        self.assertEqual(struct.unpack_from("<I", data, 4)[0], backend.EPOCH)

        base = f"crypto_pq-{crypto_pq_version()}"

        with tarfile.open(fileobj=io.BytesIO(gzip.decompress(data))) as archive:
            members = archive.getmembers()

            names = [member.name for member in members]

            self.assertEqual(names, sorted(names))

            for member in members:
                self.assertEqual((member.mtime, member.mode, member.uid, member.gid, member.uname, member.gname), (backend.EPOCH, 0o644, 0, 0, "", ""))

            expected = {f"{base}/{path}" for path in ("PKG-INFO", "pyproject.toml", "LICENSE-APACHE", "LICENSE-MIT", "build_backend/cpq_build.py")}

            expected |= {f"{base}/src/crypto_pq/{file.name}" for file in (PROJECT / "src" / "crypto_pq").iterdir() if file.suffix == ".py" or file.name == "py.typed"}

            self.assertEqual(set(names), expected)

            archive.extractall(self.directory / "unpacked", filter="data")

        with zipfile.ZipFile(self.wheel()) as wheel:
            info = next(name for name in wheel.namelist() if name.endswith("/METADATA"))

            self.assertEqual((self.directory / "unpacked" / base / "PKG-INFO").read_bytes(), wheel.read(info))

        # The sdist builds the same wheel, byte for byte.
        unpacked = load_backend(self.directory / "unpacked" / base, "cpq_build_sdist")

        rebuilt = unpacked.build(str(self.directory / "rebuilt"))

        self.assertEqual((self.directory / "rebuilt" / rebuilt).read_bytes(), self.wheel().read_bytes())

    def test_project_checks(self):
        root = self.directory / "project"

        root.mkdir()

        for name in ("pyproject.toml", "LICENSE-APACHE", "LICENSE-MIT"):
            shutil.copy(PROJECT / name, root / name)

        shutil.copytree(PROJECT / "build_backend", root / "build_backend")

        shutil.copytree(PROJECT / "src", root / "src", ignore=shutil.ignore_patterns("__pycache__"))

        original = (root / "pyproject.toml").read_text()

        for changed, message in (
            (original.replace('requires-python = ">=3.11"', 'requires-python = ">=3.11"\ndependencies = ["x"]'), "does not handle the project keys dependencies"),
            (original.replace('version = "0.2.0.dev0"', 'version = "0.2.0-dev.0"'), "normal form of PEP 440"),
            (original.replace('"Typing :: Typed",', '"Typing :: Typed",\n    "License :: OSI Approved :: MIT License",'), "excludes license classifiers"),
            (original.replace('license-files = ["LICENSE-APACHE", "LICENSE-MIT"]', 'license-files = ["../LICENSE-MIT"]'), "plain path inside the project"),
        ):
            with self.subTest(message=message):
                (root / "pyproject.toml").write_text(changed)

                with self.assertRaisesRegex(ValueError, message):
                    load_backend(root, "cpq_build_checked").build(str(self.directory / "refused"))


def crypto_pq_version():
    for line in (PROJECT / "pyproject.toml").read_text().splitlines():
        if line.startswith("version = "):
            return line.split('"')[1]

    raise AssertionError("no version in pyproject.toml")


class PlatformTest(BuildCase):
    CASES = (
        ("x86_64-linux", "libcrypto_pq.so", elf(0x3E), ("manylinux_2_17_x86_64", "manylinux2014_x86_64", "musllinux_1_1_x86_64")),
        ("aarch64-linux", "libcrypto_pq.so", elf(0xB7), ("manylinux_2_17_aarch64", "manylinux2014_aarch64", "musllinux_1_1_aarch64")),
        ("riscv64-linux", "libcrypto_pq.so", elf(0xF3), ("manylinux_2_17_riscv64", "musllinux_1_1_riscv64")),
        ("x86_64-macos", "libcrypto_pq.dylib", macho(0x01000007), ("macosx_13_0_x86_64",)),
        ("aarch64-macos", "libcrypto_pq.dylib", macho(0x0100000C, 11), ("macosx_11_0_arm64",)),
        ("x86_64-windows", "crypto_pq.dll", pe(0x8664), ("win_amd64",)),
        ("aarch64-windows", "crypto_pq.dll", pe(0xAA64), ("win_arm64",)),
    )

    def library(self, name, data, directory="lib"):
        path = self.directory / directory / name

        path.parent.mkdir(exist_ok=True)

        path.write_bytes(data)

        return path

    # The headers of the library give its platform and tags; the wheel holds it with its record.
    def test_platforms(self):
        for target, name, data, tags in self.CASES:
            with self.subTest(target=target):
                self.assertEqual(backend.library_platform(data), (target, name, tags))

                path = self.wheel(str(self.library(name, data)))

                self.check_wheel(path, tags, False)

                with zipfile.ZipFile(path) as archive:
                    self.assertEqual(archive.read(f"crypto_pq/{name}"), data)

                    record = archive.read("crypto_pq/native.record").decode().splitlines()

                self.assertEqual(record, ["crypto-pq native library 1", f"file {name}", f"target {target}", f"size {len(data)}", f"crc32 {binascii.crc32(data):08x}"])

                self.assertEqual(path.read_bytes(), self.wheel(str(self.library(name, data, "other")), "again").read_bytes())

    def test_refusals(self):
        for data, name, message in (
            (elf(0x3E, needed=True), "libcrypto_pq.so", "needs another library"),
            (elf(0x3E, width=1), "libcrypto_pq.so", "not 64-bit little-endian"),
            (elf(0x28), "libcrypto_pq.so", "supported architecture"),
            (macho(0x01000007, kind=8), "libcrypto_pq.dylib", "not a dynamic library"),
            (pe(0x8664, characteristics=0x22), "crypto_pq.dll", "not a DLL"),
            (pe(0x14C), "crypto_pq.dll", "not a DLL of a supported architecture"),
            (b"\x00" * 64, "libcrypto_pq.so", "not an ELF, Mach-O or PE file"),
            (elf(0xB7), "crypto_pq.dll", "must be named libcrypto_pq.so"),
            (macho(0x0100000C), "libcrypto_pq.so", "must be named libcrypto_pq.dylib"),
        ):
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    self.wheel(str(self.library(name, data)))

    def test_config_setting(self):
        path = self.library("libcrypto_pq.so", elf(0xB7))

        name = backend.build_wheel(str(self.directory / "hook"), {"native": str(path)})

        self.assertEqual((self.directory / "hook" / name).read_bytes(), self.wheel(str(path)).read_bytes())

        info = backend.prepare_metadata_for_build_wheel(str(self.directory / "meta"), {"native": str(path)})

        wheel = (self.directory / "meta" / info / "WHEEL").read_text()

        self.assertIn("Root-Is-Purelib: false", wheel)

        self.assertIn("Tag: py3-none-musllinux_1_1_aarch64", wheel)

        with self.assertRaisesRegex(ValueError, "takes one value"):
            backend.build_wheel(str(self.directory / "hook"), {"native": [str(path), str(path)]})


@unittest.skipUnless(DIST, "CRYPTO_PQ_DIST names no `zig build dist` output")
class DistTest(BuildCase):
    # Every shipped library makes its platform's wheel, twice the same, holding the library as
    # `zig build dist` wrote it.
    def test_all_wheels(self):
        built = {}

        for directory in ("one", "two"):
            out = self.directory / directory

            backend.build(str(out))

            for target, (name, _) in backend.PLATFORMS.items():
                backend.build(str(out), os.path.join(DIST, target, name))

            backend.build_sdist_archive(str(out))

            built[directory] = sorted(out.iterdir())

        self.assertEqual([path.name for path in built["one"]], [path.name for path in built["two"]])

        for first, second in zip(built["one"], built["two"]):
            self.assertEqual(first.read_bytes(), second.read_bytes(), first.name)

        for target, (name, _) in backend.PLATFORMS.items():
            with self.subTest(target=target):
                library = (pathlib.Path(DIST) / target / name).read_bytes()

                found, _, tags = backend.library_platform(library)

                self.assertEqual(found, target)

                path = next(path for path in built["one"] if path.name.endswith(f"-py3-none-{'.'.join(tags)}.whl"))

                self.check_wheel(path, tags, False)

                with zipfile.ZipFile(path) as archive:
                    self.assertEqual(archive.read(f"crypto_pq/{name}"), library)

        self.assertEqual(len(built["one"]), len(backend.PLATFORMS) + 2)


if __name__ == "__main__":
    unittest.main()

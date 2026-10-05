"""A PEP 517 build backend for crypto-pq that needs nothing but the Python standard library.

`pip wheel .` and `pip install .` build the pure wheel, py3-none-any, offline and with an empty
build environment. A platform wheel takes the native library that `zig build dist` writes for one
platform, given as a config setting or on the command line:

    pip wheel . --config-settings native=../zig/zig-out/dist/x86_64-linux/libcrypto_pq.so
    python build_backend/cpq_build.py wheel OUT_DIR [--native LIBRARY]
    python build_backend/cpq_build.py sdist OUT_DIR
    python build_backend/cpq_build.py all OUT_DIR DIST_DIR

The library's own headers name its platform, so a wheel never carries a library under another
platform's tags. The wheel holds the library and its build record (file name, platform, size and
CRC-32), which the loader checks before it maps the library. The metadata is METADATA 2.4 with a
license expression and license files (PEP 639); RECORD hashes come from crypto-pq's own SHA-256,
never from hashlib; every archive entry has a fixed time, mode and order, so that the same sources
and library give the same bytes with the same zlib.
"""

import base64
import binascii
import gzip
import io
import os
import re
import struct
import sys
import tarfile
import tomllib
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PACKAGE = "crypto_pq"

# 1980-01-01, the earliest time a zip entry can hold.
TIMESTAMP = (1980, 1, 1, 0, 0, 0)

EPOCH = 315532800

RECORD = "native.record"

RECORD_FORMAT = "crypto-pq native library 1"

# The libraries that `zig build dist` writes, by platform: the file name and the wheel's platform
# tags. A Linux library needs no libc, so one file serves glibc and musl; a macOS tag takes the
# minimum version that the library itself records.
PLATFORMS = {
    "x86_64-linux": ("libcrypto_pq.so", ("manylinux_2_17_x86_64", "manylinux2014_x86_64", "musllinux_1_1_x86_64")),
    "aarch64-linux": ("libcrypto_pq.so", ("manylinux_2_17_aarch64", "manylinux2014_aarch64", "musllinux_1_1_aarch64")),
    "riscv64-linux": ("libcrypto_pq.so", ("manylinux_2_17_riscv64", "musllinux_1_1_riscv64")),
    "x86_64-macos": ("libcrypto_pq.dylib", ("macosx_{}_{}_x86_64",)),
    "aarch64-macos": ("libcrypto_pq.dylib", ("macosx_{}_{}_arm64",)),
    "x86_64-windows": ("crypto_pq.dll", ("win_amd64",)),
    "aarch64-windows": ("crypto_pq.dll", ("win_arm64",)),
}

PROJECT_KEYS = {"name", "version", "description", "license", "license-files", "requires-python", "authors", "keywords", "classifiers", "urls"}

VERSION = re.compile(r"\d+(\.\d+)*((a|b|rc)\d+)?(\.post\d+)?(\.dev\d+)?")

_digest: list = []


def read(path):
    with open(path, "rb") as handle:
        return handle.read()


# crypto-pq's own SHA-256, from the sources being built unless crypto_pq is already imported: not
# even the build uses hashlib. The import takes the pure backend, which the sources always have.
def sha256(data):
    if not _digest:
        previous = os.environ.get("CRYPTO_PQ_BACKEND")

        os.environ["CRYPTO_PQ_BACKEND"] = "pure"

        sys.path.insert(0, os.path.join(ROOT, "src"))

        try:
            from crypto_pq import SHA_256
        finally:
            sys.path.remove(os.path.join(ROOT, "src"))

            if previous is None:
                del os.environ["CRYPTO_PQ_BACKEND"]
            else:
                os.environ["CRYPTO_PQ_BACKEND"] = previous

        _digest.append(SHA_256.digest)

    return _digest[0](data)


def project():
    with open(os.path.join(ROOT, "pyproject.toml"), "rb") as handle:
        table = tomllib.load(handle)["project"]

    unknown = sorted(set(table) - PROJECT_KEYS)

    if unknown:
        raise ValueError(f"cpq_build does not handle the project keys {', '.join(unknown)}")

    if not VERSION.fullmatch(table["version"]):
        raise ValueError(f"the version {table['version']!r} is not in the normal form of PEP 440")

    if any(classifier.startswith("License ::") for classifier in table.get("classifiers", ())):
        raise ValueError("a license expression excludes license classifiers (PEP 639)")

    return table


def distribution(table):
    return re.sub(r"[-_.]+", "_", table["name"]).lower()


def metadata(table):
    lines = ["Metadata-Version: 2.4", f"Name: {table['name']}", f"Version: {table['version']}"]

    if "description" in table:
        lines.append(f"Summary: {table['description']}")

    names = [person["name"] for person in table.get("authors", ()) if "email" not in person]

    emails = [f"{person['name']} <{person['email']}>" if "name" in person else person["email"] for person in table.get("authors", ()) if "email" in person]

    if names:
        lines.append(f"Author: {', '.join(names)}")

    if emails:
        lines.append(f"Author-email: {', '.join(emails)}")

    if "keywords" in table:
        lines.append(f"Keywords: {','.join(table['keywords'])}")

    lines.append(f"License-Expression: {table['license']}")

    lines += [f"License-File: {path}" for path in table.get("license-files", ())]

    lines += [f"Classifier: {classifier}" for classifier in table.get("classifiers", ())]

    if "requires-python" in table:
        lines.append(f"Requires-Python: {table['requires-python']}")

    lines += [f"Project-URL: {label}, {url}" for label, url in table.get("urls", {}).items()]

    return ("\n".join(lines) + "\n").encode("utf-8")


def license_files(table):
    files = []

    for path in table.get("license-files", ()):
        if os.path.isabs(path) or ".." in path.split("/") or any(character in path for character in "*?["):
            raise ValueError(f"license file {path!r} must be a plain path inside the project")

        files.append((path, read(os.path.join(ROOT, *path.split("/")))))

    return files


def package_files():
    base = os.path.join(ROOT, "src")

    found = []

    for directory, subdirectories, files in os.walk(os.path.join(base, PACKAGE)):
        subdirectories[:] = sorted(name for name in subdirectories if name != "__pycache__")

        for name in sorted(files):
            if name.endswith(".py") or name == "py.typed":
                path = os.path.join(directory, name)

                found.append((os.path.relpath(path, base).replace(os.sep, "/"), read(path)))

    return found


def elf_target(data):
    if data[4:6] != b"\x02\x01":
        raise ValueError("the ELF library is not 64-bit little-endian")

    kind, machine = struct.unpack_from("<HH", data, 16)

    architecture = {0x3E: "x86_64", 0xB7: "aarch64", 0xF3: "riscv64"}.get(machine)

    if kind != 3 or architecture is None:
        raise ValueError("the ELF file is not a shared library of a supported architecture")

    # One file serves glibc and musl only while it needs no library at all: no DT_NEEDED entry.
    program_offset, = struct.unpack_from("<Q", data, 32)

    entry_size, count = struct.unpack_from("<HH", data, 54)

    for i in range(count):
        kind, _, offset, _, _, size = struct.unpack_from("<IIQQQQ", data, program_offset + i * entry_size)

        if kind != 2:
            continue

        for position in range(offset, offset + size, 16):
            tag, = struct.unpack_from("<q", data, position)

            if tag == 0:
                break

            if tag == 1:
                raise ValueError("the Linux library needs another library, so it cannot serve glibc and musl alike")

    return f"{architecture}-linux"


def macho_target(data):
    cpu, _, kind, commands = struct.unpack_from("<iiII", data, 4)

    architecture = {0x01000007: "x86_64", 0x0100000C: "aarch64"}.get(cpu)

    if kind != 6 or architecture is None:
        raise ValueError("the Mach-O file is not a dynamic library of a supported architecture")

    offset = 32

    for _ in range(commands):
        command, size = struct.unpack_from("<II", data, offset)

        # LC_BUILD_VERSION and LC_VERSION_MIN_MACOSX, whose minimum versions are xxxx.yy.zz.
        if command in (0x32, 0x24):
            minimum, = struct.unpack_from("<I", data, offset + (12 if command == 0x32 else 8))

            return f"{architecture}-macos", (minimum >> 16, (minimum >> 8) & 0xFF)

        offset += size

    raise ValueError("the Mach-O library records no minimum macOS version")


def pe_target(data):
    offset, = struct.unpack_from("<I", data, 0x3C)

    if data[offset : offset + 4] != b"PE\0\0":
        raise ValueError("the file is not a PE image")

    machine, = struct.unpack_from("<H", data, offset + 4)

    characteristics, = struct.unpack_from("<H", data, offset + 22)

    architecture = {0x8664: "x86_64", 0xAA64: "aarch64"}.get(machine)

    if not characteristics & 0x2000 or architecture is None:
        raise ValueError("the PE file is not a DLL of a supported architecture")

    return f"{architecture}-windows"


# The platform and the wheel's platform tags of a library, read from its own headers.
def library_platform(data):
    if data[:4] == b"\x7fELF":
        target, version = elf_target(data), None
    elif data[:4] == b"\xcf\xfa\xed\xfe":
        target, version = macho_target(data)
    elif data[:2] == b"MZ":
        target, version = pe_target(data), None
    else:
        raise ValueError("the library is not an ELF, Mach-O or PE file")

    name, tags = PLATFORMS[target]

    return target, name, tuple(tag.format(*version) if version else tag for tag in tags)


def native_files(path):
    data = read(path)

    target, name, tags = library_platform(data)

    if os.path.basename(path) != name:
        raise ValueError(f"a library for {target} must be named {name}")

    record = f"{RECORD_FORMAT}\nfile {name}\ntarget {target}\nsize {len(data)}\ncrc32 {binascii.crc32(data):08x}\n"

    return [(f"{PACKAGE}/{name}", data), (f"{PACKAGE}/{RECORD}", record.encode("ascii"))], tags


def wheel_metadata(table, tags, purelib):
    lines = ["Wheel-Version: 1.0", "Generator: crypto-pq cpq_build", f"Root-Is-Purelib: {'true' if purelib else 'false'}"]

    lines += [f"Tag: py3-none-{tag}" for tag in tags]

    files = [("METADATA", metadata(table)), ("WHEEL", ("\n".join(lines) + "\n").encode("ascii"))]

    return files + [(f"licenses/{path}", data) for path, data in license_files(table)]


def digest(data):
    return base64.urlsafe_b64encode(sha256(data)).rstrip(b"=").decode("ascii")


def write_wheel(directory, entries, table, tags, purelib):
    name = distribution(table)

    info = f"{name}-{table['version']}.dist-info"

    entries = sorted(entries) + [(f"{info}/{path}", data) for path, data in wheel_metadata(table, tags, purelib)]

    if any("," in path or '"' in path for path, _ in entries):
        raise ValueError("a file name in the wheel needs quoting in RECORD")

    record = "".join(f"{path},sha256={digest(data)},{len(data)}\n" for path, data in entries) + f"{info}/RECORD,,\n"

    entries.append((f"{info}/RECORD", record.encode("utf-8")))

    filename = f"{name}-{table['version']}-py3-none-{'.'.join(tags)}.whl"

    os.makedirs(directory, exist_ok=True)

    with zipfile.ZipFile(os.path.join(directory, filename), "w") as archive:
        for path, data in entries:
            entry = zipfile.ZipInfo(path, TIMESTAMP)

            entry.create_system = 3

            entry.compress_type = zipfile.ZIP_DEFLATED

            entry.external_attr = (0o100755 if path.endswith((".so", ".dylib", ".dll")) else 0o100644) << 16

            archive.writestr(entry, data, compresslevel=9)

    return filename


def build(directory, native=None):
    table = project()

    entries = package_files()

    if native is None:
        return write_wheel(directory, entries, table, ("any",), True)

    files, tags = native_files(native)

    return write_wheel(directory, entries + files, table, tags, False)


# PEP 660: a wheel whose .pth file puts the sources on sys.path. The native backend needs a
# library and its record next to them, which the sources do not hold, so this installs the pure
# backend.
def build_editable_wheel(directory):
    table = project()

    path = (os.path.join(ROOT, "src") + "\n").encode("utf-8")

    return write_wheel(directory, [(f"{PACKAGE}.pth", path)], table, ("any",), True)


def build_sdist_archive(directory):
    table = project()

    base = f"{distribution(table)}-{table['version']}"

    members = [("PKG-INFO", metadata(table)), ("pyproject.toml", read(os.path.join(ROOT, "pyproject.toml"))), ("build_backend/cpq_build.py", read(os.path.abspath(__file__)))]

    members += license_files(table)

    members += [(f"src/{path}", data) for path, data in package_files()]

    buffer = io.BytesIO()

    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for path, data in sorted(members):
            entry = tarfile.TarInfo(f"{base}/{path}")

            entry.size, entry.mtime, entry.mode = len(data), EPOCH, 0o644

            entry.uid = entry.gid = 0

            entry.uname = entry.gname = ""

            archive.addfile(entry, io.BytesIO(data))

    filename = f"{base}.tar.gz"

    os.makedirs(directory, exist_ok=True)

    with open(os.path.join(directory, filename), "wb") as handle:
        with gzip.GzipFile(filename="", mode="wb", fileobj=handle, compresslevel=9, mtime=EPOCH) as compressed:
            compressed.write(buffer.getvalue())

    return filename


def setting(config_settings, name):
    value = (config_settings or {}).get(name)

    if isinstance(value, list):
        raise ValueError(f"the config setting {name} takes one value")

    return value


def write_metadata(metadata_directory, config_settings, editable):
    table = project()

    native = None if editable else setting(config_settings, "native")

    tags = native_files(native)[1] if native else ("any",)

    info = f"{distribution(table)}-{table['version']}.dist-info"

    for path, data in wheel_metadata(table, tags, native is None):
        target = os.path.join(metadata_directory, info, *path.split("/"))

        os.makedirs(os.path.dirname(target), exist_ok=True)

        with open(target, "wb") as handle:
            handle.write(data)

    return info


# The PEP 517 and PEP 660 hooks.


def get_requires_for_build_wheel(config_settings=None):
    return []


def get_requires_for_build_sdist(config_settings=None):
    return []


def get_requires_for_build_editable(config_settings=None):
    return []


def prepare_metadata_for_build_wheel(metadata_directory, config_settings=None):
    return write_metadata(metadata_directory, config_settings, False)


def prepare_metadata_for_build_editable(metadata_directory, config_settings=None):
    return write_metadata(metadata_directory, config_settings, True)


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    return build(wheel_directory, setting(config_settings, "native"))


def build_editable(wheel_directory, config_settings=None, metadata_directory=None):
    return build_editable_wheel(wheel_directory)


def build_sdist(sdist_directory, config_settings=None):
    return build_sdist_archive(sdist_directory)


def main(arguments):
    command, directory, *rest = arguments

    if command == "wheel":
        print(build(directory, rest[rest.index("--native") + 1] if "--native" in rest else None))
    elif command == "sdist":
        print(build_sdist_archive(directory))
    elif command == "all":
        print(build(directory))

        for target, (name, _) in PLATFORMS.items():
            print(build(directory, os.path.join(rest[0], target, name)))

        print(build_sdist_archive(directory))
    else:
        raise SystemExit("usage: cpq_build.py wheel OUT_DIR [--native LIBRARY] | sdist OUT_DIR | all OUT_DIR DIST_DIR")


if __name__ == "__main__":
    main(sys.argv[1:])

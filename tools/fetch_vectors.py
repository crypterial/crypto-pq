import hashlib
import io
import pathlib
import sys
import urllib.request
import zipfile

VECTORS = pathlib.Path(__file__).resolve().parents[1] / "vectors"

CAVP = "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents"

ACVP = "https://raw.githubusercontent.com/usnistgov/ACVP-Server/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files"

CCTV = "https://raw.githubusercontent.com/C2SP/CCTV/4448f2097b2daa812c91a26141f9f36c2096b9ca/ML-KEM"

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

FILES = (
    (f"{ACVP}/ML-KEM-keyGen-FIPS203/prompt.json", "3f9ce34f6c836c77958bad2729e837c3b213f44ac36c3065976e7acca6389523", "acvp/ML-KEM-keyGen-FIPS203.prompt.json"),
    (f"{ACVP}/ML-KEM-keyGen-FIPS203/expectedResults.json", "a253d0ad91c95ebea5b409673defef0aa49d65d4ed72286399e2e798ddf073a4", "acvp/ML-KEM-keyGen-FIPS203.expectedResults.json"),
    (f"{ACVP}/ML-KEM-keyGen-FIPS203/internalProjection.json", "d7a62a2c3476957f56dd8d24f9004ea6776ccfe995ffe71a65bb9506dc9c7b1b", "acvp/ML-KEM-keyGen-FIPS203.internalProjection.json"),
    (f"{ACVP}/ML-KEM-encapDecap-FIPS203/prompt.json", "998e22dfb12efb14ce9fdff911ca634b13612819a1806f25da69adba7e16db91", "acvp/ML-KEM-encapDecap-FIPS203.prompt.json"),
    (f"{ACVP}/ML-KEM-encapDecap-FIPS203/expectedResults.json", "9089ec6ff2424da9f2782b89b2f831a329a3e28d6e5e24b802b78ff36ac61cdf", "acvp/ML-KEM-encapDecap-FIPS203.expectedResults.json"),
    (f"{ACVP}/ML-KEM-encapDecap-FIPS203/internalProjection.json", "a556952ce869bb89c3a3196a701dad89647c193a34c86eafb61a9d710d5b810f", "acvp/ML-KEM-encapDecap-FIPS203.internalProjection.json"),
    (f"{CCTV}/modulus/ML-KEM-512.txt.gz", "4292314fd44bb211a27ef38273dcac32f602601c2f65b15a69773221227bf298", "cctv/modulus-ML-KEM-512.txt.gz"),
    (f"{CCTV}/modulus/ML-KEM-768.txt.gz", "22308df988866e2731c9b79bfa0ce754ea962a77b198436d56bde6481a526af7", "cctv/modulus-ML-KEM-768.txt.gz"),
    (f"{CCTV}/modulus/ML-KEM-1024.txt.gz", "5792e788280ecdf5be7bfd2d8b66e18a0f9b9c80f4beb1d801fd27d20e882bf7", "cctv/modulus-ML-KEM-1024.txt.gz"),
    (f"{CCTV}/strcmp/ML-KEM-512.txt", "4bc308bf9a7ac41c0e1c6845e9195d4932f66650e09a4ff76ed780e5f606a42f", "cctv/strcmp-ML-KEM-512.txt"),
    (f"{CCTV}/strcmp/ML-KEM-768.txt", "2b09aa46d8b1c7b9a549a25f009cbd3937b98df177e868d3eb6395930079e4fa", "cctv/strcmp-ML-KEM-768.txt"),
    (f"{CCTV}/strcmp/ML-KEM-1024.txt", "5059fcb4d5912c37bef560e92608799b576cf785bc20708688f65ffcfca4adfb", "cctv/strcmp-ML-KEM-1024.txt"),
)


def fetch(url, expected):
    request = urllib.request.Request(url, headers={"User-Agent": "crypto-pq-vectors (+https://crypterial.com)"})

    data = urllib.request.urlopen(request, timeout=120).read()

    actual = hashlib.sha256(data).hexdigest()

    if actual != expected:
        sys.exit(f"{url}: sha256 {actual}, expected {expected}")

    return data


def write(relative, data):
    path = VECTORS / relative

    path.parent.mkdir(parents=True, exist_ok=True)

    path.write_bytes(data)


def main():
    for url, expected, members in ARCHIVES:
        archive = zipfile.ZipFile(io.BytesIO(fetch(url, expected)))

        for member, relative in members.items():
            write(relative, archive.read(member))

    for url, expected, relative in FILES:
        write(relative, fetch(url, expected))

    files = sorted(p for p in VECTORS.rglob("*") if p.is_file() and p.name != "SHA256SUMS")

    lines = [f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(VECTORS).as_posix()}" for p in files]

    (VECTORS / "SHA256SUMS").write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()

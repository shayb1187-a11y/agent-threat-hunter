"""Fetch the M14 external validation datasets listed in data/external/MANIFEST.json.

Everything under data/external/ except the manifest is gitignored; this script is how
it is recreated. Each file is verified against the sha256 recorded when it was first
fetched, so a silently changed upstream shows up as a failure, not as a changed number
in the evaluation table.

Two fetch styles, both read from the manifest:

* plain HTTP -- the dataset's ``url`` when it has one file, or a per-file ``url``;
* zip-range  -- DEDALE's Winlogbeat archive is a 27 GB deflate zip of hourly members
  and its host honours HTTP Range requests, so a member is fetched by offset from the
  committed zip index (``archive.index_file``) and never by downloading the archive.

Usage::

    python scripts/fetch_external.py                 # everything in the manifest
    python scripts/fetch_external.py flaws_cloud     # one dataset
    python scripts/fetch_external.py --verify-only   # checksums of what is on disk
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXTERNAL = ROOT / "data" / "external"
MANIFEST = EXTERNAL / "MANIFEST.json"
USER_AGENT = "agentic-threat-hunter/m14 (dataset fetch)"


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def http_get(url: str, byte_range: tuple[int, int] | None = None) -> bytes:
    headers = {"User-Agent": USER_AGENT}
    if byte_range is not None:
        headers["Range"] = f"bytes={byte_range[0]}-{byte_range[1]}"
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=600) as response:
        if byte_range is not None and response.status != 206:
            raise RuntimeError(f"{url}: server ignored Range (HTTP {response.status})")
        return response.read()


def fetch_plain(url: str, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    print(f"  GET {url}")
    target.write_bytes(http_get(url))


def fetch_zip_member(archive: dict, member_name: str, target: Path) -> None:
    """Range-fetch one stored/deflated member of a remote zip, as raw compressed bytes.

    The bytes written are exactly what the zip holds for that member (for DEDALE, a
    deflate stream wrapping a bz2 file); decoding is the reader's job, and keeping the
    on-disk form identical to the archive's is what lets the checksum mean something.
    """
    index = json.loads((EXTERNAL / archive["index_file"]).read_text(encoding="utf-8"))
    entry = next((e for e in index if e["name"].split("/")[-1] == member_name), None)
    if entry is None:
        raise KeyError(f"{member_name} is not in {archive['index_file']}")
    url = archive["url"]
    offset = int(entry["offset"])
    header = http_get(url, (offset, offset + 29))
    signature, *_rest = struct.unpack("<IHHHHHIIIHH", header)
    if signature != 0x04034B50:
        raise RuntimeError(f"{member_name}: no local file header at offset {offset}")
    name_len, extra_len = struct.unpack("<HH", header[26:30])
    start = offset + 30 + name_len + extra_len
    size = int(entry["usize"])
    print(f"  RANGE {url} bytes={start}-{start + size - 1} ({member_name})")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(http_get(url, (start, start + size - 1)))


def process(name: str, dataset: dict, verify_only: bool) -> bool:
    print(f"[{name}] {dataset.get('name', '')}")
    if dataset.get("_entry_kind") == "citation-only":
        # The manifest records the corpus for attribution and provenance, but it has no
        # URL this script can fetch from (COMISET is an interactive Zenodo download).
        # Skipping is not a failure: there is nothing on disk to verify either.
        print(f"  SKIP citation-only entry: {dataset.get('fetch_command', 'no fetch command')}")
        return True
    ok = True
    files = dataset.get("files", [])
    for spec in files:
        target = EXTERNAL / spec["path"]
        if not target.exists():
            if verify_only:
                print(f"  MISSING {spec['path']}")
                ok = False
                continue
            if "archive" in dataset and spec["path"].endswith(".bz2"):
                fetch_zip_member(dataset["archive"], Path(spec["path"]).name, target)
            else:
                url = spec.get("url") or (dataset.get("url") if len(files) == 1 else None)
                if not url:
                    print(f"  SKIP {spec['path']}: no url for a multi-file dataset entry")
                    ok = False
                    continue
                fetch_plain(url, target)
        actual = sha256_of(target)
        if actual != spec["sha256"]:
            print(f"  CHECKSUM MISMATCH {spec['path']}: {actual} != {spec['sha256']}")
            ok = False
        else:
            print(f"  ok {spec['path']} ({target.stat().st_size:,} bytes)")
    return ok


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("datasets", nargs="*", help="Manifest keys to fetch (default: all).")
    parser.add_argument("--verify-only", action="store_true",
                        help="Do not download; only checksum what is already on disk.")
    args = parser.parse_args(argv)

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))["datasets"]
    names = args.datasets or list(manifest)
    unknown = [n for n in names if n not in manifest]
    if unknown:
        print(f"unknown dataset(s): {unknown}; known: {sorted(manifest)}")
        return 2
    all_ok = all(process(n, manifest[n], args.verify_only) for n in names)
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())

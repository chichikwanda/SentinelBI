"""Dataset downloader (Phase 2). Verified sources only; records SHA-256 of every file.

    python -I -m sentinelbi_ml.download nf-unsw-nb15-v2 --out data/raw

Nothing is guessed: the signed download URL is obtained from the host's own API, the licence
text it returns is printed and stored in the manifest, and a failed download exits non-zero
(design rule 7: if a URL has changed or a download fails, stop and tell the user).

Downloaded archives are untrusted data: each dataset goes into its own new directory and
members are extracted with path checks (no zip-slip).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import struct
import sys
import time
import urllib.request
import zipfile
import zlib
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

UQ_API = "https://api.rdm.uq.edu.au"


@dataclass(frozen=True)
class Dataset:
    key: str
    uq_uuid: (
        str  # dataset id on rdm.uq.edu.au (from https://staff.itee.uq.edu.au/marius/NIDS_datasets/)
    )
    landing_page: str
    citation: str


DATASETS: dict[str, Dataset] = {
    "nf-unsw-nb15-v2": Dataset(
        key="nf-unsw-nb15-v2",
        uq_uuid="8c6e2a00-ef9c-11ed-827d-e762de186848",
        landing_page="https://staff.itee.uq.edu.au/marius/NIDS_datasets/",
        citation=(
            "Sarhan, Layeghy, Portmann. Towards a Standard Feature Set for Network Intrusion "
            "Detection System Datasets. Mobile Networks and Applications, 2022. "
            "https://doi.org/10.1007/s11036-021-01843-0"
        ),
    ),
    "nf-cse-cic-ids2018-v2": Dataset(
        key="nf-cse-cic-ids2018-v2",
        uq_uuid="ce5161d0-ef9c-11ed-827d-e762de186848",
        landing_page="https://staff.itee.uq.edu.au/marius/NIDS_datasets/",
        citation=(
            "Sarhan, Layeghy, Portmann. Towards a Standard Feature Set for Network Intrusion "
            "Detection System Datasets. Mobile Networks and Applications, 2022. "
            "https://doi.org/10.1007/s11036-021-01843-0"
        ),
    ),
}


def _get_json(url: str) -> dict:  # type: ignore[type-arg]
    with urllib.request.urlopen(url, timeout=60) as resp:  # noqa: S310 - https URL constant
        return json.load(resp)  # type: ignore[no-any-return]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _stream(url: str, dest: Path) -> int:
    started = time.monotonic()
    done = 0
    with urllib.request.urlopen(url, timeout=120) as resp, dest.open("wb") as out:  # noqa: S310
        total = int(resp.headers.get("Content-Length", "0"))
        while chunk := resp.read(1 << 20):
            out.write(chunk)
            done += len(chunk)
            rate = done / max(time.monotonic() - started, 1e-6) / 1024
            print(
                f"\r  {done / 1e6:7.1f} / {total / 1e6:.1f} MB  {rate:6.0f} kB/s",
                end="",
                flush=True,
            )
    print()
    if total and done != total:
        raise OSError(f"truncated download: got {done} of {total} bytes")
    return done


def _member_chunks(zip_path: Path, info: zipfile.ZipInfo) -> Iterator[bytes]:
    """Yield a member's decompressed bytes by inflating the raw stream ourselves.

    Python's ``ZipFile.open`` raises on a CRC mismatch at end of stream and the last chunk is
    lost; we need ALL the bytes so they can be checked against the publisher's own checksum.
    """
    if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
        raise ValueError(f"unsupported compression method {info.compress_type} for {info.filename}")
    with zip_path.open("rb") as fh:
        fh.seek(info.header_offset)
        header = fh.read(30)
        name_len, extra_len = struct.unpack("<HH", header[26:30])
        fh.seek(name_len + extra_len, 1)
        inflater = zlib.decompressobj(-15) if info.compress_type == zipfile.ZIP_DEFLATED else None
        remaining = info.compress_size
        while remaining > 0:
            chunk = fh.read(min(1 << 22, remaining))
            if not chunk:
                raise OSError(f"archive truncated inside {info.filename}")
            remaining -= len(chunk)
            yield inflater.decompress(chunk) if inflater else chunk
        if inflater:
            yield inflater.flush()
            if not inflater.eof:
                raise ValueError(f"incomplete deflate stream for {info.filename}")


def _bagit_sha1(bag_root: Path) -> dict[str, str]:
    """Publisher checksums from a BagIt ``manifest-sha1.txt`` (relative path -> sha1), if present."""
    manifest = bag_root / "manifest-sha1.txt"
    if not manifest.exists():
        return {}
    out: dict[str, str] = {}
    for line in manifest.read_text(encoding="utf-8").splitlines():
        digest, _, rel = line.strip().partition(" ")
        if digest and rel.strip():
            out[rel.strip()] = digest.lower()
    return out


def _extract_verified(zip_path: Path, target: Path) -> dict[str, dict[str, Any]]:
    """Extract every member (no path escapes) and verify it. A file is accepted if the zip's own
    CRC-32 matches OR the publisher's BagIt SHA-1 matches; otherwise the download is rejected."""
    root = target.resolve()
    extracted: dict[str, dict[str, Any]] = {}
    with zipfile.ZipFile(zip_path) as zf:
        members = [m for m in zf.infolist() if not m.is_dir()]
    for info in members:
        dest = (root / info.filename).resolve()
        if root not in dest.parents:
            raise ValueError(f"refusing to extract outside the target directory: {info.filename}")
        dest.parent.mkdir(parents=True, exist_ok=True)
        sha1, sha256, crc, size = hashlib.sha1(), hashlib.sha256(), 0, 0  # noqa: S324 - integrity only
        with dest.open("wb") as out:
            for chunk in _member_chunks(zip_path, info):
                out.write(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
                crc = zlib.crc32(chunk, crc)
                size += len(chunk)
        if size != info.file_size:
            raise ValueError(
                f"{info.filename}: got {size:,d} bytes, archive declares {info.file_size:,d}"
            )
        extracted[info.filename] = {
            "path": dest,
            "bytes": size,
            "sha256": sha256.hexdigest(),
            "sha1": sha1.hexdigest(),
            "zip_crc32_ok": (crc & 0xFFFFFFFF) == info.CRC,
        }
    # the bag directory is the top-level folder of the archive
    bag_root = next((e["path"].parent.parent for n, e in extracted.items() if "/data/" in n), root)
    publisher = _bagit_sha1(bag_root)
    for name, e in extracted.items():
        rel = e["path"].relative_to(bag_root).as_posix()
        e["publisher_sha1_ok"] = (publisher[rel] == e["sha1"]) if rel in publisher else None
        if not e["zip_crc32_ok"] and e["publisher_sha1_ok"] is not True:
            raise ValueError(
                f"{name}: fails the zip CRC-32 and is not confirmed by a publisher SHA-1; "
                "the data cannot be verified, refusing it"
            )
        if not e["zip_crc32_ok"]:
            print(
                f"  NOTE {name}: the zip CRC-32 does not match, but the content matches the "
                "publisher's own SHA-1 (BagIt manifest): accepted, and recorded in MANIFEST.json"
            )
    return extracted


def fetch(ds: Dataset, out_root: Path, reextract: bool = False) -> int:
    target = (out_root / ds.key).resolve()
    zip_path = target / f"{ds.key}.zip"
    if target.exists() and not (reextract and zip_path.exists()):
        print(f"{target} already exists; refusing to overwrite (delete it to re-download)")
        return 1
    meta = _get_json(f"{UQ_API}/datasets/{ds.uq_uuid}/file-details")
    if meta.get("accessType") != "OPEN" or meta.get("status") != "PUBLISHED":
        print(f"dataset is not openly published (accessType={meta.get('accessType')}); stopping")
        return 2
    print(
        f"{meta['name']}: licence/terms from the host:\n  "
        + meta["description"].replace("\n", "\n  ")
    )
    if reextract:
        for child in target.iterdir():  # keep only the archive we already downloaded
            if child != zip_path:
                shutil.rmtree(child) if child.is_dir() else child.unlink()
        print(f"re-extracting {zip_path} (no new download)")
    else:
        link = _get_json(f"{UQ_API}/datasets/{ds.uq_uuid}/download")
        if link.get("packagingStatus") != 0 or not link.get("url"):
            print("host reports the archive is not ready for download; stopping")
            return 2
        target.mkdir(parents=True)
        print(f"downloading to {zip_path}")
        _stream(link["url"], zip_path)

    extracted = _extract_verified(zip_path, target)
    files: dict[str, dict[str, Any]] = {
        zip_path.name: {"bytes": zip_path.stat().st_size, "sha256": sha256_file(zip_path)}
    }
    for e in extracted.values():
        files[e["path"].relative_to(target).as_posix()] = {
            "bytes": e["bytes"],
            "sha256": e["sha256"],
            "sha1": e["sha1"],
            "zip_crc32_ok": e["zip_crc32_ok"],
            "publisher_sha1_ok": e["publisher_sha1_ok"],
        }
    manifest = {
        "dataset": ds.key,
        "source_page": ds.landing_page,
        "host_dataset_uuid": ds.uq_uuid,
        "licence_text_from_host": meta["description"],
        "citation": ds.citation,
        "downloaded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "files": files,
    }
    (target / "MANIFEST.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print("\nSHA-256 (copy into data/DATASETS.md):")
    for name, info in files.items():
        flag = (
            "" if info.get("zip_crc32_ok", True) else "   (zip CRC wrong; publisher SHA-1 verified)"
        )
        print(f"  {info['sha256']}  {info['bytes']:>14,d}  {name}{flag}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("dataset", choices=sorted(DATASETS))
    parser.add_argument("--out", type=Path, default=Path("data/raw"))
    parser.add_argument(
        "--reextract",
        action="store_true",
        help="re-extract and re-verify an already downloaded archive (no new download)",
    )
    args = parser.parse_args()
    try:
        return fetch(DATASETS[args.dataset], args.out, args.reextract)
    except (OSError, ValueError, zipfile.BadZipFile, KeyError) as exc:
        print(f"download failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())

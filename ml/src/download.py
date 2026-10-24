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
import sys
import time
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path

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


def _safe_extract(zf: zipfile.ZipFile, target: Path) -> list[Path]:
    root = target.resolve()
    out: list[Path] = []
    for member in zf.infolist():
        dest = (root / member.filename).resolve()
        if root != dest and root not in dest.parents:
            raise ValueError(f"refusing to extract outside the target directory: {member.filename}")
        if member.is_dir():
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        with zf.open(member) as src, dest.open("wb") as dst:
            while chunk := src.read(1 << 20):
                dst.write(chunk)
        out.append(dest)
    return out


def fetch(ds: Dataset, out_root: Path) -> int:
    target = (out_root / ds.key).resolve()
    if target.exists():
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
    link = _get_json(f"{UQ_API}/datasets/{ds.uq_uuid}/download")
    if link.get("packagingStatus") != 0 or not link.get("url"):
        print("host reports the archive is not ready for download; stopping")
        return 2

    target.mkdir(parents=True)
    zip_path = target / f"{ds.key}.zip"
    print(f"downloading to {zip_path}")
    _stream(link["url"], zip_path)
    with zipfile.ZipFile(zip_path) as zf:
        files = _safe_extract(zf, target)

    manifest = {
        "dataset": ds.key,
        "source_page": ds.landing_page,
        "host_dataset_uuid": ds.uq_uuid,
        "licence_text_from_host": meta["description"],
        "citation": ds.citation,
        "downloaded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "files": {
            p.relative_to(target).as_posix(): {"bytes": p.stat().st_size, "sha256": sha256_file(p)}
            for p in [zip_path, *files]
        },
    }
    (target / "MANIFEST.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print("\nSHA-256 (copy into data/DATASETS.md):")
    for name, info in manifest["files"].items():
        print(f"  {info['sha256']}  {info['bytes']:>12,d}  {name}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("dataset", choices=sorted(DATASETS))
    parser.add_argument("--out", type=Path, default=Path("data/raw"))
    args = parser.parse_args()
    try:
        return fetch(DATASETS[args.dataset], args.out)
    except (OSError, ValueError, zipfile.BadZipFile, KeyError) as exc:
        print(f"download failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())

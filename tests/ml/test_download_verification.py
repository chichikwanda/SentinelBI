"""Archive extraction is verified: zip CRC OR the publisher's BagIt SHA-1, never neither.

Motivation: a first extraction of the NF-CSE-CIC-IDS2018-v2 archive reported a CRC-32 mismatch.
Later re-reads verified (CRC and the publisher's SHA-1), so the cause of the first failure is
unexplained; the downloader therefore checks both and refuses anything that passes neither.
"""

from __future__ import annotations

import hashlib
import zipfile
import zlib
from pathlib import Path

import pytest

from sentinelbi_ml.download import _extract_verified

PAYLOAD = b"IPV4_SRC_ADDR,L4_SRC_PORT\n" + b"10.0.0.1,80\n" * 5000


def make_zip(path: Path, *, manifest: bool, corrupt_crc: bool, wrong_sha1: bool = False) -> None:
    sha1 = hashlib.sha1(PAYLOAD).hexdigest()  # noqa: S324 - mirrors the publisher's manifest format
    if wrong_sha1:
        sha1 = "0" * 40
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("bag/data/set.csv", PAYLOAD)
        if manifest:
            zf.writestr("bag/manifest-sha1.txt", f"{sha1}  data/set.csv\n")
    if corrupt_crc:
        raw = path.read_bytes()
        good = zlib.crc32(PAYLOAD).to_bytes(4, "little")
        assert raw.count(good) == 2  # local header + central directory
        path.write_bytes(raw.replace(good, b"\xde\xad\xbe\xef"))


def test_clean_archive_is_accepted(tmp_path: Path) -> None:
    make_zip(tmp_path / "a.zip", manifest=True, corrupt_crc=False)
    out = _extract_verified(tmp_path / "a.zip", tmp_path / "x")
    e = out["bag/data/set.csv"]
    assert e["zip_crc32_ok"] is True and e["publisher_sha1_ok"] is True
    assert e["sha256"] == hashlib.sha256(PAYLOAD).hexdigest()
    assert (
        tmp_path / "x" / "bag" / "data" / "set.csv"
    ).read_bytes() == PAYLOAD  # every byte written


def test_wrong_zip_crc_is_accepted_only_when_the_publisher_sha1_confirms(tmp_path: Path) -> None:
    make_zip(tmp_path / "a.zip", manifest=True, corrupt_crc=True)
    e = _extract_verified(tmp_path / "a.zip", tmp_path / "x")["bag/data/set.csv"]
    assert e["zip_crc32_ok"] is False and e["publisher_sha1_ok"] is True
    # the whole file is on disk, including the final chunk Python's own reader would have dropped
    assert (tmp_path / "x" / "bag" / "data" / "set.csv").read_bytes() == PAYLOAD


def test_wrong_crc_without_any_publisher_checksum_is_rejected(tmp_path: Path) -> None:
    make_zip(tmp_path / "a.zip", manifest=False, corrupt_crc=True)
    with pytest.raises(ValueError, match="cannot be verified"):
        _extract_verified(tmp_path / "a.zip", tmp_path / "x")


def test_wrong_crc_and_disagreeing_publisher_sha1_is_rejected(tmp_path: Path) -> None:
    make_zip(tmp_path / "a.zip", manifest=True, corrupt_crc=True, wrong_sha1=True)
    with pytest.raises(ValueError, match="cannot be verified"):
        _extract_verified(tmp_path / "a.zip", tmp_path / "x")


def test_path_traversal_members_are_refused(tmp_path: Path) -> None:
    with zipfile.ZipFile(tmp_path / "evil.zip", "w") as zf:
        zf.writestr("../escape.txt", b"nope")
    with pytest.raises(ValueError, match="outside"):
        _extract_verified(tmp_path / "evil.zip", tmp_path / "x")
    assert not (tmp_path / "escape.txt").exists()

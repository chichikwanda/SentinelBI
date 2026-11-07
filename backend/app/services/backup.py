"""Backups from the web interface (Settings > Backups): create, and prove a backup can be restored.

    python -m app.services.backup create           # database dump + trained models + SHA256SUMS
    python -m app.services.backup check <folder>   # checksum, readable dump, and a trial restore

Run by the trainer service as a job. A backup holds password hashes, API-key hashes and every
organisation's flow data: the folder is sensitive. "check" restores into a scratch database and
drops it again; it never touches the live one. Restoring over the live database stays a deliberate
step outside the web interface (scripts/restore.sh with FORCE=1), because it destroys current data.
"""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy.engine import make_url

from app.core.config import get_settings

SCRATCH_DB = "sentinelbi_restore_check"
FOLDER = re.compile(r"^\d{8}T\d{6}Z$")


def _say(msg: str) -> None:
    print(msg, flush=True)


def _dsn(database: str | None = None) -> str:
    url = make_url(get_settings().database_url).set(drivername="postgresql")
    if database:
        url = url.set(database=database)
    return url.render_as_string(hide_password=False)


def _run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, check=True, capture_output=True, text=True)  # noqa: S603


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def create(backups_dir: Path, models_dir: Path) -> Path:
    out = backups_dir / datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    out.mkdir(parents=True)
    _say("dumping the database ...")
    dump = out / "db.dump"
    _run(["pg_dump", "-Fc", "-f", str(dump), _dsn()])
    # a dump that cannot be read back is not a backup: list its contents before trusting it
    _run(["pg_restore", "--list", str(dump)])
    _say(f"dump is readable ({dump.stat().st_size:,} bytes)")
    if models_dir.is_dir():
        _say("copying trained models ...")
        shutil.copytree(models_dir, out / "models", ignore=shutil.ignore_patterns(".*"))
    (out / "SHA256SUMS").write_text(f"{sha256(dump)}  db.dump\n", encoding="utf-8")
    _say(f"backup {out.name}")
    return out


def check(folder: Path) -> dict[str, int]:
    dump, sums = folder / "db.dump", folder / "SHA256SUMS"
    if not dump.is_file() or not sums.is_file():
        raise SystemExit("not a backup folder (db.dump or SHA256SUMS missing)")
    if sums.read_text(encoding="utf-8").split()[0] != sha256(dump):
        raise SystemExit("checksum mismatch: the dump has changed since it was made")
    _say("checksum matches")
    _run(["pg_restore", "--list", str(dump)])
    _say("dump is readable; restoring into a scratch database ...")
    admin = _dsn("postgres")
    _run(["psql", admin, "-v", "ON_ERROR_STOP=1", "-c", f'DROP DATABASE IF EXISTS "{SCRATCH_DB}"'])
    _run(["psql", admin, "-v", "ON_ERROR_STOP=1", "-c", f'CREATE DATABASE "{SCRATCH_DB}"'])
    try:
        # TimescaleDB dumps restore with warnings about already-existing extension objects: those
        # are expected, so only a failure to restore the data tables is an error (checked below).
        subprocess.run(  # noqa: S603
            ["pg_restore", "--no-owner", "-d", _dsn(SCRATCH_DB), str(dump)],  # noqa: S607
            capture_output=True,
            text=True,
            check=False,
        )
        counts: dict[str, int] = {}
        for table in ("organizations", "users", "sources", "alerts", "flows"):
            query = f"SELECT count(*) FROM {table}"  # noqa: S608 - fixed table names
            res = _run(["psql", _dsn(SCRATCH_DB), "-At", "-c", query])
            counts[table] = int(res.stdout.strip())
        _say("restored: " + ", ".join(f"{k}={v}" for k, v in counts.items()))
        _say("check passed")
        return counts
    finally:
        _run(["psql", admin, "-c", f'DROP DATABASE IF EXISTS "{SCRATCH_DB}"'])


def list_backups(backups_dir: Path) -> list[dict[str, object]]:
    if not backups_dir.is_dir():
        return []
    out: list[dict[str, object]] = []
    for d in sorted(backups_dir.iterdir(), reverse=True):
        if d.is_dir() and FOLDER.match(d.name) and (d / "db.dump").is_file():
            out.append(
                {
                    "name": d.name,
                    "bytes": sum(f.stat().st_size for f in d.rglob("*") if f.is_file()),
                    "has_models": (d / "models").is_dir(),
                }
            )
    return out


def main(argv: list[str]) -> int:
    s = get_settings()
    root, models = Path(s.backups_dir), Path(s.models_dir)
    if argv[:1] == ["create"]:
        create(root, models)
        return 0
    if argv[:1] == ["check"] and len(argv) == 2 and FOLDER.match(argv[1]):
        check(root / argv[1])
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

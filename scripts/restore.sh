#!/usr/bin/env bash
# Restore a backup made by scripts/backup.sh.
#
#   bash scripts/restore.sh <backup-dir> [target-database]
#
# The default target is a SCRATCH database (sentinelbi_restore_check) so a backup can be verified
# without touching live data. To replace the live database, stop everything that writes to it first
#
#   docker compose stop api worker collector web
#   FORCE=1 bash scripts/restore.sh backups/<timestamp> <the POSTGRES_DB name>
#   docker compose up -d --wait
#
# and note that the live database is dropped and recreated. Models are copied back with
#   cp -r <backup-dir>/models/. ml/models/
set -euo pipefail
cd "$(dirname "$0")/.."

dir="${1:?usage: restore.sh <backup-dir> [target-database]}"
target="${2:-sentinelbi_restore_check}"
[ -f "$dir/db.dump" ] || { echo "no db.dump in $dir" >&2; exit 1; }
(cd "$dir" && sha256sum --check --quiet SHA256SUMS) || { echo "backup checksum mismatch: refusing" >&2; exit 1; }

live="$(docker compose exec -T db sh -c 'printf %s "$POSTGRES_DB"')"
if [ "$target" = "$live" ] && [ "${FORCE:-}" != "1" ]; then
  echo "refusing to overwrite the live database '$live' without FORCE=1 (see the header of this script)" >&2
  exit 1
fi
case "$target" in *[!a-zA-Z0-9_]*) echo "invalid database name" >&2; exit 1 ;; esac

psql() { docker compose exec -T db sh -c "psql -v ON_ERROR_STOP=1 -U \"\$POSTGRES_USER\" -d $1" ; }

echo "recreating database $target ..."
echo "DROP DATABASE IF EXISTS $target WITH (FORCE);" | psql postgres
echo "CREATE DATABASE $target;" | psql postgres

# TimescaleDB needs its pre/post-restore calls around pg_restore, or hypertable metadata is lost
echo "CREATE EXTENSION IF NOT EXISTS timescaledb; SELECT timescaledb_pre_restore();" | psql "$target" > /dev/null

echo "restoring ..."
# pg_restore reports the already-present extension as an error; everything else must be clean
log="$(docker compose exec -T db sh -c "pg_restore -U \"\$POSTGRES_USER\" -d $target --no-owner" < "$dir/db.dump" 2>&1 || true)"
unexpected="$(printf '%s\n' "$log" | grep -i "error" | grep -v -i "extension \"timescaledb\" already exists" || true)"
if [ -n "$unexpected" ]; then
  echo "restore reported problems:" >&2
  printf '%s\n' "$unexpected" >&2
  exit 1
fi

echo "SELECT timescaledb_post_restore();" | psql "$target" > /dev/null
echo "restored into database $target"

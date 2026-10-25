#!/usr/bin/env bash
# Back up the database and the trained models into backups/<UTC timestamp>/ (or the directory given).
#
#   bash scripts/backup.sh [target-dir]
#
# The dump holds password hashes, API-key hashes and every organisation's flow data: treat the folder
# as sensitive. backups/ is gitignored. Needs the stack running (`docker compose up -d`).
set -euo pipefail
cd "$(dirname "$0")/.."

out="${1:-backups/$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$out"

echo "dumping the database ..."
docker compose exec -T db sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc' > "$out/db.dump"

# a dump that cannot be read back is not a backup: list its contents before trusting it
docker compose exec -T db pg_restore --list < "$out/db.dump" > /dev/null
echo "dump is readable ($(wc -c < "$out/db.dump") bytes)"

if [ -d ml/models ]; then
  mkdir -p "$out/models"
  # models are gitignored and cost ~15 minutes to retrain; _superseded/ holds retired ones
  cp -r ml/models/. "$out/models/"
fi

(cd "$out" && sha256sum db.dump > SHA256SUMS)
echo "backup written to $out"

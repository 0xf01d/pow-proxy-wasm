#!/bin/sh
# Build the embedded ipintel DB (data/ipintel.bin, ~15MB, gitignored).
#
# This is the recipe that used to live inline in the Makefile `ipintel-db`
# target — same CLI, same fetch/build steps, same --exclude list. The DB is a
# build-time artifact: never committed; the daily refresh workflow uploads it
# as a workflow artifact and records size + sha256 + record count on the
# refresh PR instead.
#
# Usage: scripts/build-ipintel-db.sh [--force]
#   --force  rebuild even if data/ipintel.bin already exists (the daily job
#            uses this; a plain `make build` skips an existing DB).
#
# Also writes data/ipintel.manifest.json (the exact manifest embedded in the
# .bin, extracted from its header) — gitignored too, because built_at changes
# on every rebuild. The ip-intel CLI has no --manifest flag, so the manifest
# is pulled out of the .bin: 28-byte header (magic, version, manifest len,
# index len, data offset), then the manifest JSON verbatim.
set -eu

REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$REPO"

DB="data/ipintel.bin"
MANIFEST="data/ipintel.manifest.json"
RAW="data/raw-tmp"
# Identical to the original Makefile target — do not change what goes into
# the DB without updating docs and the ipintel docs together.
EXCLUDE="geolite2-country,geolite2-asn,aws,gcp,cloudflare,oracle,digitalocean,linode,fastly"

FORCE=0
for arg in ${1+"$@"}; do
	case "$arg" in
	--force) FORCE=1 ;;
	-h | --help)
		sed -n '/^# Usage/,/^set -eu/p' "$0" | sed 's/^# \{0,1\}//'
		exit 0
		;;
	*)
		echo "build-ipintel-db.sh: unknown option: $arg" >&2
		exit 2
		;;
	esac
done

if [ "$FORCE" = "0" ] && [ -f "$DB" ]; then
	echo "ipintel DB ready: $DB ($(wc -c <"$DB") bytes) — exists, skipping (use --force to rebuild)"
	exit 0
fi

IPINTEL="$(go env GOPATH)/bin/ip-intel"
if [ ! -x "$IPINTEL" ]; then
	echo "==> installing ip-intel CLI"
	go install github.com/iakat/ipintel/cmd/ip-intel@latest
fi

echo "==> fetching ipintel sources"
"$IPINTEL" fetch --out "$RAW"
echo "==> building ipintel DB (excludes: $EXCLUDE)"
mkdir -p data
"$IPINTEL" build --raw "$RAW/raw" --db "$DB" --exclude "$EXCLUDE"
rm -rf "$RAW"

# Manifest: extract the embedded one from the .bin header (verbatim), then
# print the audit numbers the refresh workflow records on the PR.
manifest_len=$(od -An -tu4 -j12 -N4 --endian=little "$DB" | tr -d ' \n')
tail -c +29 "$DB" | head -c "$manifest_len" >"$MANIFEST"
RECORDS=$(python3 -c "import json;print(json.load(open('$MANIFEST'))['record_count'])")
BYTES=$(wc -c <"$DB")
SHA=$(sha256sum "$DB" | awk '{print $1}')
echo "ipintel db: ${BYTES} bytes sha256 ${SHA} record_count ${RECORDS}"
echo "manifest written: $MANIFEST"

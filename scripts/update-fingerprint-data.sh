#!/bin/sh
# Refresh the vendored fingerprint data (data/fingerprints/) and regenerate the
# Go files built from it (fpdata_gen.go, fpbrowsers_gen.go). Run daily by
# .github/workflows/refresh-data.yml; safe to run by hand — a quiet day is a
# no-op (every write is cmp-gated).
#
# Usage: scripts/update-fingerprint-data.sh [options]
#   --no-foxio     Do not fetch the FoxIO ja4plus mapping; emit fpdata_gen.go
#                  as an empty denylist stub (w_known_bad_ja4 becomes inert).
#                  The FoxIO data is licensed for non-commercial use only —
#                  use this flag if that license does not fit your deployment.
#   --no-browsers  Do not fetch browser-fingerprints.json; emit
#                  fpbrowsers_gen.go with the original hand-written family
#                  table (the pre-vendoring behavior).
#   --no-ipintel   Skip the ipintel DB rebuild (scripts/build-ipintel-db.sh is
#                  invoked by the caller, not by this script; the flag is
#                  accepted so one flag set can be forwarded and is echoed in
#                  the summary).
#   --check        Fetch + validate only; never writes the tree. Used by the
#                  upstream-health workflow job to fail loudly when upstream
#                  breaks (network or schema change).
#   --fixtures=DIR Test hook: use DIR/foxio-ja4plus-mapping.csv and
#                  DIR/browser-fingerprints.json instead of fetching (no
#                  network). Exercised by TestUpdateFingerprintData.
#
# Exit != 0 on: fetch failure (non-200, empty body), validation failure
# (header mismatch, shape violation, count below minimum), or generation
# failure. A truncated or garbage upstream file can never land in the tree.
set -eu

FOXIO_CSV_URL="https://raw.githubusercontent.com/FoxIO-LLC/ja4/main/ja4plus-mapping.csv"
FOXIO_LICENSE_URL="https://raw.githubusercontent.com/FoxIO-LLC/ja4/main/LICENSE"
BROWSERS_URL="https://raw.githubusercontent.com/North-web-dev/fingerprint-db/main/fingerprints.json"
FPDB_LICENSE_URL="https://raw.githubusercontent.com/North-web-dev/fingerprint-db/main/LICENSE"
FOXIO_REPO="FoxIO-LLC/ja4"
FPDB_REPO="North-web-dev/fingerprint-db"

NO_FOXIO=0
NO_BROWSERS=0
NO_IPINTEL=0
CHECK=0
FIXTURES=""

for arg in ${1+"$@"}; do
	case "$arg" in
	--no-foxio) NO_FOXIO=1 ;;
	--no-browsers) NO_BROWSERS=1 ;;
	--no-ipintel) NO_IPINTEL=1 ;;
	--check) CHECK=1 ;;
	--fixtures=*) FIXTURES=${arg#--fixtures=} ;;
	-h | --help)
		sed -n '/^# Usage/,/^set -eu/p' "$0" | sed 's/^# \{0,1\}//'
		exit 0
		;;
	*)
		echo "update-fingerprint-data.sh: unknown option: $arg" >&2
		exit 2
		;;
	esac
done

REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
DATA="$REPO/data/fingerprints"

command -v python3 >/dev/null 2>&1 || {
	echo "FATAL: update-fingerprint-data.sh requires python3 (JSON validation + Go generation)" >&2
	exit 1
}
if [ -z "$FIXTURES" ]; then
	command -v curl >/dev/null 2>&1 || {
		echo "FATAL: update-fingerprint-data.sh requires curl (or --fixtures=DIR for offline runs)" >&2
		exit 1
	}
fi

TMP=$(mktemp -d "${TMPDIR:-/tmp}/fpdata.XXXXXX")
trap 'rm -rf "$TMP"' EXIT INT TERM

# fetch URL OUTFILE — fails hard on non-200 (curl -f) or an empty body.
fetch() {
	curl -fsS --max-time 60 -o "$2" "$1" ||
		{ echo "FATAL: fetch failed (non-200 or network error): $1" >&2; exit 1; }
	[ -s "$2" ] || { echo "FATAL: empty body: $1" >&2; exit 1; }
}

# lookup_sha OWNER/REPO — best-effort upstream head commit sha; "unknown" when
# the API is unreachable or rate-limited (a metadata outage must not fail the
# daily run; the data fetch itself is the loud part).
lookup_sha() {
	curl -fsS --max-time 30 "https://api.github.com/repos/$1/commits?per_page=1" 2>/dev/null |
		python3 -c 'import json,sys
try:
    print(json.load(sys.stdin)[0]["sha"])
except Exception:
    print("unknown")' ||
		echo "unknown"
}

# --- 1. fetch ---------------------------------------------------------------

FOXIO_SHA="fixture"
FPDB_SHA="fixture"
if [ -n "$FIXTURES" ]; then
	[ -d "$FIXTURES" ] || { echo "FATAL: fixtures dir not found: $FIXTURES" >&2; exit 1; }
	if [ "$NO_FOXIO" = "0" ]; then
		cp "$FIXTURES/foxio-ja4plus-mapping.csv" "$TMP/foxio-ja4plus-mapping.csv"
	fi
	if [ "$NO_BROWSERS" = "0" ]; then
		cp "$FIXTURES/browser-fingerprints.json" "$TMP/browser-fingerprints.json"
	fi
	# fixtures mode provides no license files: use the tree's copies so the
	# cmp-gated install below treats them as unchanged.
	for lic in foxio-LICENSE fingerprint-db-LICENSE; do
		[ -f "$DATA/LICENSES/$lic" ] && cp "$DATA/LICENSES/$lic" "$TMP/$lic"
	done
else
	if [ "$NO_FOXIO" = "0" ]; then
		fetch "$FOXIO_CSV_URL" "$TMP/foxio-ja4plus-mapping.csv"
		fetch "$FOXIO_LICENSE_URL" "$TMP/foxio-LICENSE"
		FOXIO_SHA=$(lookup_sha "$FOXIO_REPO")
	fi
	if [ "$NO_BROWSERS" = "0" ]; then
		fetch "$BROWSERS_URL" "$TMP/browser-fingerprints.json"
		fetch "$FPDB_LICENSE_URL" "$TMP/fingerprint-db-LICENSE"
		FPDB_SHA=$(lookup_sha "$FPDB_REPO")
	fi
fi

# --- 2. validate ------------------------------------------------------------

# JA4 shape gate. This implements the plugin's own validator (normalizeJA4 in
# ja4.go): 36 chars, t|q|d first, d|i at index 3, lowercase alnum elsewhere in
# part a, two 12-lower-hex parts. Deliberately NOT the stricter `...h[0-9]...`
# regex (ALPN required in part a): upstream legitimately ships no-ALPN
# fingerprints (IcedID `t13d201100…`, SoftEther `t13d880900…`, GoLang
# `t13d181000…`), which the plugin accepts — a stricter gate would fail the
# daily run on real upstream data. Anything outside the plugin's shape
# (ja4s/ja4h/ja4x columns, uppercase hex, truncation) fails the run.
validate_csv() {
	python3 - "$1" <<'PY'
import csv, sys

path = sys.argv[1]
EXPECTED_HEADER = ["Application", "Library", "Device", "OS", "ja4", "ja4s", "ja4h", "ja4x", "ja4t", "ja4tscan", "Notes"]
# 35 ja4 cells in the CSV as of 2026-11; 30 leaves headroom for upstream churn
# while still catching truncation. (40 would fail on today's real data.)
MIN_JA4_CELLS = 30
HEX = set("0123456789abcdef")
ALNUM = set("0123456789abcdefghijklmnopqrstuvwxyz")

def ja4_shape_ok(v):
	if len(v) != 36 or v[10] != "_" or v[23] != "_":
		return False
	a, b, c = v[:10], v[11:23], v[24:]
	if a[0] not in "tqd" or a[3] not in "di":
		return False
	if not set(a[1:3]).issubset(ALNUM) or not set(a[4:]).issubset(ALNUM):
		return False
	return set(b).issubset(HEX) and set(c).issubset(HEX)

try:
	with open(path, newline="") as f:
		rows = list(csv.reader(f))
except Exception as e:
	sys.exit(f"FATAL: foxio CSV parse failed: {e}")
if not rows or rows[0] != EXPECTED_HEADER:
	sys.exit(f"FATAL: foxio CSV header mismatch: {(rows[0] if rows else None)!r} != {EXPECTED_HEADER}")
ja4_rows = [r for r in rows[1:] if len(r) >= 5 and r[4].strip()]
if len(ja4_rows) < MIN_JA4_CELLS:
	sys.exit(f"FATAL: foxio CSV has {len(ja4_rows)} ja4 rows, expected >= {MIN_JA4_CELLS} (truncated upstream?)")
for r in ja4_rows:
	v = r[4].strip()
	if not ja4_shape_ok(v):
		sys.exit(f"FATAL: foxio CSV ja4 cell fails the plugin JA4 shape: {v!r} (row: {r[0]!r}/{r[1]!r})")
print(f"foxio csv ok: {len(rows)-1} rows, {len(ja4_rows)} ja4 cells")
PY
}

validate_json() {
	python3 - "$1" <<'PY'
import json, sys

path = sys.argv[1]
REQUIRED = ("chrome", "firefox", "safari")
HEX = set("0123456789abcdef")
ALNUM = set("0123456789abcdefghijklmnopqrstuvwxyz")

def ja4_shape_ok(v):
	if len(v) != 36 or v[10] != "_" or v[23] != "_":
		return False
	a, b, c = v[:10], v[11:23], v[24:]
	if a[0] not in "tqd" or a[3] not in "di":
		return False
	if not set(a[1:3]).issubset(ALNUM) or not set(a[4:]).issubset(ALNUM):
		return False
	return set(b).issubset(HEX) and set(c).issubset(HEX)

try:
	with open(path) as f:
		d = json.load(f)
except Exception as e:
	sys.exit(f"FATAL: browser-fingerprints.json parse failed: {e}")
browsers = d.get("browsers")
if not isinstance(browsers, dict) or not browsers:
	sys.exit("FATAL: browser-fingerprints.json has no `browsers` object")
for name in REQUIRED:
	entry = browsers.get(name)
	tls = (entry or {}).get("tls") or {}
	ja4 = tls.get("ja4")
	if not isinstance(ja4, str) or not ja4_shape_ok(ja4):
		sys.exit(f"FATAL: browser {name!r} missing/invalid tls.ja4: {ja4!r}")
for name, entry in sorted(browsers.items()):
	ja4 = ((entry or {}).get("tls") or {}).get("ja4")
	if ja4 is not None and not ja4_shape_ok(ja4):
		sys.exit(f"FATAL: browser {name!r} tls.ja4 fails the plugin JA4 shape: {ja4!r}")
print(f"browsers ok: {', '.join(sorted(browsers))}")
PY
}

if [ "$NO_FOXIO" = "0" ]; then
	validate_csv "$TMP/foxio-ja4plus-mapping.csv"
fi
if [ "$NO_BROWSERS" = "0" ]; then
	validate_json "$TMP/browser-fingerprints.json"
fi

# --- 3. generate ------------------------------------------------------------

if [ "$NO_FOXIO" = "0" ]; then
	python3 - "$TMP/foxio-ja4plus-mapping.csv" "$TMP/fpdata_gen.go" "$FOXIO_SHA" <<'PY'
import csv, re, sys

csv_path, out_path, upstream_sha = sys.argv[1], sys.argv[2], sys.argv[3]

# Rows whose Application/Library names offensive tooling become denylist
# entries (lowercase substring match on either column).
BAD_TOKENS = (
    "cobalt strike", "cobaltstrike", "sliver", "qakbot", "pikabot",
    "lumma", "icedid", "darkgate", "softether", "ngrok", "metasploit",
)

def is_bad(row):
	text = f"{row['Application']} {row['Library']}".lower()
	return any(tok in text for tok in BAD_TOKENS)

def label(name):
	return re.sub(r"[^a-z0-9]+", "-", name.strip().lower()).strip("-")

with open(csv_path, newline="") as f:
	rows = list(csv.DictReader(f))

benign = set()
bad = {}
for r in rows:
	fp = (r.get("ja4") or "").strip()
	if not fp:
		continue  # JA4S/JA4H/JA4X-only rows: the plugin cannot match those forms
	if is_bad(r):
		bad.setdefault(fp, set()).add(label(r["Application"] or r["Library"] or "unknown"))
	else:
		benign.add(fp)

# A fingerprint that also occurs on a benign row is EXCLUDED: Sliver reuses the
# stock GoLang fingerprint verbatim, and denylisting it would block every
# honest Go client. Full-fingerprint keys keep the rest collision-free.
entries = {fp: sorted(labels)[0] for fp, labels in bad.items() if fp not in benign}
if not entries:
	sys.exit("FATAL: denylist came out empty — refusing to regenerate (upstream schema change?)")

keys = sorted(entries)
width = max(len(k) for k in keys)
body = "".join('\t"%s": "%s",\n' % (k.ljust(width), entries[k]) for k in keys)

with open(out_path, "w") as f:
	f.write(
		"// Code generated by scripts/update-fingerprint-data.sh from\n"
		"// data/fingerprints/foxio-ja4plus-mapping.csv (FoxIO-LLC/ja4 @ %s); DO NOT EDIT.\n"
		"//\n"
		"// Denylist sources: FoxIO ja4plus-mapping.csv rows whose Application/Library\n"
		"// names offensive tooling (cobalt strike, sliver, qakbot, pikabot, lumma,\n"
		"// icedid, darkgate, softether, ngrok, metasploit). FoxIO License 1.1:\n"
		"// non-commercial use only — see data/fingerprints/LICENSES/foxio-LICENSE.\n"
		"// Fingerprints that also occur on benign rows (e.g. Sliver's stock GoLang\n"
		"// fingerprint) are excluded; JA4S/JA4H/JA4X-only rows are skipped (the\n"
		"// plugin matches the ja4_header form only).\n"
		"package main\n\n"
		"// knownBadJA4 maps full JA4 fingerprints (the normalized ja4_header form)\n"
		"// of known offensive tooling to a short label. Empty (the --no-foxio\n"
		"// build) => the denylist is inert; zero behavior change.\n"
		"var knownBadJA4 = map[string]string{\n%s}\n" % (upstream_sha, body)
	)
print(f"fpdata_gen.go: {len(entries)} denylist entries")
PY
fi

if [ "$NO_BROWSERS" = "0" ]; then
	python3 - "$TMP/browser-fingerprints.json" "$TMP/fpbrowsers_gen.go" "$FPDB_SHA" <<'PY'
import json, sys

json_path, out_path, upstream_sha = sys.argv[1], sys.argv[2], sys.argv[3]

# browser name -> ja4 family. iOS/iPadOS ship WebKit networking (every iOS
# browser does), so they sit in the Safari TLS family — matching the UA
# classifier, which maps CriOS/FxiOS to the Safari family via the WebKit
# "Safari/…" token. An unmapped browser name fails the run: it needs a human
# family decision, not a silent guess.
FAMILY = {
	"chrome": "chromium", "chromium": "chromium", "edge": "chromium",
	"brave": "chromium", "opera": "chromium", "vivaldi": "chromium",
	"arc": "chromium", "duckduckgo": "chromium",
	"firefox": "firefox",
	"safari": "safari", "ios": "safari", "ipados": "safari", "macos": "safari",
}
CONST = {
	"chromium": "ja4FamChromium",
	"firefox": "ja4FamFirefox",
	"safari": "ja4FamSafari",
	"other": "ja4FamOther",
}

# Supplemental part-a entries, hand-sourced (FoxIO ja4plus-mapping.csv +
# homelab gateway capture): the no-SNI (`i…`) variants the measured JSON does
# not carry, and the honest non-browser stacks (python, go, CLI) used by the
# UA/JA4 mismatch check. Machine (JSON) entries win on key conflicts.
SUPPLEMENTAL = {
	"t13d1517h2": ("chromium", "foxio csv + homelab capture"),
	"t13i1516h2": ("chromium", "foxio csv, no SNI"),
	"t13i1714h2": ("firefox", "foxio csv, no SNI"),
	"t13i2013h2": ("safari", "foxio csv, no SNI"),
	"t13d3814h1": ("other", "python http.client + homelab CLI capture"),
	"t13d4312h1": ("other", "python (foxio csv)"),
	"t13d181000": ("other", "python (foxio csv)"),
	"t13i181000": ("other", "python, no SNI (foxio csv)"),
	"t13d190900": ("other", "go (foxio csv)"),
	"t13i190800": ("other", "go, no SNI (foxio csv)"),
	"t13d191000": ("other", "go net/http (foxio csv)"),
	"t13d1412h2": ("other", "go webhooks (foxio csv)"),
	"t13d141000": ("other", "go (foxio csv)"),
}

with open(json_path) as f:
	browsers = json.load(f)["browsers"]

entries = {}  # part-a -> (family, comment)
for name, entry in sorted(browsers.items()):
	ja4 = ((entry or {}).get("tls") or {}).get("ja4")
	if not ja4:
		continue
	fam = FAMILY.get(name)
	if fam is None:
		sys.exit(f"FATAL: browser {name!r} has no family mapping — add it to the generator")
	entries[ja4[:10]] = (fam, f"{name} (measured, browser-fingerprints.json)")
for part_a, (fam, note) in SUPPLEMENTAL.items():
	if part_a not in entries:
		entries[part_a] = (fam, note)

keys = sorted(entries)
lines = ['\t"%s": %s,' % (k, CONST[entries[k][0]]) for k in keys]
code_width = max(len(line) for line in lines)  # uniform column → gofmt-stable
body = "".join(
	line.ljust(code_width) + " // " + entries[k][1] + "\n"
	for line, k in zip(lines, keys)
)

with open(out_path, "w") as f:
	f.write(
		"// Code generated by scripts/update-fingerprint-data.sh from\n"
		"// data/fingerprints/browser-fingerprints.json (North-web-dev/fingerprint-db @ %s)\n"
		"// plus hand-sourced supplemental part-a entries; DO NOT EDIT.\n"
		"//\n"
		"// MIT licensed (data/fingerprints/LICENSES/fingerprint-db-LICENSE).\n"
		"package main\n\n"
		"// ja4FamilyTable maps known JA4 part-a values (exactly 10 chars) to client\n"
		"// families. BEST-EFFORT HEURISTICS, NOT SECURITY: this table cannot\n"
		"// authenticate anything — it only catches clients too lazy to ship a real\n"
		"// browser ClientHello. The browser entries are machine-refreshed from the\n"
		"// measured upstream JSON; supplemental entries (no-SNI variants, honest\n"
		"// non-browser stacks) are hand-maintained. QUIC ('q…') fingerprints are\n"
		"// injected by the TCP tls_inspector and never appear here as input.\n"
		"var ja4FamilyTable = map[string]ja4Family{\n%s}\n" % (upstream_sha, body)
	)
print(f"fpbrowsers_gen.go: {len(entries)} family entries")
PY
fi

# --- 3b. stubs --------------------------------------------------------------

if [ "$NO_FOXIO" = "1" ]; then
	cat >"$TMP/fpdata_gen.go" <<'EOF'
// Code generated by scripts/update-fingerprint-data.sh (--no-foxio); DO NOT EDIT.
//
// FoxIO data withheld at generation time (FoxIO License 1.1 is non-commercial
// only): the denylist is empty and the w_known_bad_ja4 weight is inert. JA4
// family classification (fpbrowsers_gen.go) is unaffected.
package main

// knownBadJA4 is empty in --no-foxio builds; map lookup on an empty map is a
// no-op, so the scorer behaves exactly as before the denylist existed.
var knownBadJA4 = map[string]string{}
EOF
fi

if [ "$NO_BROWSERS" = "1" ]; then
	cat >"$TMP/fpbrowsers_gen.go" <<'EOF'
// Code generated by scripts/update-fingerprint-data.sh (--no-browsers); DO NOT EDIT.
//
// browser-fingerprints.json withheld at generation time: this is the ORIGINAL
// hand-written family table (the pre-vendoring behavior, previously in
// botscore.go), so JA4 classification still works without the vendored JSON.
package main

// ja4FamilyTable maps known JA4 part-a values (exactly 10 chars) to client
// families. BEST-EFFORT HEURISTICS, NOT SECURITY: this table cannot
// authenticate anything — it only catches clients too lazy to ship a real
// browser ClientHello. Every value is sourced, none guessed: FoxIO's
// published ja4plus-mapping.csv (github.com/FoxIO-LLC/ja4) plus the homelab
// gateway capture for the CLI entry. Part-a values shared by multiple
// non-browser apps (e.g. t12d190800: WinINET AND Go) are fine — they land in
// the same family. QUIC ('q…') rows are omitted: the fingerprint is injected
// by the TCP tls_inspector.
var ja4FamilyTable = map[string]ja4Family{
	// Chromium (FoxIO mapping; t13d1517h2 also confirmed by homelab capture)
	"t13d1516h2": ja4FamChromium,
	"t13d1517h2": ja4FamChromium,
	"t13i1516h2": ja4FamChromium,
	// Firefox (FoxIO mapping)
	"t13d1715h2": ja4FamFirefox,
	"t13i1714h2": ja4FamFirefox,
	// Safari (FoxIO mapping)
	"t13d2014h2": ja4FamSafari,
	"t13i2013h2": ja4FamSafari,
	// Honest non-browser stacks — Python and Go (FoxIO mapping) and the
	// homelab CLI capture. A browser-claimed UA over one of these is the
	// classic spoof.
	"t13d3814h1": ja4FamOther,
	"t13d4312h1": ja4FamOther,
	"t13d181000": ja4FamOther,
	"t13i181000": ja4FamOther,
	"t13d190900": ja4FamOther,
	"t13i190800": ja4FamOther,
	"t13d191000": ja4FamOther,
	"t13d1412h2": ja4FamOther,
	"t13d141000": ja4FamOther,
}
EOF
fi

if [ "$CHECK" = "1" ]; then
	echo "check ok (upstream reachable + valid); tree untouched"
	if [ -f "$DATA/foxio-ja4plus-mapping.csv" ] && [ "$NO_FOXIO" = "0" ]; then
		cmp -s "$TMP/foxio-ja4plus-mapping.csv" "$DATA/foxio-ja4plus-mapping.csv" ||
			echo "drift: foxio-ja4plus-mapping.csv differs from upstream (refresh pending)"
	fi
	if [ -f "$DATA/browser-fingerprints.json" ] && [ "$NO_BROWSERS" = "0" ]; then
		cmp -s "$TMP/browser-fingerprints.json" "$DATA/browser-fingerprints.json" ||
			echo "drift: browser-fingerprints.json differs from upstream (refresh pending)"
	fi
	exit 0
fi

# --- 4. install (cmp-gated: only replace what actually changed) -------------

CHANGED=""

install_if_changed() { # SRC DST
	# Only files enabled this run exist in $TMP; absent SRC = skipped source.
	[ -f "$1" ] || return 0
	if [ -f "$2" ] && cmp -s "$1" "$2"; then
		return 0
	fi
	mkdir -p "$(dirname "$2")"
	cp "$1" "$2"
	CHANGED="$CHANGED ${2#"$REPO"/}"
}

if [ "$NO_FOXIO" = "0" ]; then
	install_if_changed "$TMP/foxio-ja4plus-mapping.csv" "$DATA/foxio-ja4plus-mapping.csv"
	install_if_changed "$TMP/foxio-LICENSE" "$DATA/LICENSES/foxio-LICENSE"
	install_if_changed "$TMP/fpdata_gen.go" "$REPO/fpdata_gen.go"
fi
if [ "$NO_BROWSERS" = "0" ]; then
	install_if_changed "$TMP/browser-fingerprints.json" "$DATA/browser-fingerprints.json"
	install_if_changed "$TMP/fingerprint-db-LICENSE" "$DATA/LICENSES/fingerprint-db-LICENSE"
	install_if_changed "$TMP/fpbrowsers_gen.go" "$REPO/fpbrowsers_gen.go"
fi
if [ "$NO_FOXIO" = "1" ]; then
	install_if_changed "$TMP/fpdata_gen.go" "$REPO/fpdata_gen.go"
fi
if [ "$NO_BROWSERS" = "1" ]; then
	install_if_changed "$TMP/fpbrowsers_gen.go" "$REPO/fpbrowsers_gen.go"
fi

# --- 5. SOURCES.md ----------------------------------------------------------
# Per-source blocks: a source whose bytes did not change keeps its existing
# block (preserving the original fetch date), so a quiet day produces no
# SOURCES.md churn and `git diff` on this file shows only real refreshes.

python3 - "$DATA/SOURCES.md" "$TMP" "$FOXIO_SHA" "$FPDB_SHA" "$NO_FOXIO" "$NO_BROWSERS" <<'PY'
import csv
import datetime
import hashlib
import json
import os
import sys

md_path, tmp, foxio_sha, fpdb_sha, no_foxio, no_browsers = sys.argv[1:7]
today = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")


def sha256(p):
	with open(p, "rb") as f:
		return hashlib.sha256(f.read()).hexdigest()


def parse_existing(path):
	blocks = {}
	if not os.path.exists(path):
		return blocks
	cur = None
	for line in open(path):
		if line.startswith("## `") and line.rstrip().endswith("`"):
			cur = line.rstrip()[3:].strip("`")  # "## `name`" -> "name"
			blocks[cur] = line
		elif cur is not None:
			blocks[cur] += line
	return blocks


def csv_note(p):
	with open(p, newline="") as f:
		rows = list(csv.reader(f))
	ja4 = sum(1 for r in rows[1:] if len(r) >= 5 and r[4].strip())
	return f"- Rows: {len(rows) - 1} data rows, {ja4} with a `ja4` fingerprint"


def json_note(p):
	with open(p) as f:
		n = len(json.load(f)["browsers"])
	return f"- Browsers: {n} (each with `tls.ja4`)"


def data_block(name, url, repo, sha, license_line, note_fn):
	tree_path = os.path.join(os.path.dirname(md_path), name)
	tmp_path = os.path.join(tmp, name)
	if os.path.exists(tree_path) and sha256(tmp_path) == sha256(tree_path):
		existing = EXISTING.get(name)
		if existing:
			return existing.rstrip("\n") + "\n"  # unchanged bytes: keep old date/sha
	return (
		f"## `{name}`\n\n"
		f"- Source: `{url}`\n"
		f"- Upstream: `{repo}` @ `{sha}`\n"
		f"- Fetched: {today}\n"
		f"{license_line}\n"
		f"{note_fn(tmp_path)}\n"
		f"- sha256 @ fetch: `{sha256(tmp_path)}`\n"
	)


def license_block(name, url, repo, sha):
	tree_path = os.path.join(os.path.dirname(md_path), name)
	tmp_path = os.path.join(tmp, os.path.basename(name))  # licenses land in $TMP by basename
	if not os.path.exists(tmp_path):
		# license not fetched this run (fixtures mode / source skipped)
		return EXISTING.get(name)
	if os.path.exists(tree_path) and sha256(tmp_path) == sha256(tree_path):
		existing = EXISTING.get(name)
		if existing:
			return existing.rstrip("\n") + "\n"
	return (
		f"## `{name}`\n\n"
		f"- Source: `{url}` (verbatim, unmodified)\n"
		f"- Upstream: `{repo}` @ `{sha}`\n"
		f"- Fetched: {today}\n"
		f"- sha256 @ fetch: `{sha256(tmp_path)}`\n"
	)


EXISTING = parse_existing(md_path)

header = (
	"# Vendored fingerprint data\n\n"
	"All files in this directory are fetched and refreshed by\n"
	"`scripts/update-fingerprint-data.sh` (daily via\n"
	"`.github/workflows/refresh-data.yml`). The script rewrites this file with\n"
	"per-file URL, upstream commit at fetch time, fetch date, license, counts,\n"
	"and sha256 — this file is the diff record for the refresh job.\n"
)

out = [header]

# Data sources: fresh block when fetched this run, else keep the existing one.
if no_foxio == "0":
	out.append(data_block(
		"foxio-ja4plus-mapping.csv",
		"https://raw.githubusercontent.com/FoxIO-LLC/ja4/main/ja4plus-mapping.csv",
		"github.com/FoxIO-LLC/ja4", foxio_sha,
		"- License: FoxIO License 1.1 (verbatim in `LICENSES/foxio-LICENSE`) — **non-commercial use only**",
		csv_note,
	))
elif "foxio-ja4plus-mapping.csv" in EXISTING:
	out.append(EXISTING["foxio-ja4plus-mapping.csv"].rstrip("\n") + "\n")

if no_browsers == "0":
	out.append(data_block(
		"browser-fingerprints.json",
		"https://raw.githubusercontent.com/North-web-dev/fingerprint-db/main/fingerprints.json",
		"github.com/North-web-dev/fingerprint-db", fpdb_sha,
		"- License: MIT (verbatim in `LICENSES/fingerprint-db-LICENSE`)",
		json_note,
	))
elif "browser-fingerprints.json" in EXISTING:
	out.append(EXISTING["browser-fingerprints.json"].rstrip("\n") + "\n")

# Licenses: same keep-when-unchanged rule; skipped (None) when neither
# fetched this run nor present from an earlier run.
for lic in (
	license_block(
		"LICENSES/foxio-LICENSE",
		"https://raw.githubusercontent.com/FoxIO-LLC/ja4/main/LICENSE",
		"github.com/FoxIO-LLC/ja4", foxio_sha,
	),
	license_block(
		"LICENSES/fingerprint-db-LICENSE",
		"https://raw.githubusercontent.com/North-web-dev/fingerprint-db/main/LICENSE",
		"github.com/North-web-dev/fingerprint-db", fpdb_sha,
	),
):
	if lic:
		out.append(lic)

with open(os.path.join(tmp, "SOURCES.md"), "w") as f:
	f.write("\n".join(out))
PY

install_if_changed "$TMP/SOURCES.md" "$DATA/SOURCES.md"

# --- 6. summary -------------------------------------------------------------

if [ -n "$CHANGED" ]; then
	echo "changed:$CHANGED"
else
	echo "unchanged"
fi
if [ "$NO_IPINTEL" = "1" ]; then
	echo "ipintel: skipped (--no-ipintel)"
fi
exit 0

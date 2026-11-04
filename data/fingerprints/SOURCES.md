# Vendored fingerprint data

All files in this directory are fetched and refreshed by
`scripts/update-fingerprint-data.sh` (daily via
`.github/workflows/refresh-data.yml`). The script rewrites this file with
per-file URL, upstream commit at fetch time, fetch date, license, counts,
and sha256 — this file is the diff record for the refresh job.

## `foxio-ja4plus-mapping.csv`

- Source: `https://raw.githubusercontent.com/FoxIO-LLC/ja4/main/ja4plus-mapping.csv`
- Upstream: `github.com/FoxIO-LLC/ja4` @ `c6469a7b0dbf8fe963810162429fbfd9d1acc4d5`
- Fetched: 2026-11-04
- License: FoxIO License 1.1 (verbatim in `LICENSES/foxio-LICENSE`) — **non-commercial use only**
- Rows: 66 data rows, 35 with a `ja4` fingerprint
- sha256 @ fetch: `e21b11ea9f7c630ae798377b346a055af4e6797fb60712356b46ecc5e1606551`

## `browser-fingerprints.json`

- Source: `https://raw.githubusercontent.com/North-web-dev/fingerprint-db/main/fingerprints.json`
- Upstream: `github.com/North-web-dev/fingerprint-db` @ `6c62f2754d408f52d87009d06c44959696d67889`
- Fetched: 2026-11-04
- License: MIT (verbatim in `LICENSES/fingerprint-db-LICENSE`)
- Browsers: 5 (each with `tls.ja4`)
- sha256 @ fetch: `25135eeddc2027e2b2d969e32c101a787b4dc727870a536d61ed683684e65744`

## `LICENSES/foxio-LICENSE`

- Source: `https://raw.githubusercontent.com/FoxIO-LLC/ja4/main/LICENSE` (verbatim, unmodified)
- Upstream: `github.com/FoxIO-LLC/ja4` @ `c6469a7b0dbf8fe963810162429fbfd9d1acc4d5`
- Fetched: 2026-11-04
- sha256 @ fetch: `7781abaf8b8f1cd550de05de5cba4387886dabd493e618b630b359c450f4d8f0`

## `LICENSES/fingerprint-db-LICENSE`

- Source: `https://raw.githubusercontent.com/North-web-dev/fingerprint-db/main/LICENSE` (verbatim, unmodified)
- Upstream: `github.com/North-web-dev/fingerprint-db` @ `6c62f2754d408f52d87009d06c44959696d67889`
- Fetched: 2026-11-04
- sha256 @ fetch: `a409ea3891fe5bc0766b8273540295e4da51c0ebe99ce79eb0307461c890750b`

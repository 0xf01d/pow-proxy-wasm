# Bot scoring (`botscore`)

One pure score per protected request over (ipintel verdict, JA4, User-Agent,
browser headers) → pass / challenge (difficulty from a ladder) / block.
No state, no per-IP memory.

## What this can and cannot do

The plugin cannot prove "this is a real browser": JA4 is public and
reproducible, and a bot running a real JS engine solves the same PoW a
browser does. Verifiable here: (1) TLS stack shape (JA4, `ja4_header`) —
public, but it must be *implemented*; (2) **consistency** — a UA claiming
Chrome over a stock-curl ClientHello is a mismatch no honest client produces,
and faking it requires shipping a real browser TLS stack (the highest-value
signal); (3) IP reputation (ipintel); (4) browser-only headers
(`accept-language`, `sec-fetch-mode`). A client-supplied claim is never
attestation: the UA is a claim to be *contradicted*, not evidence — no
"is this headless" signal, unverifiable at this layer.

## Config (all optional; absent ⇒ disabled, zero behavior change)

```jsonc
{
  "botscore": {
    "enabled": true,
    "w_ipintel": 40, "w_ua_mismatch": 40,            // weights, defaults shown
    "w_no_browser_headers": 15, "w_unknown_ja4": 10, "w_known_bad_ja4": 100,
    "pass_below": 20,          // score <  N → no challenge ever. 0 = disabled
    "block_above": 90,         // score >= N → 403 immediately.   0 = disabled
    "ladder": [ {"min_score": 0, "difficulty": 14}, {"min_score": 25, "difficulty": 16},
                {"min_score": 55, "difficulty": 20}, {"min_score": 80, "difficulty": 24} ]
  }
}
```

Negative weights/thresholds clamp to 0 with a logged problem;
`pass_below`/`block_above` default to 0 (disabled) — set `pass_below` (e.g.
20) or no human ever passes on score alone. Ladder difficulties clamp to the
global bounds; malformed steps are dropped with a logged problem. **Never
half-enabled**: an empty (or fully invalid) ladder, or `pass_below >=
block_above` (both non-zero), disables the whole block and logs why.

## Scoring (sum capped at 100)

| Condition | Weight |
|---|---|
| ipintel verdict is in `challenge_categories` | `w_ipintel` |
| JA4 full fingerprint is in the vendored known-bad denylist (fpdata_gen.go) | `w_known_bad_ja4` |
| UA names chrome/firefox/safari/edge AND JA4 known AND families differ | `w_ua_mismatch` |
| UA names a browser AND `accept-language` AND `sec-fetch-mode` both absent | `w_no_browser_headers` |
| `ja4_header` configured AND fingerprint absent/unparsable AND UA names a browser | `w_unknown_ja4` |

The known-bad denylist is generated from FoxIO's `ja4plus-mapping.csv` rows
whose Application/Library names offensive tooling (Cobalt Strike, IcedID,
SoftEther, …) and refreshed daily (`.github/workflows/refresh-data.yml`,
`data/fingerprints/SOURCES.md` is the provenance record). Exact
full-fingerprint match, UA-independent; fingerprints that also occur on benign
rows (Sliver ships the stock GoLang fingerprint) are excluded rather than
blocking honest clients. The default weight (100) blocks on its own under any
sane `block_above`. The FoxIO data is **non-commercial-only** licensed — build
with `NO_FOXIO=1` for an empty denylist (the weight goes inert, everything
else unchanged).

Family matching: JA4 part-a is looked up in a small table of *sourced*
prefixes (Edge == Chromium; the machine-refreshed browser rows come from the
vendored `browser-fingerprints.json`, no-SNI variants and honest CLI stacks
from FoxIO's mapping + homelab captures — see `fpbrowsers_gen.go`).
Best-effort heuristics, NOT security. A valid fingerprint matching no entry
is **unknown and never scores** — browser majors drift their extension
counts, and penalizing unmapped values would hit real users. Honest
non-browser UAs (`curl/*`, `python-requests`, `Go-http-client`, `Wget`) claim
no browser family; iOS UAs (CriOS/FxiOS) carry the WebKit `Safari/…` token
and match their real TLS family (accepted false positive: an iOS Edge UA).

## Actions and precedence

- `score >= block_above` (non-zero) → **403**, even for valid clearance
  holders — a block is not escapable by presenting an old solve.
- `score < pass_below` (non-zero) → **continue** without touching the
  challenge flow. A bad ipintel verdict adds `w_ipintel` (40 default), above
  the recommended `pass_below` (20), so flagged IPs are never passed here.
- Otherwise **challenge**: the ladder rung for the score becomes a difficulty
  floor with the same precedence as a `protected` rule base — it may raise,
  never lower; pressure/`difficulty_header` still rise, ipintel elevation
  clamps on top, the global max stays absolute.

## What would break this

**curl-impersonate** (and `curl_cffi`) ships a genuine Chrome ClientHello
plus Chrome header order, defeating the UA/JA4 mismatch AND the
missing-header check — only ipintel still sees it; residential proxies +
curl-impersonate score ≈ 0. A tuned speed bump, not attestation: new browser
majors can drift part-a counts into "unknown" until the table is updated
(heuristic decay, never a false block).

# API keys v1 — stateless HMAC keys that bypass PoW

Status: spec for implementation. Audience: Go engineers building v1 in this repo.
Locked decisions (do not relitigate): keys are stateless HMAC with cleartext
metadata inside the key; Redis is in scope for rate limiting and revocation;
scope `pow` is the only scope in v1.

## 1. Key format

```
key = base64url(payload_json) "." base64url(HMAC-SHA256(raw_payload_bytes, api_key_secret))
```

- `payload_json` is UTF-8 JSON, compact separators, **cleartext**. The signature
  provides integrity only, never confidentiality. Nothing secret goes in the payload.
- HMAC is computed over the **raw payload bytes exactly as received**, never over a
  re-serialized structure. Go's `encoding/json` reordering/omitting fields would
  otherwise break verification.
- base64url, no padding, both segments (same encoding as clearance tokens in `crypt.go`).

Payload fields:

| field | type | req | meaning |
|---|---|---|---|
| `v` | uint | yes | format version. Only `1` accepted in v1. |
| `id` | string | yes | 16 random bytes (crypto/rand), base64url (22 chars). Key identity. |
| `kid` | uint | yes | key-signing-secret rotation epoch. Selects the secret used to verify. |
| `exp` | int64 | yes | unix seconds, REQUIRED. Hard expiry. Issuance must cap `exp - now` at `api_key_max_lifetime_sec`. |
| `nbf` | int64 | no | unix seconds, not-before. Absent = valid immediately. |
| `bucket` | string | yes | tenant / rate-limit-group label. Groups counters and dashboards. `[a-z0-9_.-]{1,32}`. |
| `scope` | string | yes | must be `"pow"` in v1. Any other value → reject (forward compatibility). |
| `limits` | object | yes | `{rpm, burst, bytes_per_window, window_sec}` (see §6). Effective limits are clamped by config caps (§7). |
| `hosts` | []string | no | `:authority` allowlist. Absent = valid for any protected host. Matching reuses the existing `protected` rule host matcher: lowercase, port-stripped, `*.suffix` matches exactly one extra leftmost label. |
| (unknown) | any | — | verifiers MUST ignore unknown fields (JSON decode without `DisallowUnknownFields`). |

Hard limits: payload ≤ 768 bytes pre-encoding at mint time (keeps the whole key
under ~1.1 KB: 768 bytes → 1024 b64url chars + 43-char sig). `hosts` ≤ 8 entries.
Verifier rejects any header value > 4096 bytes before decoding.

### Test vector (normative)

```
api_key_secret = 0123456789abcdef0123456789abcdef   (32 bytes)
payload_json   = {"v":1,"id":"n4bQgYhMfWWaL-qgxVrQFQ","kid":1,"exp":1800000000,"bucket":"acme","scope":"pow","limits":{"rpm":300,"burst":50,"bytes_per_window":104857600,"window_sec":60},"hosts":["api.example.com"]}
key            = eyJ2IjoxLCJpZCI6Im40YlFnWWhNZldXYUwtcWd4VnJRRlEiLCJraWQiOjEsImV4cCI6MTgwMDAwMDAwMCwiYnVja2V0IjoiYWNtZSIsInNjb3BlIjoicG93IiwibGltaXRzIjp7InJwbSI6MzAwLCJidXJzdCI6NTAsImJ5dGVzX3Blcl93aW5kb3ciOjEwNDg1NzYwMCwid2luZG93X3NlYyI6NjB9LCJob3N0cyI6WyJhcGkuZXhhbXBsZS5jb20iXX0.9QKHtANwOrAeSSZOTJrcdILkqbeKwmAq_K23upT_e-4
sha256(id) hex = 13575d5fd43f4fe3570bfa69ec99b982a17630f588e864872ed6984e8293e89b
```

The `id` above is the base64url of the raw bytes `9f86d081884c7d659a2feaa0c55ad015`.
A conforming implementation must mint exactly this key from these inputs and verify it.
Field order in the JSON is mint-time canonical; verifiers never depend on it (raw bytes).

## 2. Verification pipeline

Run in `OnHttpRequestHeaders`, after the `protected`-rules gate, before the
clearance-cookie check. Header lookup: `x-api-key` (config `api_key_header`).

1. **Header absent** → normal PoW flow, unchanged. API keys are an accelerant, not a gate.
2. **Header present** → API-key path. Split on `.`; require exactly 2 non-empty
   base64url segments, total length ≤ 4096. Any structural failure → `401`.
3. **HMAC over RAW payload bytes.** Decode segment 1 to raw bytes, HMAC-SHA256 with
   each candidate secret (see rotation below), compare with `subtle.ConstantTimeCompare`
   (same pattern as `crypt.go`). No mismatch → `401` (constant-shape error path; see §8).
   Never JSON-parse the payload before the signature verifies.
4. **Parse** payload JSON into a struct. Enforce `v == 1`, `scope == "pow"`, `id`
   decodes to 16 bytes, `exp` present. Violation → `401`.
5. **Time checks.** `now > exp + skew` → `401` (expired). `nbf` present and
   `now < nbf - skew` → `401`. `skew = api_key_clock_skew_sec` (default 30, cap 300).
6. **Host check.** `hosts` present and normalized `:authority` matches no entry → `401`.
7. **Revocation** (only when Redis configured, §5): `EXISTS pow:ak:rev:<sha256hex(id)>`
   → 1 → `401` (revoked). Redis error/timeout → skip, log at warn (fail-open; §5).
8. **Rate limits** (§6) → over limit → `429` + `Retry-After`.
9. `types.ActionContinue`. No clearance cookie is minted or required; the key
   bypasses PoW entirely on protected paths for the key's lifetime.

Secret separation: `api_key_secret` ≠ `secret` (the clearance secret). Both live in
plugin config; losing one must not compromise the other. Both ≥ 32 bytes
(`MinSecretLen`); refuse plugin start when `api_key_secret` is configured but short
(mirror existing `secret` validation).

Rotation (secret selection, step 3): the plugin config map `api_key_secrets`
(`{"<kid>": "<secret>"}`) holds every accepted epoch. Lookup by the payload's `kid`
is impossible before verification (kid is inside the signed region), so: try the
secret for each configured kid, constant-time compare, accept on first match.
With the usual 1–2 live kids this is 1–2 HMACs — negligible. **Verify-before-parse
is preserved: candidate selection iterates secrets, it never parses the payload.**

Zero network roundtrips on the hot path when `redis_addr` is absent: steps 3–6 are
pure CPU; steps 7–8 run against in-process state.

## 3. Issuance — `powcli mint-api-key`

New subcommand in `test/tools/powcli` (single-dash Go `flag` style, like `mint-clearance`):

```
powcli mint-api-key -secret <api_key_secret> -kid <uint> -lifetime <seconds>
                    -bucket <name> -rpm <n> -burst <n> -bytes <n> -window <sec>
                    [-hosts h1,h2] [-nbf <unix>] [-scope pow] [-id <16-byte-hex>]
                    [-max-lifetime <sec>] [-max-rpm <n>] [-max-burst <n>] [-max-bytes <n>]
```

- `-secret`: the `api_key_secret` (NOT the clearance `-secret` used by `mint-clearance`).
- `-lifetime`: key validity from now; `exp = now + lifetime`, rejected above
  `-max-lifetime` (default 2592000 = 30d, mirroring the plugin cap).
- `-id`: optional; random 16 bytes when omitted. Printed so the operator can record it.
- `hosts` comma-separated; validated with the same rules as `protected` host entries
  at mint time (reject malformed early).
- caps flags default to the plugin defaults; mint refuses to exceed them so keys
  never need re-minting because of a later config tightening.
- CLI behavior: `-hosts` omitted → mint prints a warning that the key is
  **unconstrained** (valid on every protected host) before emitting it. Pinning
  keys to their tenant's host is the recommended practice; unconstrained keys are
  for platform-level integrations only.

Output (stdout, exactly once for the key):

```
API-KEY (shown once; store in your secret manager now):
  eyJ2IjoxLC...<key>...

AUDIT (append to keys-audit.jsonl; contains NO secret material):
  {"id_hash":"13575d5f...","kid":1,"bucket":"acme","scope":"pow","exp":1800000000,"limits":{"rpm":300,...},"created":1760000000}
```

Server-side storage = `id_hash = sha256hex(raw id bytes)` only. Plaintext keys and
ids are never stored server-side; the audit line is enough to revoke (§5) and audit.
The operator copies the key to the client out-of-band; the client treats it like a
password. Re-print is impossible by design — mint a new key instead.

## 4. Rotation

- Config: `api_key_kid` (uint, default 1) is the epoch `mint-api-key` defaults to;
  `api_key_secret` is the secret for `api_key_kid`; `api_key_secrets` maps every
  still-accepted kid to its secret. `api_key_secret` must equal an entry in the map.
- Dual-accept: during rotation the map holds both kids, so old and new keys verify
  simultaneously. There is no time-based window in the plugin — the window is the
  lifetime of old-kid keys.
- Procedure: 1) add `"<kid+1>": "<new secret>"` to `api_key_secrets` and set
  `api_key_kid`/`api_key_secret` to the new epoch; reload config (plugin restart).
  2) Mint all new keys with the new kid. 3) After every old-kid key has passed its
  `exp` (check the audit file), drop the old kid from the map.
- Verify path is unchanged: unknown-`kid` keys simply fail HMAC against every mapped
  secret → `401`.

## 5. Revocation (the only pre-expiry state)

Revocation kills a key before `exp`. Everything else about the key stays stateless.

- Redis key: `SET pow:ak:rev:<sha256hex(id)> 1 EX <ttl>` with `ttl = exp - now`
  (Redis deletes it automatically at/after natural expiry — no cleanup job).
- `EXISTS pow:ak:rev:<sha256hex(id)>` in the verification pipeline (§2 step 7),
  batched into the same HTTP-callout pipeline as the rate-limit commands (§6) so the
  whole Redis interaction costs **one** roundtrip per request.
- Manual revocation (operational runbook):

  ```
  ID_HASH=13575d5fd43f4fe3570bfa69ec99b982a17630f588e864872ed6984e8293e89b
  EXP=1800000000
  redis-cli SET "pow:ak:rev:$ID_HASH" 1 EX $(( EXP - $(date +%s) ))
  ```

- Config: `redis_addr` (optional; e.g. `http://127.0.0.1:7379`). Absent → stateless
  mode: revocation check skipped entirely.
- **Fail-open tradeoff (explicit):** if Redis is absent, down, or times out, the
  plugin falls back to stateless mode *per request*: revoked keys work again until
  Redis recovers, and rate limits degrade to per-node approximations (§6). This is a
  deliberate availability-over-strictness choice: PoW bypass keys are issued to
  semi-trusted tenants, and hard-failing all API traffic because a cache is down is
  worse than a temporary enforcement gap. Revocation therefore has **eventual**
  semantics: revoke-then-fail-open windows are bounded by Redis recovery time +
  gateway timeout (`redis_timeout_ms`).

## 6. Rate limiting

One simple design: fixed-window counters (atomic `INCR`/`INCRBY`, no Lua, no
read-modify-write races). Burst is a 1-second fixed-window counter — chosen over a
Redis token bucket because a token bucket needs Lua or non-atomic GET/SET to be
correct, and v1 refuses that complexity.

**Accepted limitation:** fixed windows are not exact. A client that spends its
`rpm` budget in the last second of window N and again in the first second of
window N+1 pushes ~2× `rpm` through across the boundary. v1 accepts this: the
1-second burst counter caps the spike, and exact sliding windows (Lua zset /
token bucket) are exactly the rejected complexity above.

Counters, per key, window derived from the key's own `limits`:

```
w  = floor(now / window_sec) * window_sec          # rpm + bytes window start
s  = now                                            # burst window (1s)
K  = sha256hex(id)                                  # id never appears in Redis
id = "pow:ak:rl:<bucket>:<K>:<w>"                   # requests
ib = "pow:ak:bt:<bucket>:<K>:<w>"                   # bytes
b  = "pow:ak:burst:<bucket>:<K>:<s>"                # burst
```

Pipeline (all seven commands in one callout; one RTT):

```
EXISTS pow:ak:rev:<K>
INCR   <id>
EXPIRE <id>  <window_sec + 60>
INCRBY <ib> <content_length or 0>
EXPIRE <ib>  <window_sec + 60>
INCR   <b>
EXPIRE <b>  5
```

`INCR` creates the counter at 1 on first hit; `EXPIRE` refreshes on every request —
the +60s grace absorbs clock skew across proxy nodes.

Evaluation against the key's limits, clamped by config caps (§7):

- `count > rpm` → over rate. `bytes > bytes_per_window` → over volume.
- `burst_count > burst` → over burst.
- Any violation → `429`, body `{"error":"rate_limited"}`, `Retry-After: <window_sec + w - now + 1>`
  (for burst violations: `Retry-After: 1`). No challenge HTML, no PoW fallback.
- `content_length` is read from request headers; chunked bodies without a
  `content-length` count 0 (documented approximation; header-stage filtering cannot
  see unparsed bodies without pausing the stream — out of scope for v1).

Redis transport (grounded in this repo's ABI): proxy-wasm has **no TCP sockets**;
the only network hostcall is `proxywasm.DispatchHTTPCall` to an Envoy cluster.
Redis is therefore reached through a RESP-over-HTTP gateway (webdis is the reference
implementation; its `POST /` accepts a JSON array pipeline and returns a JSON array
of replies). Deployment adds an Envoy cluster (default name `pow_redis`, config
`redis_cluster`) pointing at `redis_addr`, e.g. `http://127.0.0.1:7379`. The request
handler calls `DispatchHTTPCall` and returns `types.ActionPause`; the
`OnHttpCallResponse` callback evaluates the replies and resumes with continue/429/401.
Callout error, non-200, gateway decode failure, or `redis_timeout_ms` exceeded →
fail-open per §5 (log warn, in-memory counters only). Consequence: when Redis is
configured, API-key requests pay one extra RTT to a local gateway — this is the
price of revocation + global limits, and it is skipped entirely when `redis_addr`
is absent (§2). **Timeout note:** `DispatchHTTPCall` exposes no plugin-side
per-call timeout — the deadline is the Envoy cluster's. The `pow_redis` cluster
MUST set `connect_timeout` (sized to `redis_timeout_ms`) in every deployment
fixture; an unbounded cluster timeout stalls paused requests for the full
cluster timeout.

In-memory fallback (Redis absent): same three counters per worker, kept in the
`pluginContext` under a mutex (Envoy workers are threads; the context is shared,
like `challengeCounter` today): `map[sha256hex(id)]{w, rpmCount, bytesCount, s, burstCount}`,
reset lazily when the stored window differs from the current one. **Approximate and
per-node**: with N workers the effective ceiling is N × configured limits. Documented,
not fixed — global exactness is what Redis mode is for.

429 vs 401: 401 = authentication failure (missing segment, bad signature, bad
version/scope, expired, `nbf` in future, host mismatch, revoked). 429 = authenticated
but over limits. Never conflate: clients retry 429 after `Retry-After`; 401 means
"get a new key".

## 7. Config schema

Plugin config is a JSON object (existing convention — `secret`, `client_ip_source`,
`protected` are siblings). All keys optional except where noted; absent
`api_key_secret`/`api_key_secrets` = API-key feature fully disabled (zero behavior
change for existing deployments).

```json
{
  "secret": "<clearance secret — existing, unchanged>",

  "api_key_secret": "<32+ bytes; signs minted keys; required if api_keys used>",
  "api_key_kid": 1,
  "api_key_secrets": { "0": "<old secret>", "1": "<current secret>" },

  "api_key_header": "x-api-key",
  "api_key_clock_skew_sec": 30,

  "api_key_max_lifetime_sec": 2592000,
  "api_key_max_rpm": 6000,
  "api_key_max_burst": 200,
  "api_key_max_bytes_per_window": 1073741824,
  "api_key_min_window_sec": 10,
  "api_key_max_window_sec": 3600,

  "redis_addr": "http://127.0.0.1:7379",
  "redis_cluster": "pow_redis",
  "redis_timeout_ms": 50
}
```

Caps are deploy-time ceilings enforced at **verification** (`effective = min(key.limits, cap)`,
`window_sec` clamped to `[min, max]`) and mirrored as `mint-api-key` flags (§3) so
minting fails fast. A signed key can therefore never outbid the operator's caps.
Defaults: lifetime 30d, rpm 6000, burst 200, bytes 1 GiB/window, window 60s.

## 8. Threats and gotchas

- **Timing-safe compare only.** Signature comparison via `subtle.ConstantTimeCompare`
  (as in `crypt.go`); never `==`/`bytes.Equal` on secrets. Error responses for all
  401 causes are byte-identical `{"error":"invalid_api_key"}` with no cause detail;
  cause goes to the proxy log only.
- **Verify-before-parse.** The payload is attacker-controlled bytes; HMAC must pass
  before any JSON decode. Parsing first would hand untrusted data to the JSON parser
  and leak parse-failure oracles. Candidate-secret iteration (§2) keeps this intact.
- **Header, not query param.** Recommend `x-api-key` header. Query strings land in
  access logs, `Referer`, browser history, and intermediary caches; headers do not.
  This matches the existing non-browser path (`challenge-token` header). Accepting
  keys from query params is explicitly rejected for v1.
- **Clock skew.** Keys are minted on operator machines and verified on proxy nodes;
  both must be NTP-synced. Skew allowance `api_key_clock_skew_sec` applies to `nbf`
  (subtract) and `exp` (add) symmetrically; default 30s, hard cap 300s. Issuance
  warnings when `-lifetime` < 2 × skew.
- **Payload size budget.** The key rides every request; hosts lists inflate it. Mint
  caps: payload ≤ 768 B, `hosts` ≤ 8, `bucket` ≤ 32 chars. Verifier drops keys
  > 4096 B before decode to bound parse cost from garbage traffic.
- **Why secrets/counters/UA-binds stay OUT of the key.** The payload is cleartext —
  anyone holding the key reads it, so secrets in the payload would leak to clients.
  Counters are mutable server state; embedding them would require re-issuing the key
  on every request. UA/fingerprint binds would tie keys to client-observable strings
  (spoofable, brittle across client upgrades) and break the stateless property that
  makes the hot path zero-network. What the key carries is exactly what verification
  needs to know without a database: identity, epoch, time bounds, placement
  (bucket/hosts), and limits.
- **Replay.** The key is bearer: possession = authority until `exp` or revocation.
  TLS protects transit; revocation + short lifetimes bound abuse. This is the same
  trust model as the existing clearance cookie, minus IP binding — API keys
  deliberately do NOT bind IP (clients live behind NAT/egress pools; binding would
  cause mass 401s), which is acceptable because keys are issued per tenant, not per
  anonymous visitor.
- **Byte accounting is advisory against hostile clients.** Volume is counted from
  the request's `content-length`, which the client controls: chunked bodies count 0
  and a client can understate arbitrarily. The bytes cap stops accidents and
  misconfigured tenants; a determined adversary bypasses it. Volumetric defense
  against hostile traffic belongs upstream (Envoy buffer/stream limits), not here.
- **`api_key_secret` ≠ clearance `secret`.** Rotation and compromise of one must not
  affect the other. Never derive one from the other.
- **Redis keys carry no plaintext id** — `sha256hex(id)` only (§6), consistent with
  id-hash-only server-side storage (§3).

## 9. Non-goals for v1

- Multi-scope keys (only `pow`; the `scope` field exists so later scopes don't need
  a format bump).
- Per-key UA/fingerprint/IP binds.
- Admin API server (issuance/revocation is `powcli` + `redis-cli`, operator-driven).
- JWT/OAuth/OIDC compatibility; asymmetric (Ed25519/RSA) signatures — HMAC suffices
  while only the proxy and the minting CLI hold secrets.
- Global exact rate limits without Redis; streaming-body byte accounting.

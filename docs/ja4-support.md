# JA4 support — design note (v1)

Status: proposal. Target: `pow-proxy-wasm` main @ 5084256.
Verdict up front: **no new Envoy filter exists or is needed.** Envoy's supported JA4 path is the TLS
inspector listener filter (core, `enable_ja4_fingerprinting` since v1.35.0) plus the
`%TLS_JA4_FINGERPRINT%` substitution command to bridge the hash into a request header the plugin reads.
The plugin consumes the header as a new `protected` rule dimension and as a difficulty override target.
It never touches TLS itself.

Verified against upstream sources on 2026-09-21; citations inline, uncertain items labeled.

## 1. Verified Envoy facts

**A dedicated `envoy.filters.http.ja4_fingerprint` HTTP filter does not exist.** Checked
`source/extensions/extensions_build_config.bzl` (the registry of every core + contrib extension) — no
JA3/JA4/fingerprint entry; the HTTP-filters documentation index lists no such filter; web search surfaces
none. Do not design against it.

What does exist (all verified in current `main` sources and docs):

- **TLS inspector listener filter** (`envoy.filters.listener.tls_inspector`, core, not contrib).
  Proto `envoy.extensions.filters.listener.tls_inspector.v3.TlsInspector` fields:
  - `enable_ja3_fingerprinting` (BoolValue, default false) — MD5-based JA3 hash.
  - `enable_ja4_fingerprinting` (BoolValue, default false) — JA4 fingerprint.
  - `initial_read_buffer_size`, `max_client_hello_size` (default/cap 16 KiB),
    `close_connection_on_client_hello_parsing_errors` (default false).
- **Version:** the v1.35.0 release notes state: *"tls_inspector_filter: Added `enable_ja4_fingerprinting`
  to create a JA4 fingerprint hash from the Client Hello message."* JA3 support predates it (exact
  release not verified — check your Envoy version's notes).
- **Where the values live:** not dynamic metadata (the inspector's dynamic metadata only carries failure
  reasons like `client_hello_too_large`), not filter state. They are plain strings on the downstream
  socket: `Network::Socket::setJA3Hash()/setJA4Hash()` (called by the inspector) with accessors
  `ja3Hash()/ja4Hash()`, stored in the connection's `ConnectionInfoProvider`
  (`source/common/network/socket_impl.h`, `connection_socket_impl.h`).
- **The bridge to HTTP:** the substitution commands **`%TLS_JA3_FINGERPRINT%`** and
  **`%TLS_JA4_FINGERPRINT%`** (`source/common/formatter/stream_info_formatter.cc`, COMMAND_ONLY; the
  `FilterManager` also surfaces `ja4Hash()` to stream callbacks). These work in access logs and in
  header-value substitutions — which is how the hash reaches an HTTP filter.
- **Proxy-wasm exposure:** the hashes are **not** in the documented proxy-wasm property list (checked
  the Wasm filter docs property reference). So the header bridge below is the *only* core-Envoy path for
  our plugin. [INFERENCE based on absent documentation; re-check if Envoy adds a property.]
- **Value shape (FoxIO JA4):** `t13d1516h2_8daaf6152771_b186095e22b6` — part `a` (10 chars): transport
  char (`t` TCP / `q` QUIC / `d` DTLS), 2-char TLS version, `d`/`i` (SNI present/absent), 2-char cipher
  count, 2-char extension count, first+last char of first ALPN; part `b`: truncated SHA-256 (12 hex) of
  sorted cipher list; part `c`: truncated SHA-256 of sorted extension list + signature algorithms. GREASE
  ignored; empty lists yield `000000000000`. Envoy's implementation follows this
  (`ja4_fingerprint.h`: `tXXdYYZZ_CIPHERHASH_EXTENSIONHASH`), with a runtime guard
  `envoy.reloadable_features.ja4_alpn_hex_conversion_fix` affecting non-ASCII ALPN rendering — pin Envoy
  to a release with the fix before cross-matching fingerprints.
- **Scope:** Envoy computes **JA4** (TLS client) and **JA3** only. JA4S (server hello), JA4H (HTTP),
  JA4X (certificates), JA4L/JA4TS (latency) are not computed. JA4S classifies *servers*, so it is not
  useful for client classification anyway.
- **Failure modes:** ClientHello > 16 KiB or unparseable → no fingerprint (counter
  `client_hello_too_large`); connection continues unless `close_connection_on_client_hello_parsing_errors`
  is set. Plaintext/HTTP/1 cleartext listeners → no fingerprint.

Non-Envoy edges (for deployments where Envoy is not the TLS terminator): Apache Traffic Server ships a
first-party `ja4_fingerprint` plugin; nginx has the third-party `phuslu/nginx-ssl-fingerprint` module
(JA3/JA4/H2, 240★); Caddy has third-party `TDS-SO/caddy-ja4`; HAProxy's JA4 request
(haproxy/haproxy#2495) is closed as completed — the exact native fetch syntax is **unverified** here
[INFERENCE]; a community Lua implementation exists. Any edge works as long as it strips then injects the
same header contract (§3).

Sources: [tls_inspector proto](https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/listener/tls_inspector/v3/tls_inspector.proto) ·
[TLS inspector docs](https://www.envoyproxy.io/docs/envoy/latest/configuration/listeners/listener_filters/tls_inspector) ·
[v1.35.0 release notes](https://www.envoyproxy.io/docs/envoy/latest/version_history/v1.35/v1.35.0) ·
[FoxIO JA4 spec](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md) ·
[socket API](https://github.com/envoyproxy/envoy/blob/main/envoy/network/socket.h) ·
[formatter commands](https://github.com/envoyproxy/envoy/blob/main/source/common/formatter/stream_info_formatter.cc) ·
[ATS JA4 plugin](https://docs.trafficserver.apache.org/en/latest/admin-guide/plugins/ja4_fingerprint.en.html) ·
[nginx module](https://github.com/phuslu/nginx-ssl-fingerprint)

## 2. Architecture

**Constraint, stated plainly:** the plugin cannot see the TLS ClientHello. Proxy-WASM plugins are HTTP
filters; the ClientHello is parsed by listener filters before the HTTP connection manager exists, and the
proxy-wasm ABI exposes no ClientHello data (and, per §1, no `ja3/ja4` property either). JA4 must be
computed by Envoy at the listener/connection layer and injected into the request as a header.

```
ClientHello ─▶ [listener] tls_inspector (enable_ja4_fingerprinting)
                     │ socket.setJA4Hash(...)                (per connection)
                     ▼
              [HCM] request_headers_to_remove: x-ja4, x-ja3   ← strip client-supplied (§3)
              [HCM] request_headers_to_add: x-ja4: %TLS_JA4_FINGERPRINT%
                     ▼
              [http_filters] envoy.filters.http.wasm  ← plugin reads header
                     ▼
                   router
```

Placement rules (load-bearing):

- **Inject at HCM level.** HCM-level `request_headers_to_add`/`request_headers_to_remove` are applied
  before the HTTP filter chain. Route/virtual-host-level header mutations are applied by the **router**,
  i.e. *after* the wasm filter — too late. The router-level mutation is only useful for forwarding the
  header upstream (not needed by us).
- **Strip at HCM level, before injection**, and before the filter chain (§3).
- Header set by the edge on a plaintext/no-TLS request: `%TLS_JA4_FINGERPRINT%` resolves empty — expect
  either an omitted header or a `-` placeholder (Envoy's standard empty-substitution behavior; confirm
  exact behavior in the bats fixture). The plugin normalizes absent, empty, and `-` to **unknown**.
- One JA4 per **connection**: HTTP/2 multiplexes many requests over one ClientHello, so all requests on a
  connection share a fingerprint. Consistent with per-connection data we already use (`connection.id`).

## 3. Trust model / anti-spoofing (critical)

The header is **not authenticated** — it is trusted only because the edge controls the injection point.
The threat is a client sending `x-ja4: <nice-browser-fingerprint>` to hit a low-difficulty or exempt
class.

Rules, all required for v1:

1. **Edge strips before injecting.** HCM `request_headers_to_remove: [x-ja4, x-ja3]` (plus any other
   names in use) unconditionally removes client-supplied values before any HTTP filter runs. Never rely
   on route-level removal — it happens at the router, after the plugin.
2. **Configurable header names.** Plugin config `ja4_header` (default `x-ja4`; optional `ja3_header`).
   Operators may choose a non-default, non-documented name (e.g. `x-client-tls-class`) so a blind
   spoof attempt guesses wrong. Cheap defense-in-depth; also decouples us from the default name.
3. **Origin isolation.** Anyone who can reach the origin bypassing Envoy can inject anything. Origins
   must only accept traffic from the edge (network policy / firewall). The header adds a dimension;
   it does not replace transport trust.
4. **Unknown ≠ bypass.** No header (plaintext, non-Envoy edge, feature off, ClientHello failure) means
   the JA4 dimension is unknown: `ja4` match lists never match unknown clients, `ja4_excluded` vetoes
   never apply to unknown clients. JA4 dimensions can only narrow or add matches — they can never
   silently exempt a client whose fingerprint we did not see. Default posture for unknown stays
   exactly what the hosts/paths selectors decide today.
5. **Header value hygiene.** JA4 is 26 chars `tQQddccaa_hhhhhhhhhhhh_hhhhhhhhhhhh`; the plugin treats any
   value that doesn't parse (wrong length/charset/structure) as unknown, not as a match failure that
   could leak into logs unescaped.

## 4. Usage as a rule dimension

Existing `protected` semantics: rules are OR-ed; within a rule `hosts` AND `paths` must both match;
compiled once at plugin start into a flat zero-allocation matcher pass. JA4 slots in as a third optional
dimension without changing those invariants.

**Selector grammar** (an entry is one of):

| Entry | Meaning |
|---|---|
| `t13d1516h2_8daaf6152771_b186095e22b1` | exact full fingerprint (26 chars) |
| `a=t13d1516h2` | exact part-`a` match (transport+version+SNI+counts+ALPN class) |
| `a=t13d*` | part-`a` **prefix** — the only wildcard form, pinned at the version boundary (all TCP/TLS1.3 clients) |
| `b=8daaf6152771` | exact cipher-list hash match |
| `c=b186095e22b6` | exact extension+sigalg hash match |

- Within a rule's `ja4` list entries are OR-ed; the `ja4` dimension ANDs with `hosts`/`paths`.
- `a=t13d*` deliberately diverges from the hosts wildcard convention (leading wildcard there, trailing
  here) because JA4's useful coarse class lives at the *front* of part `a`. Documented; no other
  wildcard forms.
- Validation at plugin start mirrors existing rule handling: malformed entries (bad part key, non-12-hex
  `b`/`c`, unknown transport char, length ≠ expected) are logged and dropped; a rule whose `ja4` list
  ends up empty behaves as if the dimension were absent — never "challenge everything" by accident.

**Exemption (veto) dimension.** Exempting a client class cannot be expressed as "not matching" when the
route must stay protected for everyone else, so rules get an explicit optional list:

- `ja4_excluded`: same grammar; a request matched by the rule whose JA4 matches any entry is **not
  challenged by that rule**. Applied after the positive dimensions. Unknown clients never match the
  veto (§3.4).

**Difficulty override target.** Optional per-rule `difficulty: {base, min, max}`: when a rule matches,
that request's challenge starts from the rule's `base` instead of the global `base_difficulty` (e.g.
known automation fingerprints → harder PoW). Precedence: rule `base` > global `base`; the adaptive
pressure bump still applies on top; the **global `max_difficulty` remains the absolute clamp** — rule
`min`/`max` outside the global bounds are clamped at parse time and the clamped values logged. Config
validation failures behave like other rule drops (log + drop, never fail the request).

## 5. Config schema sketch + worked examples

Envoy side (core, no contrib image):

```yaml
listener:
  - name: main
    filter_chains:
      - filters: [ ...http_connection_manager... ]
        listener_filters:
          - name: envoy.filters.listener.tls_inspector
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.listener.tls_inspector.v3.TlsInspector
              enable_ja4_fingerprinting: true
              # enable_ja3_fingerprinting: true   # optional; pass-through only in v1

http_connection_manager:
  request_headers_to_remove: ["x-ja4", "x-ja3"]     # MUST precede filters
  request_headers_to_add:
    - header: { key: "x-ja4", value: "%TLS_JA4_FINGERPRINT%" }
  http_filters:
    - name: envoy.filters.http.wasm                  # plugin, unchanged position
    - name: envoy.filters.http.router
```

Plugin config (JSON, existing config object):

```json
{
  "ja4_header": "x-client-tls-class",
  "protected": [
    {
      "hosts": ["status.example.org"],
      "paths": ["/healthz"],
      "ja4_excluded": ["a=t11h1", "a=t13h1"]
    },
    {
      "hosts": ["api.example.org"],
      "paths": ["/write"],
      "ja4": ["a=t13d1516h2", "a=t12d2116h2"],
      "ja4_excluded": ["t13d2116h1_9fd4d8ad2b64_5b495ccfc4bd"],
      "difficulty": { "base": 20, "min": 16, "max": 26 }
    }
  ]
}
```

`ja4_header` absent ⇒ feature off: no rule carries a JA4 dimension, zero behavior change (legacy
configs keep working; hot path unchanged for requests not matching JA4-carrying rules).

Worked examples (fingerprints are **shape-illustrative** — capture real values from your own traffic
before pinning):

1. **Health checks.** `/healthz` on the status host must answer LB probes made with CLI HTTP clients,
   while browsers hitting it still get challenged. Rule 1 protects the path but vetoes the
   CLI-client classes (`a=t11h1`, `a=t13h1` — HTTP/1.1, no ALPN h2). Unknown clients stay challenged
   (veto never applies to unknown).
2. **Headless/automation tooling.** Raise PoW cost for non-browser clients on expensive endpoints:
   rule 2 pins the HTTP/2 browser-shaped classes via `a=t13d1516h2`-style entries and sets
   `difficulty.base: 20`. Honest limitation: **headless Chrome has the same JA4 as desktop Chrome** —
   identical TLS stack, identical ClientHello. JA4 reliably separates *non-browser HTTP clients*
   (curl, python-requests, Go http, Java) from browsers; it does not separate browser-engine bots
   from real browsers. Do not oversell it.
3. **Known-good CLI exemption on an API route.** `ja4_excluded` with the exact full fingerprint of the
   ops team's pinned client build. Full-fingerprint pins break whenever the client's TLS stack updates
   (§6) — prefer part-`a` classes unless the client is under your control.

## 6. Explicit non-goals (v1)

- **Computing JA4 inside the plugin.** Impossible (no ClientHello via proxy-wasm ABI, §2) and
  redundant — Envoy already computes it before the first HTTP filter runs.
- **JA4+ suite members other than JA4.** No JA4H (HTTP-layer), JA4X (certs), JA4S (classifies *servers*),
  JA4L/JA4TS (latency) in v1. Envoy doesn't compute them; the plugin's HTTP view cannot derive JA4H
  reliably either.
- **JA3-based rules.** Header pass-through only (`ja3_header`, optional). JA3 has been randomized since
  Chrome 110 and is ineffective against current browsers; JA4 is the rule dimension.
- **Fingerprint allowlist-only security.** JA4 is not a secret: every install of the same client build
  produces the same value (zero per-client entropy), and any TLS library can imitate a ClientHello
  (curl-impersonate et al). It also *rotates*: browser updates routinely change cipher/extension sets,
  so a pinned fingerprint that admits "good browsers" today rejects them after the next auto-update.
  Use JA4 as a difficulty/routing **dimension**, never as authentication or as the sole gate.

## 7. Gotchas

- **Strip-then-inject order is load-bearing.** If the strip is lost in a config refactor, any client
  can forge the dimension. Add a bats case: send `x-ja4: t99d9910x0x_ffffffffffff_ffffffffffff` with a
  spoof-class value and assert the plugin sees only the edge value.
- **Empty-value rendering.** `%TLS_JA4_FINGERPRINT%` on a plaintext request is empty; Envoy may render
  `-` or drop the header depending on `HeaderValueOption` context. Confirm in the fixture; the plugin
  must treat absent/`-`/empty identically (unknown).
- **ClientHello > 16 KiB** → no fingerprint, `client_hello_too_large` counter. Fingerprint-hiding
  ClientHello padding (uTLS "hide") can push automated clients over the cap — treat *missing*
  fingerprints from supposedly-browser traffic as a weak negative signal, not proof.
- **Fingerprint churn.** Prefer `a=` class matches over full pins; review pinned values on browser
  release cadence. Never let a stale pin become a denial of a legitimate client population.
- **Envoy version pin.** JA4 needs ≥ v1.35.0 (or backport); the ALPN rendering runtime guard means
  fingerprints computed by different Envoy versions can differ for exotic ALPNs. Compute and match in
  the same Envoy.
- **Istio deployments.** Both changes (listener filter + HCM header ops) require `EnvoyFilter` patches
  at the right insertion points; HCM-level (not route-level) header ops are mandatory (§2).

## 8. Rollout / testing notes

- Unit tests (pure Go, no Envoy): grammar parsing (valid/invalid entries, prefix wildcard, clamping),
  match semantics (unknown header, veto-not-applicable-to-unknown, AND/OR composition), difficulty
  precedence (rule base vs global base/pressure/global max).
- Bats: extend the Envoy fixture with `tls_inspector` + HCM header ops; assert `x-ja4` present on TLS
  requests, spoofed `x-ja4` stripped, plaintext path yields unknown; end-to-end: JA4-matched rule
  triggers challenge, `ja4_excluded` passes through unchallenged.
- k6 perf: no impact on the clearance hot path (JA4 rules only widen the existing linear selector walk).

## 9. Open questions

1. **Veto scoping** — per-rule `ja4_excluded` (proposed) vs a single top-level exempt list. Per-rule is
   more precise; a global list is a trivial follow-up if operators want one.
2. **Target environments** — raw Envoy first (config above)? Istio/EnvoyFilter support is doable but
   invasive; confirm before promising it.
3. **Difficulty clamp policy** — proposed: rule `difficulty` always clamped by global
   `min_difficulty`/`max_difficulty`. Alternative (rule may exceed global max for hostile classes)
   needs an explicit operator decision.

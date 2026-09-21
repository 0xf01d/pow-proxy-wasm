# Challenge automation-resistance: design note

**Scope:** pow-proxy-wasm @ `5084256`, docs only. Question from the operator: can we change
the challenge every time so it becomes impossible to automate? Short answer: no — impossibility
is off the table at this layer. This note ranks what actually raises bot cost and marks the rest
as theater.

---

## 1. Threat model

### Adversary classes

| Class | What they run | Marginal cost per solve | Notes |
|---|---|---|---|
| T1 headless browser | Playwright/Puppeteer, JS enabled | ≈ a real browser: JS exec + PoW | Indistinguishable from a user at the proxy layer |
| T2 headless solver, no JS | curl + script (the `test/tools/powcli` model) | ~0 after a one-time port | The class a "generic solver" is; powcli exists in-repo precisely as this proof |
| T3 solver farm | T2 × N IPs | solver time + IP churn | Challenge is already IP+conn.id bound, so one solve per IP |
| T4 CAPTCHA farm | Humans / ML solvers | $1–3 per 1k solves | Only interactive challenges push back; a non-interactive PoW never will |
| T5 LLM agents with real browsers | Full Chromium + JS | ≈ T1 | Anubis's actual target population |

### What the proxy can observe

- **Headers**: UA, and edge-injected **JA4** (Envoy listener filter injects a header; already
  queued in the project plan — this plugin only reads a header, stays stateless).
- **IP / Envoy `connection.id`**: already bound into the challenge signature and clearance
  (`crypt.go`, `ClientContext`).
- **Per-IP/UA volumes**: queued as LRU adaptive layer in the project plan; can feed the existing
  difficulty clamp.
- **Not observable**: whether JS actually executed, real render cost, behavioral telemetry.
  The stateless design forbids the server-side validation that makes client-side fingerprinting
  meaningful. Any "we detect automation" claim is therefore unverifiable by us — treat as theater.

Adversary economics: challenge issuance costs us one HMAC; a solve costs a SHA-256 loop. Any
mechanism must move the solve off the attacker's cheap path (T2/T3) or force repeated porting
work. Nothing stops a one-time port — that's the honest ceiling.

### Already-known hazard in this codebase

`x-challenge-difficulty` is read from the request (`main.go` ~line 373) and clamped to
`[min_difficulty, max_difficulty]`, but the clamp does not stop an attacker from *steering to the
minimum*. This is the exact shape of Anubis CVE-2025-24369 (client asks for difficulty 0 and the
challenge still verifies). Fix: treat that header as edge/operator-only input — strip it at the
listener from untrusted hops, or clamp overrides to `[base, max]`, never `[min, max]`.

---

## 2. Why per-request challenge mutation alone fails

The premise "change it every time" is already the status quo:

- Every challenge carries a **fresh 32-byte random salt**, a 60 s expiry, an HMAC-SHA256
  signature, and IP+`connection.id` binding (`generateChallengeMAC` in `crypt.go`).
- Two requests never see the same challenge. `powcli` still solves every one of them headlessly.

Root cause: the challenge is **self-describing**. `ChallengePayload{ts, exp, diff, salt, ctx,
cid}` plus the fixed "SHA-256 over salt‖nonce must have N leading zero bits" contract is a
complete public protocol. A solver author needs our README, not our JS. The generic property
lives in the *protocol*, not in the *instance* — mutating instances (fresh salt) automates
perfectly; only mutating the *protocol* (what code must run to produce a valid solution) taxes
the solver author.

So every candidate below is one of four honest levers:

1. **Make the solver execute JS we ship** (the Anubis model) — gates the no-JS class outright.
2. **Rotate the protocol on a schedule** — a maintenance tax on solver authors, not feasibility.
3. **Condition difficulty on risk** (JA4, volumes) — a per-request economic tax on farms/scripts.
4. **Make the work function expensive to parallelize/ASIC-ize** — hardware tax; mostly theater
   at this scale (see 3d).

Corroborating evidence that self-describing challenges get abused generically: ALTCHA's PoW
suffered challenge splicing + replay ([GHSA-6gvq-jcmp-8959](https://github.com/altcha-org/altcha-lib/security/advisories/GHSA-6gvq-jcmp-8959),
CVE-2025-68113) and a cryptanalytic break of its obfuscation mode (CVE-2025-65849, disputed);
Anubis has multiple published no-browser solvers
([sleeyax/anubis-solver](https://github.com/sleeyax/anubis-solver),
[gan-anubis on PyPI](https://pypi.org/project/gan-anubis/)). Being fresh-per-request did not
save either of them.

---

## 3. Candidate mechanisms

### a. JS-gated solving — the Anubis model

Anubis ([Xe Iaso](https://xeiaso.net/blog/2025/anubis), [how it works](https://github.com/TecharoHQ/anubis/blob/main/docs/docs/design/how-anubis-works.mdx))
weighs each connection with a SHA-256 PoW the browser must compute; difficulty is customizable.
Its no-browser solvers prove the *protocol* is still portable — but the gate works because a
client that won't execute the served JS never gets through the intended path, and Anubis keeps
rotating the implementation (pure-JS → WASM/SIMD SHA-256, Firefox WebCrypto swapped out for JS
loops in v1.22.0, challenge variants including the merged
["proof of React"](https://github.com/TecharoHQ/anubis/pull/1038)).

**Important framing:** we *already* serve an in-browser JS solver (`challenge.html`, sync
pure-JS SHA-256). What we lack is exclusivity: the challenge JSON plus docs fully describe the
proof, and the `challenge-token` header lane makes headless solving a supported interface.

The increment:

- Derive the final hash input inside the served JS (a per-release transform over salt/nonce);
  stop documenting the derivation. `powcli` breaks on the first transform change and every
  rotation after.
- Rotate/minify/variant the JS like Anubis does.
- **No-JS lane:** this deliberately kills the header-token path for machines. That is exactly
  why the v1 **API-key design is the escape hatch and the synergy**: keys for scripts/CLIs/partners,
  challenge for browsers. The two specs compose; neither should ship assuming the other doesn't.

**What it raises for bots:** T2 loses the zero-port property — every rotation costs a re-port;
T1/T5 unchanged (they run JS anyway).

**Cost to legit users:** ~none — browsers already execute our JS today.

**Implementation fit:** good. It's `challenge.html` + a payload-schema version (see b). No new
state; verification changes stay in `crypt.go`.

**Verdict: RECOMMENDED.** The only increment that actually gates headless solvers instead of
merely slowing them. Honest limit: headless *browsers* sail through; this targets the cheap-script
class and makes them maintain code.

### b. Challenge schema versioning / rotation

Add `"v": N` to `ChallengePayload`; config selects the active version; issue new, accept old
until a deprecation deadline, then reject; allow two versions coexisting for rolling deploys.

**What it raises for bots:** solver *maintenance*, not feasibility. If the active version stays
self-describing, a port is hours of work per rotation. Sold alone as "impossible to automate" it
is theater; sold as the *delivery vehicle* for (a)'s transform rotation it's the right
infrastructure.

**Cost to legit users:** none if the accept-window covers deploy skew; a wrong window 403s real
users mid-rollout.

**Implementation fit:** small — payload is already versioned-shape JSON; verifier needs a version
dispatch. All replicas must ship the same version map simultaneously (stateless plugin: no
coordination mechanism exists).

**Verdict: WORTH IT as infrastructure for (a); theater as a standalone claim.**

### c. Difficulty conditioning — JA4 + per-IP/UA volume LRU (the adaptive layer)

These are already queued in the project plan (JA4 edge-injection; volume LRU). Slot them in;
do not redesign:

- **JA4**: edge listener filter injects the fingerprint header; plugin maps scripting-like
  fingerprints (Go/Python TLS) to higher difficulty. Raise-the-cost note: clients can fake a
  ClientHello (uTLS), so this is a one-notch tax, not a gate.
- **Volume LRU**: per-IP and per-IP+JA4 rate buckets escalate difficulty through the existing
  clamp (`min → base → max`; the current pressure mechanism already bumps up to +6). Conditioning
  feeds the same `getEffectiveDifficulty` seam instead of inventing a second one — and
  conditioning output must *override* any client-suggested `x-challenge-difficulty` (closes the
  §1 steering hole end-to-end).

**What it raises for bots:** per-request economics — farms pay escalated work on every IP that
misbehaves; one-time solver ports don't help. Best effort/benefit ratio of everything here.

**Cost to legit users:** modest and tunable; CGNAT false positives are the real risk (many users
behind one IP land in the hard tier). Mitigate by conditioning on IP+JA4 and capping escalation.

**Implementation fit:** the plugin stays stateless if LRU/JA4 logic lives at the edge and rides
headers in; an in-plugin LRU means proxy-wasm shared state and complicates the stateless story.

**Verdict: RECOMMENDED — do this before (a)/(b); it's planned, cheap, and taxes the adversary
who already solved the PoW generically.**

### d. Memory-hard PoW (argon2id / Equihash)

Reality check with numbers from the
[argon2-browser benchmark](https://github.com/antelle/argon2-browser#the-numbers)
(t=100, m=1 MiB, 2020 Intel laptop):

| Runtime | Time |
|---|---|
| Native `-O3` SSE | 15 ms |
| WASM (Chrome/Firefox) | 195–225 ms |
| WASM+SIMD | 119–135 ms |

Same parameters: in-browser WASM is **8–15× slower than native before mobile even enters the
picture**; a mid-range phone (no SIMD, efficiency cores) lands plausibly another 2–4× worse than
the laptop. Difficulty in a PoW is time-per-attempt, so any scaling that makes a *native*
solver work meaningfully harder multiplies the same way on the phone: a "1 s on desktop"
memory-hard challenge is 5–15 s on a mid-range phone and effectively never on old Android. That
is the 10–100× legit-user slowdown, verified against sources rather than assumed — disqualifying
for a default path.

GPU/ASIC resistance buys little here anyway: the adversary is a V8 instance on a bot box paying
CPU, not a mining rig; native argon2 on that box is fast. Equihash needs ≥100 MB working memory
per solve — dead on mobile tabs.

**Verdict: REJECT for the default path.** At most an opt-in "paranoid mode" if an operator
specifically needs farm-scale GPU resistance and accepts the mobile pain.

### e. Third-party challenge embeds (Turnstile / hCaptcha / ALTCHA SaaS)

Cloudflare Turnstile's architecture ([docs](https://developers.cloudflare.com/turnstile/),
[get started](https://developers.cloudflare.com/turnstile/get-started/)): a JS widget runs
challenges in the visitor's browser producing a token; the backend validates it via the
`siteverify` API; Private Access Tokens offload attestation on Apple devices.

For this project that is a non-starter, plainly:

- The WASM plugin is stateless and has **no egress** to call siteverify; you'd need an external
  validator service, a Cloudflare account + keys, and per-host widget config — hostile to the
  `protected` multi-host selector model.
- The challenge page currently brags "no external deps"; a widget injects third-party JS +
  telemetry into every challenge, inverting the project's privacy posture (Turnstile's privacy
  is relative to CAPTCHAs, not to self-hosting).
- Availability coupling: Cloudflare's challenge infra becomes our challenge infra.

ALTCHA self-hosted is just a PoW with the same properties we already have — and its CVE history
(splicing/replay CVE-2025-68113; cryptanalytic break CVE-2025-65849) is a warning, not a feature.
Its v2 move to PBKDF2 ([docs](https://altcha.org/docs/v2/proof-of-work-captcha)) is, however,
instructive: sequential iterations ≈ "proof-of-time-lite" (see f).

**Verdict: REJECT for this project's identity. Operators wanting Turnstile should terminate it
at their ingress, not inside this plugin.**

### f. Proof-of-time (VDFs) — asked for, so addressed

Real VDFs (Wesolowski [eprint 2018/623](https://eprint.iacr.org/2018/623.pdf), Pietrzak
[eprint 2018/627](https://eprint.iacr.org/2018/627)) are sequential squarings in unknown-order
groups: genuinely unparallelizable, GPU-farm-resistant. Also: big-int modexp in WASM, nontrivial
group setup, real verification cost in the Go plugin, and a *fixed wall-time* cost that punishes
every legit browser including battery-powered mobile. Difficulty being time rather than work also
makes per-device tuning (3c) impossible to combine safely.

The cheap cousin is already field-proven: **PBKDF2-iteration PoW** (ALTCHA v2) — sequential
SHA-256 iterations, unparallelizable per challenge, tunable, implementable in our pure-JS solver
today. Keep expectations honest: it removes the GPU-parallelism discount, not the native-vs-WASM
gap; modest bot-cost delta.

**Verdict: full VDF REJECT (research project, wrong fit). PBKDF2-iteration variant: MAYBE as a
schema-v2 experiment behind config, riding (b)'s versioning.**

---

## 4. Recommended roadmap

Ordered by (cost to build) / (bot-cost gained). "Bot-cost delta" names who pays what.

| # | Increment | Effort | Bot-cost delta |
|---|---|---|---|
| 1 | Close difficulty steering: `x-challenge-difficulty` becomes edge-only (strip from untrusted hops) or clamps to `[base, max]`; conditioning overrides it | **S** | Kills the trivial "ask for min difficulty" bypass (CVE-2025-24369 shape) |
| 2 | Difficulty conditioning: JA4 header + per-IP/UA volume LRU feeding the existing clamp (3c, already planned) | **S/M** | Per-request economic tax on farm IPs and scripting TLS; legit users ~unchanged |
| 3 | API-key lane (v1 spec, sibling design) declared the no-JS path for machines; deprecate header-token solving for non-key clients | **M** | Separates humans from machines so (4) can be strict in the browser lane |
| 4 | JS-gated solve transform inside `challenge.html` + `"v"` schema version (3a+3b); rotate the transform per release, keep a rolling accept window | **M** | Every rotation re-costs a T2 port; headless-browser class unchanged (be honest about that) |
| 5 | Optional schema-v2 experiment: PBKDF2-iteration PoW behind config (3f) | **L** | Removes GPU-parallelism discount; small legit cost if tuned to today's wall-time |

An implementer picks #1 and starts: it's a header-plumbing change in `main.go` plus tests; no
protocol change.

### REJECT list (looks good, is theater)

- **"Change the challenge every time"** as a feature: already true (fresh salt, 60 s TTL, signed,
  IP+conn.id bound). Generic solvers don't care.
- **Secret/obfuscated *verification* algorithm**: any client-side secret is public by definition;
  unverifiable-by-us detection claims (stateless proxy) are unfalsifiable theater.
- **Memory-hard default** (3d): 10–100× legit-mobile pain for a few× solver pain.
- **Turnstile/hCaptcha embed** (3e): dependency, privacy inversion, no egress from WASM, wrong
  for self-hosted identity.
- **Full VDF** (3f): research project; fixed wall-time punishes mobile; can't coexist with
  per-device tuning.
- **Raising global difficulty to fight scripts**: taxes every real browser (incl. phones) while
  scripts just wait longer; conditioning (#2) is the targeted version of the same lever.

### Bottom line

Impossibility is not achievable at this layer: a T1 adversary with a real JS-executing browser is
indistinguishable from a user to a stateless proxy. What is achievable and worth doing: make
every bot run the JS we ship (raise the floor), tax volume and scripting TLS per-request (raise
marginal cost), and break one-time solver ports on a schedule (maintenance tax). The API-key lane
is what lets the browser lane stay strict.

## Sources

- Anubis: [intro post](https://xeiaso.net/blog/2025/anubis) ·
  [how-anubis-works](https://github.com/TecharoHQ/anubis/blob/main/docs/docs/design/how-anubis-works.mdx) ·
  [v1.22.0 Firefox/WebCrypto note](https://newreleases.io/project/github/TecharoHQ/anubis/release/v1.22.0) ·
  [proof-of-React PR #1038](https://github.com/TecharoHQ/anubis/pull/1038)
- Anubis solvers: [sleeyax/anubis-solver](https://github.com/sleeyax/anubis-solver) ·
  [gan-anubis (PyPI)](https://pypi.org/project/gan-anubis/) ·
  [mangetoncompost/anubis-bypass](https://github.com/mangetoncompost/anubis-bypass) ·
  [CVE-2025-24369](https://cvefeed.io/vuln/detail/CVE-2025-24369)
- ALTCHA: [GHSA-6gvq-jcmp-8959 / CVE-2025-68113](https://github.com/altcha-org/altcha-lib/security/advisories/GHSA-6gvq-jcmp-8959) ·
  [CVE-2025-65849](https://nvd.nist.gov/vuln/detail/CVE-2025-65849) ·
  [v2 PoW docs (PBKDF2)](https://altcha.org/docs/v2/proof-of-work-captcha)
- Turnstile: [overview](https://developers.cloudflare.com/turnstile/) ·
  [get started](https://developers.cloudflare.com/turnstile/get-started/) ·
  [Private Access Tokens](https://blog.cloudflare.com/eliminating-captchas-on-iphones-and-macs-using-new-standard/)
- Memory-hard in WASM: [argon2-browser benchmark table](https://github.com/antelle/argon2-browser#the-numbers)
- VDFs: [Wesolowski 2018/623](https://eprint.iacr.org/2018/623.pdf) ·
  [Pietrzak 2018/627](https://eprint.iacr.org/2018/627.pdf)

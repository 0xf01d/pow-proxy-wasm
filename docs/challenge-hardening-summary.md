# Challenge hardening — operator verdict
"Impossible to automate" is impossible: a headless browser running our JS is indistinguishable from a
user to this stateless proxy, and challenges are already fresh+signed per request — powcli works
because the payload self-describes the protocol, not because it's stale. Raise bot cost:
1. **S** Stop difficulty steering — `x-challenge-difficulty` is client-settable to `min_difficulty`
   today (Anubis CVE-2025-24369 bug class); make it edge-only or clamp to `[base, max]`.
2. **S/M** Difficulty conditioning — JA4 header + per-IP/UA volume LRU (both already planned) feed
   the existing clamp; taxes farms/scripting TLS per-request, ~no cost for real users.
3. **M** API-key lane for machines (sibling v1 spec), then **M** JS-gated solve transform + versioned
   challenge format, rotated per release — every rotation re-costs a solver port.
Rejected as theater/misfit: memory-hard PoW default (argon2 in WASM is 8-15x slower than native
before mobile: a 1 s desktop solve is 5-15 s on a phone, per argon2-browser's own benchmark),
Turnstile/hCaptcha embeds (third-party JS, no siteverify egress from WASM — wrong for self-hosting),
full VDFs (fixed wall-time punishes mobile), "secret" verification algorithms (client-side secrets are public by definition).
Full note: `docs/challenge-hardening.md`.

# JA4 support — summary (for operators)

JA4 is a short identifier computed from how a client's TLS library says hello; it separates real
browsers from scripts (curl, python, Go tools) without cookies or JavaScript.

- Verified: Envoy has no dedicated JA4 HTTP filter; the supported path is its built-in TLS inspector
  (core since v1.35) forwarded to our plugin as one request header. No new Envoy components.
- The plugin gains: rules that match or exempt client classes (e.g. don't challenge monitoring agents
  on /healthz) and per-rule harder proof-of-work for automation-like fingerprints.
- Anti-spoofing: the edge strips client-supplied fingerprint headers before injecting its own;
  unknown/missing fingerprints never earn exemptions — they follow today's rules.
- Honest limits: headless Chrome looks identical to Chrome (same TLS stack); fingerprints rotate with
  browser updates (use broad classes, never allowlist-only security); anyone bypassing Envoy can fake
  the header, so origins must only accept edge traffic.
- Not in v1: computing JA4 inside the plugin (impossible), other JA4+ family members, JA3 rules
  (randomized by Chrome 110+), fingerprint pinning as authentication.

Full spec: docs/ja4-support.md — a Go/Envoy engineer can build v1 from it.

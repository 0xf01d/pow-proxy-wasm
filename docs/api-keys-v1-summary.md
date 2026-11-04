# API keys v1 — operator summary

API keys let trusted clients (scripts, partners) skip the proof-of-work challenge entirely.

- A key is a signed text token: its settings are readable inside it, but tampering breaks the signature.
- Each key carries its own limits (requests/burst/volume), expiry, and optional host restriction.
- Issue with: `powcli mint-api-key ...` — the key is shown ONCE; only an anonymous fingerprint (id hash) is kept server-side.
- Rotate by adding a new signing secret epoch (`kid`) to the config; old and new keys both work until old ones expire.
- Revoke before expiry with one Redis command (runbook in the spec); Redis TTL makes revocations self-clean.
- If Redis is off or down, the proxy keeps working statelessly: revocation is paused and rate limits become per-node estimates (accepted tradeoff).
- Redis is reached via a tiny HTTP gateway next to Envoy (webdis); config key `redis_addr`, absent = stateless mode.
- Invalid key -> 401; over its limits -> 429 with Retry-After. No key -> normal PoW challenge, so nothing changes for regular visitors.
- Deliberately out of scope for v1: multiple key types, fingerprint/UA binding, an admin web API.
